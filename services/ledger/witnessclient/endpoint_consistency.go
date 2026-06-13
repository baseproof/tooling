/*
FILE PATH: witnessclient/endpoint_consistency.go

PRE-12 item 5 — the did:web consistency monitor (the long-horizon tripwire).

Each on-log WitnessEndpointDeclaration is the AUTHORITY for where a witness
dials (the by-kind resolver serves it; LEDGER_WITNESS_ENDPOINTS is deleted). A
witness operator MAY also publish a did:web document (/.well-known/did.json) for
discovery convenience. This monitor periodically cross-checks the two: ON-LOG
WINS — a divergence is a DNS/CA-churn or tamper signal, surfaced as a WARN, never
a gate (advisory, fail-toward-noise-not-refusal).

For did:key witnesses (the genesis topology) there is no did:web document, so the
fetcher returns (nil, nil) and the witness is skipped — the monitor is a no-op
until did:web-addressed witnesses appear. The cryptographic check
(network.WitnessEndpointDeclaration.CrossCheckAgainstDIDDocument) is the SDK's;
this file is the periodic driver + the advisory HTTP fetcher.
*/
package witnessclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
)

// DIDDocFetcher fetches the did:web DID document advertised at a witness
// declaration's endpoint, or (nil, nil) when there is none to compare against
// (a did:key witness, a 404, a non-DID host). The check is advisory, so absence
// is the silent default — never an alarm.
type DIDDocFetcher func(ctx context.Context, decl network.WitnessEndpointDeclaration) (*sdkdid.DIDDocument, error)

// RecordsSource returns the on-log witness-endpoint declarations to cross-check
// (the AuthoritativeResolver's WitnessEndpointRecords).
type RecordsSource func() network.WitnessEndpointDeclarationByPosition

// WitnessEndpointMonitor periodically cross-checks each on-log declaration
// against its operator's did:web document. on-log WINS; a mismatch logs a WARN.
type WitnessEndpointMonitor struct {
	Records  RecordsSource
	Fetch    DIDDocFetcher
	Interval time.Duration
	Logger   *slog.Logger
}

// Tick runs one cross-check pass and returns the number of mismatches found.
func (m *WitnessEndpointMonitor) Tick(ctx context.Context) int {
	records := m.Records()
	mismatches := 0
	for i := range records {
		decl := records[i].Payload
		doc, err := m.Fetch(ctx, decl)
		if err != nil {
			m.Logger.Debug("witness endpoint did:web fetch skipped",
				"pub_key_id", fmt.Sprintf("%x", decl.PubKeyID), "error", err)
			continue
		}
		if doc == nil {
			continue // no did:web document (did:key witness) — advisory no-op
		}
		cerr := decl.CrossCheckAgainstDIDDocument(doc)
		if cerr == nil {
			continue
		}
		var mm *network.EndpointMismatchError
		if errors.As(cerr, &mm) {
			m.Logger.Warn("witness endpoint did:web DRIFT — on-log declaration wins; investigate DNS/CA/tamper",
				"pub_key_id", fmt.Sprintf("%x", decl.PubKeyID), "mismatch", cerr.Error())
			mismatches++
		} else {
			m.Logger.Debug("witness endpoint cross-check error (non-mismatch)",
				"pub_key_id", fmt.Sprintf("%x", decl.PubKeyID), "error", cerr)
		}
	}
	return mismatches
}

// Loop ticks every Interval until ctx is done. Interval <= 0 disables it
// (returns immediately). Run via lifecycle.SafeRunInWG.
func (m *WitnessEndpointMonitor) Loop(ctx context.Context) error {
	if m.Interval <= 0 {
		return nil
	}
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.Tick(ctx)
		}
	}
}

// HTTPDIDDocFetcher builds a production DIDDocFetcher that GETs
// <endpoint-base>/.well-known/did.json for a declaration's witness service
// endpoint and parses it as a did:web DID document. A missing endpoint, a
// non-2xx, an unreachable host, or a parse failure yields (nil, nil) — there is
// simply nothing to compare (the advisory default, so a did:key witness raises
// no false alarm). The body is io.LimitReader-capped (Law 19).
func HTTPDIDDocFetcher(client *http.Client) DIDDocFetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, decl network.WitnessEndpointDeclaration) (*sdkdid.DIDDocument, error) {
		base := firstWitnessEndpoint(decl.Endpoints)
		if base == "" {
			return nil, nil
		}
		url := strings.TrimRight(base, "/") + "/.well-known/did.json"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, nil
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil // unreachable — advisory, no alarm
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, nil // no did:web doc here (did:key witness, etc.)
		}
		var doc sdkdid.DIDDocument
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
			return nil, nil // not a DID document
		}
		return &doc, nil
	}
}

// firstWitnessEndpoint returns a deterministic endpoint base for the did:web
// fetch — the canonical witness service type if present, else any.
func firstWitnessEndpoint(eps map[string]string) string {
	if u, ok := eps["BaseproofWitness"]; ok {
		return u
	}
	for _, u := range eps {
		return u
	}
	return ""
}
