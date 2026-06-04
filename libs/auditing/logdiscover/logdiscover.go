// FILE PATH: libs/auditing/logdiscover/logdiscover.go
//
// DESCRIPTION:
//
//	Bounded-retry GET {ledgerEndpoint}/v1/log-info fetcher. Returns a
//	ledger's operational signing identity — the did:key under which
//	the ledger originates STHs (ledger_did), the canonical log DID
//	(log_did), and the first-8-bytes hex of cosign.NetworkID
//	(network_id) — in a single LogInfo struct.
//
//	Shared between the JN binary and the tooling auditor so the
//	/v1/log-info wire shape lives in one place. Both consumers need
//	the same answer at boot: which did:key signs this log's STHs, so
//	the inbound gossip witness set + peer entries can be keyed by the
//	originator (gossipverify routes WitnessSets[ev.Originator]).
//
//	# FORWARD COMPATIBILITY
//
//	At v1.34.x, the operational signing key for a log's STHs is NOT a
//	first-class on-log record kind. The SDK's *discover.AuthoritativeResolver.
//	ResolveLedger returns only Resolved{URL, Source, AsOf} — the URL,
//	not the originator key. So this helper is the canonical surface
//	for that lookup today, and it goes over HTTP.
//
//	When the SDK adds an on-log record kind for log originator identity
//	(planned post-v1.34), update FetchLogInfo to consult the SDK
//	resolver first and fall back to the HTTP probe only when the on-log
//	records are empty. Consumers re-pin libs and benefit transitively
//	without touching their own call sites.
//
//	# MELT-PROOF
//
//	Bounded exponential backoff (1s, 2s, 4s, 8s, 16s, 16s) — six attempts,
//	capped at 16s, totalling at most ~47s. Body is read under
//	io.LimitReader(64KiB) so a hostile ledger can't blow up memory.
//	ctx is honored at every attempt boundary; a cancelled ctx returns
//	immediately. nil client is rejected loudly per the v1.34.0 SDK
//	"no silent demotion" contract.
package logdiscover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// LogInfo is the subset of GET /v1/log-info every consumer needs to
// bind trust at boot:
//
//   - LogDID is the canonical log DID (what the log calls itself).
//   - LedgerDID is the OPERATIONAL did:key the ledger uses to sign
//     STHs. This is what gossip events arrive under (ev.Originator);
//     witness-set lookups MUST key on this, not on LogDID.
//   - NetworkID is the first-8-bytes hex of the cosign.NetworkID,
//     matching the ledger's wire format. Consumers cross-check
//     against their bootstrap-derived NetworkID to refuse trust
//     binding across networks.
type LogInfo struct {
	LogDID    string `json:"log_did"`
	LedgerDID string `json:"ledger_did"`
	NetworkID string `json:"network_id"`
}

// MaxResponseBytes caps the GET /v1/log-info response body. The
// expected payload is a 3-field JSON object (~256 bytes typical); 64
// KiB is ~250x the expected size, generous enough for protocol
// evolution but small enough that a hostile ledger can't exhaust
// memory.
const MaxResponseBytes = 64 << 10

// DefaultMaxAttempts is the retry bound. With DefaultBackoff this
// totals ~47 seconds of wait across 6 attempts (1+2+4+8+16+16) plus
// per-attempt RTT — long enough to ride out a ledger that's still
// coming up, short enough to surface a permanent failure quickly.
const DefaultMaxAttempts = 6

// FetchLogInfo issues GET {ledgerEndpoint}/v1/log-info with bounded
// exponential backoff, returning once the ledger answers OR ctx is
// cancelled OR retries are spent.
//
// client is REQUIRED. Thread the binary's hoisted outbound *http.Client
// (libs/clienttls.BuildFromEnv or libs/outbound.HoistFromEnv) so the
// probe shares the operator-chosen mTLS posture. A nil client returns
// an error rather than silently demoting to plaintext — same contract
// as the v1.34.0 SDK constructors (cosign.NewWitnessClient,
// gossip.NewClient, gossip.NewFeedClient).
//
// Returns the parsed LogInfo on success. On retry exhaustion returns
// the last underlying error. On ctx cancellation returns ctx.Err().
func FetchLogInfo(ctx context.Context, ledgerEndpoint string, client *http.Client) (LogInfo, error) {
	if client == nil {
		return LogInfo{}, fmt.Errorf("logdiscover: client required (no silent plaintext demotion); thread the binary's hoisted outbound client")
	}
	if ledgerEndpoint == "" {
		return LogInfo{}, fmt.Errorf("logdiscover: ledgerEndpoint required")
	}
	url := strings.TrimRight(ledgerEndpoint, "/") + "/v1/log-info"
	var lastErr error
	for attempt := 1; attempt <= DefaultMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return LogInfo{}, err
		}
		info, err := fetchOnce(ctx, url, client)
		if err == nil {
			return info, nil
		}
		lastErr = err
		// No sleep after the final attempt — return the error directly.
		if attempt == DefaultMaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return LogInfo{}, ctx.Err()
		case <-time.After(DefaultBackoff(attempt)):
		}
	}
	return LogInfo{}, lastErr
}

// fetchOnce issues a single GET. Non-2xx response codes are errors;
// the body is decoded under io.LimitReader so a hostile ledger can't
// blow up memory by sending an oversized response.
func fetchOnce(ctx context.Context, url string, client *http.Client) (LogInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return LogInfo{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return LogInfo{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return LogInfo{}, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var info LogInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxResponseBytes)).Decode(&info); err != nil {
		return LogInfo{}, fmt.Errorf("decode %s: %w", url, err)
	}
	return info, nil
}

// DefaultBackoff is exponential (1s, 2s, 4s, 8s, 16s, ...) capped at
// 16s. Exposed so callers (and tests) can compose the same shape; the
// internal retry loop uses this unconditionally.
func DefaultBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > 16*time.Second {
		return 16 * time.Second
	}
	return d
}
