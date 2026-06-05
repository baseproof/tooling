/*
FILE PATH: libs/bundle/standalone_bundle.go

The BUNDLE-DRIVEN gather: construct a StandaloneLedgerGather from a single
protocol.NetworkBundle instead of hand-passed bootstrap + quorum + per-chain
GatherOptions. This is the call shape the universal CLI and any service uses —
"name the network, gather the proof" — and the home for the per-network
vocabulary the governance + signer chains discover by.

# WHAT THE BUNDLE SUPPLIES

  - Endpoint            → the ledger read API the gather drives (baseURL).
  - TrustRoot.QuorumK   → the network's K (the same K the verifier binds).
  - TrustRoot.Bootstrap­DocumentHash → the integrity pin the fetched genesis
    bootstrap MUST hash to (fail-fast: a wrong endpoint serves a different net).
  - GovernanceSchemas / SignerRotationSchema → the vocabulary, translated to the
    existing WithGovernanceSchemas / WithSignerRotationSchema options.

The genesis bootstrap itself is NOT carried in the bundle — it is fetched from
GET /v1/network/bootstrap (served as JCS-canonical bytes) and verified against the
bundle's hash. So protocol.NetworkBundle stays decoupled from network.Bootstrap­
Document, and the bundle is a small, static, authored-once artifact.
*/
package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"

	"github.com/baseproof/tooling/libs/clitools"
)

// NewBundleGather builds a gather for ONE target entry from a NetworkBundle: it
// fetches + hash-verifies the network's genesis bootstrap from the bundle's
// Endpoint, then self-configures the governance + signer chains from the bundle's
// vocabulary. The caller supplies the transport (client + httpClient built against
// bundle.Endpoint — their TLS posture); everything network-identity and vocabulary
// comes from the bundle. seq + smtKey identify the entry (seq must match the seq
// passed to bundle.BuildStandalone).
//
// The bundle must be a GENERATION bundle: a non-empty Endpoint. A verify-only
// bundle (no endpoint) is rejected — it cannot drive generation.
func NewBundleGather(
	ctx context.Context,
	bundle *protocol.NetworkBundle,
	client *clitools.LedgerClient,
	httpClient *http.Client,
	seq uint64,
	smtKey [32]byte,
) (*StandaloneLedgerGather, error) {
	if bundle == nil {
		return nil, fmt.Errorf("bundle/standalone: nil NetworkBundle")
	}
	if err := bundle.Validate(); err != nil {
		return nil, fmt.Errorf("bundle/standalone: invalid NetworkBundle: %w", err)
	}
	if bundle.Endpoint == "" {
		return nil, fmt.Errorf("bundle/standalone: NetworkBundle has no Endpoint (verify-only bundle cannot drive generation)")
	}
	doc, err := fetchBootstrapDocument(ctx, bundle.Endpoint, httpClient, bundle.TrustRoot.BootstrapDocumentHash)
	if err != nil {
		return nil, err
	}
	return NewStandaloneLedgerGather(
		client, bundle.Endpoint, httpClient, doc, bundle.TrustRoot.QuorumK, seq, smtKey,
		gatherOptionsFromBundle(bundle)...,
	)
}

// gatherOptionsFromBundle translates a NetworkBundle's generation vocabulary into
// the gather's options. A bundle with no governance map and no signer-rotation
// schema yields no options (a genesis-only / Part-I + receipt proof).
func gatherOptionsFromBundle(b *protocol.NetworkBundle) []GatherOption {
	var opts []GatherOption
	if len(b.GovernanceSchemas) > 0 {
		opts = append(opts, WithGovernanceSchemas(b.GovernanceSchemas))
	}
	if b.SignerRotationSchema != nil {
		opts = append(opts, WithSignerRotationSchema(*b.SignerRotationSchema))
	}
	return opts
}

// fetchBootstrapDocument GETs the network's genesis bootstrap from
// {baseURL}/v1/network/bootstrap, verifies its SHA-256 equals expectedHash (the
// bundle's pin — a mismatch means the endpoint is not serving the bundle's
// network, fail closed), and parses the JCS-canonical bytes into a
// BootstrapDocument. The endpoint serves exactly BootstrapDocument.CanonicalBytes,
// so SHA-256(body) == TrustRoot.BootstrapDocumentHash by construction.
func fetchBootstrapDocument(ctx context.Context, baseURL string, httpClient *http.Client, expectedHash [32]byte) (*network.BootstrapDocument, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/network/bootstrap"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: build bootstrap request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle/standalone: bootstrap HTTP %d from %s", resp.StatusCode, url)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxProofSectionBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: read bootstrap body: %w", err)
	}
	if len(raw) > MaxProofSectionBytes {
		return nil, fmt.Errorf("bundle/standalone: bootstrap from %s exceeds %d bytes (DoS guard)", url, MaxProofSectionBytes)
	}
	if got := sha256.Sum256(raw); got != expectedHash {
		return nil, fmt.Errorf("bundle/standalone: bootstrap hash mismatch — endpoint %s serves a different network than the bundle pins (got %x, want %x)",
			baseURL, got[:8], expectedHash[:8])
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("bundle/standalone: decode bootstrap: %w", err)
	}
	return &doc, nil
}
