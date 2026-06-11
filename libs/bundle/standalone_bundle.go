/*
FILE PATH: libs/bundle/standalone_bundle.go

The BUNDLE-DRIVEN gather: construct a StandaloneLedgerGather from a single
protocol.NetworkBundle instead of hand-passed bootstrap + quorum + per-chain
GatherOptions. This is the call shape the universal CLI and any service uses —
"name the network, gather the proof" — and the home for the per-network
vocabulary the governance + signer chains discover by.

# WHAT THE BUNDLE SUPPLIES

  - Endpoint            → the ledger read API the gather drives (baseURL).
  - the verified document's GenesisQuorumK → the network's K (the same constitutional K the verifier binds; nothing plumbs K beside the document).
  - TrustRoot.Bootstrap­DocumentHash → the integrity pin the fetched genesis
    bootstrap MUST hash to (fail-fast: a wrong endpoint serves a different net).
  - GovernanceSchemas / SignerRotationSchema → the vocabulary, translated to the
    existing WithGovernanceSchemas / WithSignerRotationSchema options.

The genesis bootstrap itself is NOT carried in the bundle — it is fetched from
GET /v1/network/bootstrap and verified against the bundle's hash through
network.LoadVerifiedBootstrap (hash over the canonical subset, so the served
form may be canonical or endorsed; the ceremony is enforced when the policy
requires it). So protocol.NetworkBundle stays decoupled from network.Bootstrap­
Document, and the bundle is a small, static, authored-once artifact.
*/
package bundle

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
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
	client LedgerReader,
	httpClient *http.Client,
	seq uint64,
	smtKey [32]byte,
	opts ...GatherOption,
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
		client, bundle.Endpoint, httpClient, doc, seq, smtKey,
		append(gatherOptionsFromBundle(bundle), opts...)...,
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
// {baseURL}/v1/network/bootstrap and admits it through the SDK's single
// first-contact door, network.LoadVerifiedBootstrap: strict decode, NetworkID
// recomputed over the CANONICAL SUBSET and compared to expectedHash (the
// bundle's pin — a mismatch means the endpoint is not serving the bundle's
// network, fail closed), and the genesis ceremony verified whenever the
// constitution's policy requires it. The served body is FORM-AGNOSTIC: the
// endpoint may serve the canonical bytes or the endorsed form (endorsements
// live outside the canonical subset, so both hash to the same NetworkID) — and
// a require-network constitution stripped of its endorsements is refused here.
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
	doc, err := network.LoadVerifiedBootstrap(raw, expectedHash)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: bootstrap from %s failed first-contact verification: %w", baseURL, err)
	}
	return doc, nil
}
