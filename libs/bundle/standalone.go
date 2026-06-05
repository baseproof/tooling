/*
FILE PATH: libs/bundle/standalone.go

The v2 self-anchored proof ONLINE GATHER — the read-side that drives the SDK's
pure bundle.BuildStandalone over a live ledger's HTTP endpoints. The SDK assembles
the proof CLIENT-SIDE through the StandaloneGather + SectionGatherer seams; this
type implements those seams against the ledger's read API, so generation and the
offline VerifyStandalone share one proof shape.

# WHAT IT GATHERS

  - Part I (commitment): the configured genesis bootstrap + the target entry +
    the cosigned head (horizon) + the RFC-6962 inclusion proof + the Jellyfish SMT
    membership proof. Witness rotations are empty for a genesis-only network (the
    rotation gather is a later layer).
  - receipt_proof: the entry's third cosigned-root leg, from GET /v1/receipt/proof.

The remaining Wave-2/3 sections (consistency / burn / the governance evolution
chains / signer rotation / schema / cross_log_anchors) are left null here — they
need on-log discovery (which sequences are amendments) and, for cross-log, the
federation handles; those land as the gather grows. A genesis-only network has no
rotations or governance amendments, so its complete proof is exactly Part I +
receipt — which this gather produces and VerifyStandalone accepts.

# HEAD CONSISTENCY (the caveat to know)

A cosigned ReceiptRoot is a per-checkpoint delta (ledger/builder/checkpoint_loop.go),
so receipt_proof binds to the FIRST checkpoint covering the entry. This gather
anchors the whole proof on the horizon, which equals that first-covering checkpoint
for a RECENT entry (the common case the federation.proof E2E exercises: gather a
just-submitted entry). For an entry buried under later checkpoints, anchor on the
checkpoint /v1/receipt/proof returns instead — a follow-up as the gather generalises.
*/
package bundle

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
)

// MaxProofSectionBytes caps a single proof-section HTTP response (DoS guard).
const MaxProofSectionBytes = 8 << 20

// Compile-time: the gather drives both SDK assembly seams.
var (
	_ sdkbundle.StandaloneGather = (*StandaloneLedgerGather)(nil)
	_ sdkbundle.SectionGatherer  = (*StandaloneLedgerGather)(nil)
)

// StandaloneLedgerGather implements the SDK's bundle.StandaloneGather (+ the
// optional SectionGatherer) over a live ledger's read API.
type StandaloneLedgerGather struct {
	client     *clitools.LedgerClient
	baseURL    string // for endpoints clitools does not wrap (SMT proof, receipt proof)
	httpClient *http.Client
	bootstrap  *network.BootstrapDocument
	quorumK    int
	seq        uint64   // the target entry's sequence (for the per-entry section endpoints)
	smtKey     [32]byte // the target entry's SMT key (the witnessed presence-proof key)

	discoverer *IndexDiscoverer // index-backed evolution-chain discovery (never scan)
	// governance maps each governance v2 section name to the on-log position of the
	// schema whose amendments form that chain (DiscoverBySchemaRef key). A chain with
	// no entry here is left null (a network without that governance surface). This is
	// the per-network vocabulary the Wave-4 NetworkBundle will carry.
	governance map[string]types.LogPosition
	// signerRotationSchema is the on-log position of the network's signer-rotation
	// schema (BP-ENTRY-SIGNER-ROTATION-PAYLOAD-V1). Rotations are discovered by it
	// (O(rotations)) then filtered to the target signer; nil ⇒ signer_rotation_chain
	// is left null.
	signerRotationSchema *types.LogPosition
	// horizon caches the cosigned head so every leg of the proof (target entry +
	// every gathered section) anchors on ONE checkpoint — fetched once, reused.
	horizon *types.CosignedTreeHead
	// targetEntryCache caches the deserialized target entry (its header drives the
	// signer-rotation + schema chains); fetched once.
	targetEntryCache *envelope.Entry

	// federation is the registry of CITED networks (keyed by the source_log_did an
	// anchor entry names), supplied via WithFederationRegistry. Non-empty ⇒ the
	// gather populates cross_log_anchors by discovering A's anchors and recursively
	// gathering each cited network's nested proof; empty ⇒ that section is null.
	federation map[string]FederationMember
	// fedDepth is this gather's depth in the federation recursion (0 at the top);
	// fedPath is the set of NetworkIDs already on the recursion path (the cycle
	// guard). Both are threaded into nested gathers, mirroring the verifier's
	// depth bound (verifier.MaxCompoundProofDepth) + NetworkID cycle guard.
	fedDepth int
	fedPath  map[cosign.NetworkID]bool
}

// NewStandaloneLedgerGather wires the gather for ONE target entry. bootstrap +
// quorumK are the network's static genesis configuration (the verify-side trust
// root derives from the same bootstrap); seq + smtKey identify the entry (seq must
// match the seq passed to bundle.BuildStandalone).
// quorumK are the network's static genesis configuration (the verify-side trust
// root derives from the same bootstrap); seq + smtKey identify the entry. Optional
// GatherOptions (e.g. WithGovernanceSchemas) enable the Wave-2 deferred sections;
// with none, the gather produces a Part-I + receipt proof (a genesis-only network).
func NewStandaloneLedgerGather(
	client *clitools.LedgerClient,
	baseURL string,
	httpClient *http.Client,
	bootstrap *network.BootstrapDocument,
	quorumK int,
	seq uint64,
	smtKey [32]byte,
	opts ...GatherOption,
) (*StandaloneLedgerGather, error) {
	if client == nil || httpClient == nil {
		return nil, fmt.Errorf("bundle/standalone: nil client or http.Client")
	}
	if bootstrap == nil {
		return nil, fmt.Errorf("bundle/standalone: nil bootstrap document")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("bundle/standalone: empty baseURL")
	}
	disc, err := NewIndexDiscoverer(baseURL, httpClient)
	if err != nil {
		return nil, err
	}
	g := &StandaloneLedgerGather{
		client: client, baseURL: baseURL, httpClient: httpClient,
		bootstrap: bootstrap, quorumK: quorumK, seq: seq, smtKey: smtKey,
		discoverer: disc,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g, nil
}

// ── StandaloneGather (Part I) ────────────────────────────────────────────────

func (g *StandaloneLedgerGather) FetchGenesisBootstrap(context.Context) (*network.BootstrapDocument, int, error) {
	doc := *g.bootstrap // value copy — the SDK must not mutate the configured doc
	return &doc, g.quorumK, nil
}

func (g *StandaloneLedgerGather) FetchEntry(ctx context.Context, seq uint64) ([]byte, time.Time, error) {
	e, err := g.client.FetchEntry(ctx, seq)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bundle/standalone: FetchEntry %d: %w", seq, err)
	}
	canonical, err := hex.DecodeString(e.CanonicalHex)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bundle/standalone: entry %d canonical_hex: %w", seq, err)
	}
	return canonical, time.UnixMicro(e.LogTimeUnixMicro).UTC(), nil
}

func (g *StandaloneLedgerGather) FetchCosignedHead(context.Context, uint64) (types.CosignedTreeHead, error) {
	return g.getHorizon()
}

func (g *StandaloneLedgerGather) FetchInclusionProof(_ context.Context, seq, treeSize uint64) (types.MerkleProof, error) {
	p, err := g.client.InclusionProofAtSize(seq, treeSize)
	if err != nil {
		return types.MerkleProof{}, fmt.Errorf("bundle/standalone: inclusion %d@%d: %w", seq, treeSize, err)
	}
	if p == nil {
		return types.MerkleProof{}, fmt.Errorf("bundle/standalone: nil inclusion proof")
	}
	return *p, nil
}

func (g *StandaloneLedgerGather) FetchSMTProof(ctx context.Context, _ uint64, smtRoot [32]byte) (types.SMTProof, error) {
	url := fmt.Sprintf("%s/v1/smt/proof/%s?smt_root=%s",
		g.baseURL, hex.EncodeToString(g.smtKey[:]), hex.EncodeToString(smtRoot[:]))
	var body struct {
		Type  string         `json:"type"`
		Proof types.SMTProof `json:"proof"`
	}
	if err := g.getJSON(ctx, url, &body); err != nil {
		return types.SMTProof{}, fmt.Errorf("bundle/standalone: smt proof: %w", err)
	}
	if body.Type != "membership" {
		return types.SMTProof{}, fmt.Errorf("bundle/standalone: smt proof is %q, want membership (entry not present at key)", body.Type)
	}
	return body.Proof, nil
}

// FetchWitnessRotationChain is implemented in standalone_witness.go (the
// genesis short-circuit + the Rebuilder-backed rotated path).

// ── SectionGatherer (Wave-2/3) ───────────────────────────────────────────────

// FetchSection gathers the supported deferred sections: receipt_proof (always) and
// the six governance evolution chains (when their schema is configured via
// WithGovernanceSchemas), each discovered index-backed and assembled on the shared
// checkpoint. Unsupported / unconfigured sections return null (the SDK reports them
// not-asserted). signer_rotation / schema / consistency / burn / cross_log land as
// the gather grows.
func (g *StandaloneLedgerGather) FetchSection(ctx context.Context, name string, _ uint64) (json.RawMessage, error) {
	switch {
	case name == "receipt_proof":
		return g.receiptSection(ctx)
	case governanceSchemaSections[name]:
		return g.governanceSection(ctx, name)
	case name == "signer_rotation_chain":
		return g.signerRotationSection(ctx)
	case name == "schema_chain":
		return g.schemaChainSection(ctx)
	case name == "burn_attestation":
		return g.burnSection(ctx)
	case name == "cross_log_anchors":
		return g.crossLogSection(ctx)
	default:
		return nil, nil
	}
}

// receiptSection fetches the entry's receipt-inclusion proof (third cosigned root).
func (g *StandaloneLedgerGather) receiptSection(ctx context.Context) (json.RawMessage, error) {
	url := fmt.Sprintf("%s/v1/receipt/proof/%s", g.baseURL, strconv.FormatUint(g.seq, 10))
	var body struct {
		ReceiptProof json.RawMessage `json:"receipt_proof"`
	}
	if err := g.getJSON(ctx, url, &body); err != nil {
		return nil, fmt.Errorf("bundle/standalone: receipt proof: %w", err)
	}
	return body.ReceiptProof, nil
}

// getJSON GETs url and strict-decodes the JSON body into v (DoS-bounded), using
// this gather's http.Client.
func (g *StandaloneLedgerGather) getJSON(ctx context.Context, url string, v any) error {
	return getJSONBounded(ctx, g.httpClient, url, v)
}

// getJSONBounded GETs url over hc and strict-decodes the JSON body into v,
// bounded by MaxProofSectionBytes (DoS guard). A free function so a nested
// federation fetch can use a CITED network's own transport, not the top gather's.
func getJSONBounded(ctx context.Context, hc *http.Client, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxProofSectionBytes+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(raw) > MaxProofSectionBytes {
		return fmt.Errorf("response from %s exceeds %d bytes (DoS guard)", url, MaxProofSectionBytes)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("decode %s: %w", url, err)
	}
	return nil
}
