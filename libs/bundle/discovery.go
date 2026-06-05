/*
FILE PATH: libs/bundle/discovery.go

The v2 generate-side INDEX-BACKED DISCOVERY layer (Wave 2). To assemble a
governance / signer / schema evolution chain, the gather must first DISCOVER
which on-log entries belong to it. This file does that — and ONLY via the
ledger's secondary indexes, never a scan.

# THE SCALING CONTRACT (hard, fail-loud — the load-bearing invariant)

Discovery is ALWAYS index-backed and O(matches), NEVER O(N):

  - governance + schema chains → GET /v1/query/schema_ref/{did:seq}
    (idx_schema_ref ON entry_index(schema_ref) WHERE schema_ref IS NOT NULL)
  - signer rotation chain      → GET /v1/query/signer_did/{did}
    (idx_signer_did ON entry_index(signer_did))

A non-200 from an index endpoint — a deployment whose index is missing, or a
ledger that does not serve it — is a PREREQUISITE VIOLATION, surfaced as
ErrIndexUnavailable. The discoverer MUST NEVER fall back to /v1/query/scan
(O(N), fatal at 10B entries): silently scanning would both blow the per-proof
latency budget and mask a misconfigured deployment. At 15 years / 10B entries a
network has dozens of governance events, so an index hit returns dozens of rows
independent of N; a scan returns N. There is no middle ground — fail loud.

# WHY METADATA-ONLY DISCOVERY THEN A SEPARATE FETCH

The query endpoints return entry METADATA only (sequence + hashes; no canonical
bytes — the ledger's egress mandate). So discovery yields the matching
SEQUENCES; AssembleEvolutionChain then fetches each entry's canonical bytes +
inclusion proof by sequence (also O(matches)).
*/
package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/types"
)

// ErrIndexUnavailable is returned when an index endpoint does not answer 200 —
// a hard prerequisite violation. The discoverer fails closed rather than
// degrading to an O(N) scan.
var ErrIndexUnavailable = errors.New("bundle/discovery: required secondary index unavailable (refusing to scan)")

// DiscoveredEntry is one index hit: the entry's proven log sequence. The query
// API returns metadata only, so the canonical bytes are fetched separately by
// this sequence (AssembleEvolutionChain).
type DiscoveredEntry struct {
	Sequence uint64
}

// IndexDiscoverer discovers evolution-chain entries via the ledger's secondary
// indexes (schema_ref, signer_did) — O(matches), never a scan. See the file
// header for the scaling contract.
type IndexDiscoverer struct {
	baseURL    string
	httpClient *http.Client
}

// NewIndexDiscoverer wires a discoverer against a ledger's read API.
func NewIndexDiscoverer(baseURL string, httpClient *http.Client) (*IndexDiscoverer, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("bundle/discovery: empty baseURL")
	}
	if httpClient == nil {
		return nil, fmt.Errorf("bundle/discovery: nil http.Client")
	}
	return &IndexDiscoverer{baseURL: baseURL, httpClient: httpClient}, nil
}

// DiscoverBySchemaRef returns, in ascending sequence order, every entry whose
// schema_ref == schemaPos — the amendment set for a governance/schema chain.
// Index-backed (idx_schema_ref); fail-loud (never a scan).
func (d *IndexDiscoverer) DiscoverBySchemaRef(ctx context.Context, schemaPos types.LogPosition) ([]DiscoveredEntry, error) {
	if schemaPos.LogDID == "" {
		return nil, fmt.Errorf("bundle/discovery: schema_ref position has no log DID")
	}
	// The ledger's {pos} path value is parsed as "<did>:<sequence>" (split on the
	// final colon), so the DID's own colons are preserved.
	pos := schemaPos.LogDID + ":" + strconv.FormatUint(schemaPos.Sequence, 10)
	return d.query(ctx, "/v1/query/schema_ref/"+pos, "schema_ref "+pos)
}

// DiscoverBySignerDID returns, in ascending sequence order, every entry signed by
// did — the candidate set a signer-rotation chain filters to its rotation
// entries. Index-backed (idx_signer_did); fail-loud (never a scan).
func (d *IndexDiscoverer) DiscoverBySignerDID(ctx context.Context, did string) ([]DiscoveredEntry, error) {
	if did == "" {
		return nil, fmt.Errorf("bundle/discovery: empty signer DID")
	}
	return d.query(ctx, "/v1/query/signer_did/"+did, "signer_did "+did)
}

// query GETs an index endpoint and parses the {entries:[{sequence_number}],count}
// envelope. ANY non-200 is ErrIndexUnavailable — never a scan fallback.
func (d *IndexDiscoverer) query(ctx context.Context, path, what string) ([]DiscoveredEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("bundle/discovery: build request %s: %w", what, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle/discovery: GET %s: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s returned HTTP %d", ErrIndexUnavailable, what, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxProofSectionBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bundle/discovery: read %s: %w", what, err)
	}
	if len(raw) > MaxProofSectionBytes {
		return nil, fmt.Errorf("bundle/discovery: %s response exceeds %d bytes (DoS guard)", what, MaxProofSectionBytes)
	}
	var body struct {
		Entries []struct {
			SequenceNumber uint64 `json:"sequence_number"`
		} `json:"entries"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("bundle/discovery: decode %s: %w", what, err)
	}
	if body.Count != len(body.Entries) {
		return nil, fmt.Errorf("bundle/discovery: %s count=%d != len(entries)=%d (truncated response)", what, body.Count, len(body.Entries))
	}
	out := make([]DiscoveredEntry, len(body.Entries))
	for i, e := range body.Entries {
		out[i] = DiscoveredEntry{Sequence: e.SequenceNumber}
	}
	return out, nil
}

// ElementSource fetches the per-entry data the assembly binds: the canonical
// envelope bytes and the RFC-6962 inclusion proof at a tree size.
// *StandaloneLedgerGather satisfies it.
type ElementSource interface {
	FetchEntry(ctx context.Context, seq uint64) (canonical []byte, logTime time.Time, err error)
	FetchInclusionProof(ctx context.Context, seq, treeSize uint64) (types.MerkleProof, error)
}

// AssembleEvolutionChain turns discovered sequences into the v2 evolution-chain
// wire section: each element is the entry's canonical bytes + its RFC-6962
// inclusion proof against the SINGLE shared checkpoint head (CommittingHead =
// checkpoint). No SMT proof is attached — a governance/signer/schema element is
// proven by inclusion + the checkpoint's K-of-N cosign, never SMT membership
// (the SDK's evolution-chain verifier; baseproof#23). An empty discovery set
// yields a null section (a network with no such amendments).
//
// The inclusion proof's leaf hash is bound to THIS entry's on-log leaf
// (OnLogEntryLeafHash) and its tree size is the checkpoint's — exactly the two
// bindings VerifyStandalone enforces per element.
func AssembleEvolutionChain(ctx context.Context, src ElementSource, discovered []DiscoveredEntry, checkpoint types.CosignedTreeHead) (json.RawMessage, error) {
	if src == nil {
		return nil, fmt.Errorf("bundle/discovery: nil ElementSource")
	}
	if len(discovered) == 0 {
		return nil, nil
	}
	els := make([]sdkbundle.RotationElement, 0, len(discovered))
	for _, de := range discovered {
		canonical, _, err := src.FetchEntry(ctx, de.Sequence)
		if err != nil {
			return nil, fmt.Errorf("bundle/discovery: fetch entry %d: %w", de.Sequence, err)
		}
		inc, err := src.FetchInclusionProof(ctx, de.Sequence, checkpoint.TreeSize)
		if err != nil {
			return nil, fmt.Errorf("bundle/discovery: inclusion %d@%d: %w", de.Sequence, checkpoint.TreeSize, err)
		}
		inc.LeafHash = envelope.OnLogEntryLeafHash(canonical)
		els = append(els, sdkbundle.RotationElement{
			Record:         canonical,
			InclusionProof: inc,
			CommittingHead: checkpoint,
		})
	}
	return sdkbundle.EncodeStandaloneEvolutionChain(els)
}
