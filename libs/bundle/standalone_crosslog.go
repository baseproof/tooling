/*
FILE PATH: libs/bundle/standalone_crosslog.go

The cross_log_anchors GATHER — the recursive federation section (Wave 3). For each
foreign network B that A's log anchors, it produces a CrossLogAnchor element: A's
local anchor entry, that entry's inclusion in A's checkpoint, and a full NESTED v2
proof of B — pinned to exactly the head the anchor embeds (the bind the verifier
enforces) and gathered by the SAME bundle-driven gather, so B's proof recursively
carries B→C.

# DISCOVERY + RECURSION

  - Anchor entries carry no schema_ref, so they are discovered by KIND: scan A's
    committed prefix (like the witness Rebuilder) and keep the LATEST anchor per
    cited network in the federation registry. Only federated proofs pay the scan.
  - The registry (WithFederationRegistry) maps a cited network's log DID — the
    source_log_did an anchor names — to its self-describing NetworkBundle (endpoint,
    trust root, CitedMemberKey) + a pre-built transport. The caller assembles it
    once for the whole federation; the gather looks members up as it walks anchors.
  - The recursion is depth-bounded (verifier.MaxCompoundProofDepth) and NetworkID
    cycle-guarded, mirroring the verifier's own guards so the gather never produces
    a proof the verifier rejects.

# THE BIND (why the nested proof is head-pinned)

The verifier (verifyCrossLogAnchors → anchor.VerifyInclusion) requires the nested
proof's CosignedHead to EQUAL the head the local anchor embeds (same RootHash +
TreeSize). So the nested gather's horizon is pinned to the anchor's embedded head,
and the cited member's sequence is resolved against THAT head's SMT root.
*/
package bundle

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip/findings"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// anchorScanBatch is the page size for the anchor-discovery scan of A's log.
const anchorScanBatch = 1000

// FederationMember is one CITED network's gather inputs: its self-describing
// bundle (endpoint + trust root + the CitedMemberKey a nested proof targets) plus
// the pre-built transport to reach its ledger. The caller — who knows the
// federation set and each network's TLS posture — assembles the registry once; the
// gather looks members up by the source_log_did an anchor entry names.
type FederationMember struct {
	Bundle     *protocol.NetworkBundle
	Client     LedgerReader
	HTTPClient *http.Client
}

// WithFederationRegistry supplies the cited networks, keyed by log DID. With a
// non-empty registry the gather populates cross_log_anchors; unset/empty ⇒ the
// section is null (a non-federated proof). The registry is threaded unchanged into
// every nested gather, so the whole federation graph is reachable at any depth.
func WithFederationRegistry(reg map[string]FederationMember) GatherOption {
	return func(g *StandaloneLedgerGather) {
		g.federation = make(map[string]FederationMember, len(reg))
		for k, v := range reg {
			g.federation[k] = v
		}
	}
}

// crossLogSection produces the cross_log_anchors section: for each cited network A
// anchors, a head-pinned nested proof + the local anchor's inclusion. Returns null
// for a non-federated gather (empty registry) or when no discovered anchor cites a
// registered network.
func (g *StandaloneLedgerGather) crossLogSection(ctx context.Context) (json.RawMessage, error) {
	if len(g.federation) == 0 {
		return nil, nil // non-federated network ⇒ null section
	}
	head, err := g.getHorizon()
	if err != nil {
		return nil, err
	}
	// Cycle path: seed with THIS network so a child cannot recurse back into it.
	myNID, err := g.networkID()
	if err != nil {
		return nil, err
	}
	path := g.fedPath
	if path == nil {
		path = map[cosign.NetworkID]bool{myNID: true}
	}

	anchors, err := g.discoverCitedAnchors(ctx, head.TreeSize)
	if err != nil {
		return nil, err
	}
	var elements []sdkbundle.CrossLogAnchor
	for _, da := range anchors {
		member := g.federation[da.sourceLogDID]
		bNID := member.Bundle.TrustRoot.NetworkID
		if path[bNID] {
			continue // cycle back-edge — do not re-prove (verifier would fail closed)
		}
		if !member.Bundle.Citable() {
			return nil, fmt.Errorf("bundle/standalone: cited network %s has no CitedMemberKey (cannot build its nested proof)", da.sourceLogDID)
		}
		if g.fedDepth+1 > verifier.MaxCompoundProofDepth {
			return nil, fmt.Errorf("bundle/standalone: federation depth %d exceeds max %d", g.fedDepth+1, verifier.MaxCompoundProofDepth)
		}
		embeddedHead, err := extractAnchorHead(da.parsed)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: extract anchor head for %s: %w", da.sourceLogDID, err)
		}
		inc, err := g.client.InclusionProofAtSize(da.seq, head.TreeSize)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: anchor inclusion %d@%d: %w", da.seq, head.TreeSize, err)
		}
		if inc == nil {
			return nil, fmt.Errorf("bundle/standalone: nil anchor inclusion for seq %d", da.seq)
		}
		nested, err := g.gatherNestedProof(ctx, member, embeddedHead, path, bNID)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: nested proof for %s: %w", da.sourceLogDID, err)
		}
		elements = append(elements, sdkbundle.CrossLogAnchor{
			ReferencedNetworkID: bNID,
			AnchorEntry:         da.canonical,
			AnchorInclusion:     *inc,
			NestedProof:         nested,
			Depth:               g.fedDepth + 1,
		})
	}
	if len(elements) == 0 {
		return nil, nil
	}
	return sdkbundle.EncodeCrossLogAnchors(elements)
}

// discoveredAnchor is one cited anchor entry found on A's log.
type discoveredAnchor struct {
	seq          uint64
	canonical    []byte
	sourceLogDID string
	parsed       anchor.CosignedAnchorV1
}

// discoverCitedAnchors scans A's committed prefix [0, treeSize) for
// BP-ENTRY-ANCHOR-COSIGNED-HEAD-V1 entries whose source_log_did is in the
// federation registry, keeping the LATEST (highest seq) per cited network. Anchors
// to networks not in the registry are ignored (not cited by this proof). Discovery
// is by KIND (anchors carry no schema_ref) — an O(N) scan only federated proofs pay.
func (g *StandaloneLedgerGather) discoverCitedAnchors(ctx context.Context, treeSize uint64) ([]discoveredAnchor, error) {
	var all []discoveredAnchor
	for start := uint64(0); start < treeSize; {
		raws, err := g.client.ScanFrom(ctx, start, anchorScanBatch)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: scan anchors from %d: %w", start, err)
		}
		if len(raws) == 0 {
			break
		}
		for _, r := range raws {
			if r.Sequence >= treeSize {
				continue // never trust entries beyond the cosigned prefix
			}
			if r.Sequence+1 > start {
				start = r.Sequence + 1
			}
			canonical, err := hex.DecodeString(r.CanonicalHex)
			if err != nil {
				return nil, fmt.Errorf("bundle/standalone: anchor scan entry %d canonical: %w", r.Sequence, err)
			}
			e, err := envelope.Deserialize(canonical)
			if err != nil {
				continue // not an envelope — background traffic
			}
			if !anchor.IsCosignedAnchor(e.DomainPayload) {
				continue // not an anchor entry
			}
			a, err := anchor.ParseCosignedAnchorV1(e.DomainPayload)
			if err != nil {
				continue // malformed anchor payload — skip, not our cited set's concern
			}
			if _, cited := g.federation[a.SourceLogDID]; !cited {
				continue // anchors a network we are not citing
			}
			all = append(all, discoveredAnchor{
				seq: r.Sequence, canonical: canonical, sourceLogDID: a.SourceLogDID, parsed: a,
			})
		}
	}
	return keepLatestPerNetwork(all), nil
}

// keepLatestPerNetwork reduces discovered anchors to the LATEST (highest seq) per
// cited network — a network re-anchored every interval, and the proof binds to the
// most recent head under the checkpoint.
func keepLatestPerNetwork(in []discoveredAnchor) []discoveredAnchor {
	latest := make(map[string]discoveredAnchor, len(in))
	for _, da := range in {
		if prev, ok := latest[da.sourceLogDID]; !ok || da.seq > prev.seq {
			latest[da.sourceLogDID] = da
		}
	}
	out := make([]discoveredAnchor, 0, len(latest))
	for _, da := range latest {
		out = append(out, da)
	}
	return out
}

// gatherNestedProof builds the cited network's full v2 proof, PINNED to the head
// the anchor embeds (the verifier's bind), targeting the network's CitedMemberKey,
// with the federation recursion threaded (depth+1, this network added to the cycle
// path). The nested proof recursively carries its own cross_log_anchors.
func (g *StandaloneLedgerGather) gatherNestedProof(
	ctx context.Context,
	member FederationMember,
	embeddedHead types.CosignedTreeHead,
	path map[cosign.NetworkID]bool,
	bNID cosign.NetworkID,
) (*sdkbundle.StandaloneProof, error) {
	citedKey := member.Bundle.CitedMemberKey
	// Resolve the cited member's sequence against the EMBEDDED head's SMT root, so
	// every leg of the nested proof binds to that one pinned checkpoint.
	seq, err := resolveCitedMemberSeq(ctx, member.HTTPClient, member.Bundle.Endpoint, citedKey, embeddedHead.SMTRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve cited member seq: %w", err)
	}
	bg, err := NewBundleGather(ctx, member.Bundle, member.Client, member.HTTPClient, seq, citedKey,
		WithFederationRegistry(g.federation))
	if err != nil {
		return nil, err
	}
	bg.horizon = &embeddedHead // PIN: the nested checkpoint == the anchor's embedded head
	bg.fedDepth = g.fedDepth + 1
	bg.fedPath = clonePathAdd(path, bNID)
	return sdkbundle.BuildStandalone(ctx, bg, seq)
}

// resolveCitedMemberSeq reads the cited member's committed sequence from its SMT
// membership proof at the pinned head's root (GET /v1/smt/proof/{key}?smt_root=…),
// mirroring the as-of resolution the e2e uses for the top-level entry.
func resolveCitedMemberSeq(ctx context.Context, hc *http.Client, endpoint string, key, smtRoot [32]byte) (uint64, error) {
	url := fmt.Sprintf("%s/v1/smt/proof/%s?smt_root=%s",
		strings.TrimRight(endpoint, "/"), hex.EncodeToString(key[:]), hex.EncodeToString(smtRoot[:]))
	var body struct {
		Type  string         `json:"type"`
		Proof types.SMTProof `json:"proof"`
	}
	if err := getJSONBounded(ctx, hc, url, &body); err != nil {
		return 0, err
	}
	if body.Type != "membership" || body.Proof.TerminalLeaf == nil {
		return 0, fmt.Errorf("cited member not present at the pinned head (type=%q)", body.Type)
	}
	leaf := body.Proof.TerminalLeaf
	if !leaf.OriginTip.IsNull() {
		return leaf.OriginTip.Sequence, nil
	}
	if !leaf.AuthorityTip.IsNull() {
		return leaf.AuthorityTip.Sequence, nil
	}
	return 0, fmt.Errorf("cited member SMT leaf has no committed position")
}

// extractAnchorHead reconstructs the foreign cosigned head embedded in an anchor
// (parse-only; the verifier re-checks its K-of-N). This is the head the nested
// proof must be pinned to.
func extractAnchorHead(a anchor.CosignedAnchorV1) (types.CosignedTreeHead, error) {
	finding, err := findings.CosignedTreeHeadFromWire(a.Head)
	if err != nil {
		return types.CosignedTreeHead{}, err
	}
	return finding.Head, nil
}

// networkID returns this gather's own NetworkID (the cycle-guard key), from the
// configured bootstrap.
func (g *StandaloneLedgerGather) networkID() (cosign.NetworkID, error) {
	ids, err := g.bootstrap.IDs()
	if err != nil {
		return cosign.NetworkID{}, fmt.Errorf("bundle/standalone: bootstrap IDs: %w", err)
	}
	return cosign.NetworkID(ids.NetworkID), nil
}

// clonePathAdd copies the cycle path and adds nid (so a sibling branch never sees
// a child's additions).
func clonePathAdd(path map[cosign.NetworkID]bool, nid cosign.NetworkID) map[cosign.NetworkID]bool {
	out := make(map[cosign.NetworkID]bool, len(path)+1)
	for k := range path {
		out[k] = true
	}
	out[nid] = true
	return out
}
