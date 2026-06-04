package gossipverify

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// eraResolver is a position-aware resolver that maps an asOf sequence to a
// witness set — modelling reconstruction returning DIFFERENT era sets at
// different historical positions (what a real rotation chain does).
type eraResolver struct {
	bySeq map[uint64]*cosign.WitnessKeySet
}

func (e eraResolver) SetForHead(context.Context, string, types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	return nil, errors.New("eraResolver: SetForHead not used")
}

func (e eraResolver) SetAt(_ context.Context, _ string, asOf types.LogPosition) (*cosign.WitnessKeySet, error) {
	if s, ok := e.bySeq[asOf.Sequence]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("eraResolver: no set at seq %d", asOf.Sequence)
}

// TestGossipVerifier_PositionAware_HistoricalEquivocationVerifies: the registry
// SNAPSHOT holds the MODERN set, but an equivocation's two heads were cosigned by
// the HISTORIC (since-rotated-away) set. Position-anchored resolution (SetAt at
// the shared size) verifies it; the snapshot path falsely rejects it — the exact
// gap where a year-1 equivocation would be silently dropped (no slash).
func TestGossipVerifier_PositionAware_HistoricalEquivocationVerifies(t *testing.T) {
	const n, k = 3, 2
	historic := newVGWitnesses(t, n, k)
	modern := newVGWitnesses(t, n, k)

	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: modern.set}, modern.nid)

	// Two conflicting heads at the SAME size, both cosigned by the HISTORIC set.
	proof := witness.EquivocationProof{
		TreeSize:   100,
		HeadA:      historic.cosignedHead(t, 100, 0xAA),
		HeadB:      historic.cosignedHead(t, 100, 0xBB),
		ValidSigsA: n, ValidSigsB: n,
	}
	f, err := findings.NewEquivocationFinding(proof, "ep")
	if err != nil {
		t.Fatal(err)
	}
	ev := signedEventForFinding(t, vgSrc, f)

	// WITHOUT a resolver: the historic heads fail against the modern snapshot.
	gvBlind, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	if _, err := gvBlind.Verify(context.Background(), ev); err == nil {
		t.Fatal("snapshot path verified a historic equivocation against the modern set — bug not reproduced")
	}

	// WITH a position-aware resolver returning the historic set at the head's era.
	gvAware, _ := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{},
		WitnessSets: reg,
		Resolver:    stubHeadResolver{set: historic.set}, // SetAt returns the historic set
	})
	if _, err := gvAware.Verify(context.Background(), ev); err != nil {
		t.Fatalf("position-aware Verify rejected a historic equivocation against its own set: %v", err)
	}
}

// TestGossipVerifier_PositionAware_HistoryRewriteCrossRotation: a history-rewrite
// whose OldHead (size 100) and NewHead (size 200) straddle a rotation — OldHead
// cosigned by S0, NewHead by S1. The MULTI-ERA path (VerifyEra with a set per
// anchor) verifies it; no single set in the snapshot can, so the snapshot path
// rejects it.
func TestGossipVerifier_PositionAware_HistoryRewriteCrossRotation(t *testing.T) {
	const n, k = 3, 2
	s0 := newVGWitnesses(t, n, k) // OldHead era
	s1 := newVGWitnesses(t, n, k) // NewHead era
	modern := newVGWitnesses(t, n, k)

	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: modern.set}, modern.nid)

	p := witness.HistoryRewriteProof{
		OldHead:          s0.cosignedHead(t, 100, 0xAA),
		NewHead:          s1.cosignedHead(t, 200, 0xBB),
		ConsistencyProof: [][]byte{make([]byte, 32)}, // canonical FAILING proof
		ValidSigsOld:     n, ValidSigsNew: n,
	}
	f, err := findings.NewHistoryRewriteFinding(p, "ep")
	if err != nil {
		t.Fatal(err)
	}
	ev := signedEventForFinding(t, vgSrc, f)

	// WITHOUT a resolver: no single snapshot set verifies both eras → rejected.
	gvBlind, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	if _, err := gvBlind.Verify(context.Background(), ev); err == nil {
		t.Fatal("snapshot path verified a cross-rotation history-rewrite under one set — bug not reproduced")
	}

	// WITH a per-era resolver: size 100 → asOf 99 → S0; size 200 → asOf 199 → S1.
	resolver := eraResolver{bySeq: map[uint64]*cosign.WitnessKeySet{99: s0.set, 199: s1.set}}
	gvAware, _ := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{},
		WitnessSets: reg,
		Resolver:    resolver,
	})
	if _, err := gvAware.Verify(context.Background(), ev); err != nil {
		t.Fatalf("multi-era Verify rejected a genuine cross-rotation history-rewrite: %v", err)
	}
}

// TestGossipVerifier_PositionAware_MultiEraResolveMiss_FallsBack: if one era
// fails to resolve, the multi-era finding falls back to the snapshot (non-fatal),
// never dropped silently by the resolver seam.
func TestGossipVerifier_PositionAware_MultiEraResolveMiss_FallsBack(t *testing.T) {
	const n, k = 3, 2
	s0 := newVGWitnesses(t, n, k)
	// Both heads cosigned by s0 (same era, no rotation between) so the SNAPSHOT
	// (holding s0) can verify after fallback.
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: s0.set}, s0.nid)

	p := witness.HistoryRewriteProof{
		OldHead:          s0.cosignedHead(t, 100, 0xAA),
		NewHead:          s0.cosignedHead(t, 200, 0xBB),
		ConsistencyProof: [][]byte{make([]byte, 32)},
		ValidSigsOld:     n, ValidSigsNew: n,
	}
	f, _ := findings.NewHistoryRewriteFinding(p, "ep")
	ev := signedEventForFinding(t, vgSrc, f)

	// Resolver resolves the first era but MISSES the second → resolveAnchors fails
	// → fall back to the snapshot (which holds s0) → Verify still passes.
	resolver := eraResolver{bySeq: map[uint64]*cosign.WitnessKeySet{99: s0.set}} // 199 missing
	gv, _ := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{},
		WitnessSets: reg,
		Resolver:    resolver,
	})
	if _, err := gv.Verify(context.Background(), ev); err != nil {
		t.Fatalf("partial resolve must fall back to snapshot, not drop: %v", err)
	}
}
