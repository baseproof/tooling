package gossipverify

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
)

const vgSrc = "did:web:source.log"

func TestGossipVerifier_CosignedTreeHead_HappyPath(t *testing.T) {
	w := newVGWitnesses(t, 3, 2)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: w.set}, w.nid)
	gv, err := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.NewCosignedTreeHeadFinding(w.cosignedHead(t, 100, 0xAA), "ep")
	if err != nil {
		t.Fatal(err)
	}
	got, err := gv.Verify(context.Background(), signedEventForFinding(t, vgSrc, f))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Kind() != gossip.KindCosignedTreeHead {
		t.Fatalf("kind = %q", got.Kind())
	}
}

// Tier 1 gate: a forged/invalid envelope is rejected before any finding work.
func TestGossipVerifier_EnvelopeFails(t *testing.T) {
	w := newVGWitnesses(t, 1, 1)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: w.set}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{err: errors.New("forged envelope")},
		WitnessSets: reg,
	})
	f, _ := findings.NewCosignedTreeHeadFinding(w.cosignedHead(t, 100, 0xAA), "ep")
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, vgSrc, f)); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}

// Tier 2 gate: a head whose cosignatures don't match the LOCALLY-trusted set is
// rejected even though the envelope passed.
func TestGossipVerifier_WrongWitnessSetFailsFindingProof(t *testing.T) {
	w := newVGWitnesses(t, 3, 2)
	other := newVGWitnesses(t, 3, 2)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: other.set}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	f, _ := findings.NewCosignedTreeHeadFinding(w.cosignedHead(t, 100, 0xAA), "ep")
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, vgSrc, f)); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}

// A self-attested Kind (originator rotation) verifies on envelope authenticity
// alone — no witness set required.
func TestGossipVerifier_OriginatorRotation_SelfAttested(t *testing.T) {
	w := newVGWitnesses(t, 1, 1)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	f, err := findings.NewOriginatorRotationFinding([]byte{0x02, 0x01, 0x03}, [32]byte{0x09})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, "did:peer", f)); err != nil {
		t.Fatalf("self-attested verify: %v", err)
	}
}

func TestGossipVerifier_UnknownKindFailsDecode(t *testing.T) {
	w := newVGWitnesses(t, 1, 1)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	ev := gossip.SignedEvent{Kind: "BP-GOSSIP-NOPE-V1", Originator: "did:peer", Body: []byte(`{}`)}
	if _, err := gv.Verify(context.Background(), ev); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}

func TestNewGossipVerifier_RequiresRegistry(t *testing.T) {
	if _, err := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}}); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}

// stubHeadResolver returns a fixed set for any head — exercises the verifier's
// position-aware override seam (the auditor's real resolver is tested in its
// own package).
type stubHeadResolver struct {
	set *cosign.WitnessKeySet
	err error
}

func (s stubHeadResolver) SetForHead(_ context.Context, _ string, _ types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	return s.set, s.err
}

func (s stubHeadResolver) SetAt(_ context.Context, _ string, _ types.LogPosition) (*cosign.WitnessKeySet, error) {
	return s.set, s.err
}

// TestGossipVerifier_PositionAware_HistoricalHeadVerifies is the live-path proof
// of the position-blindness fix: the registry SNAPSHOT holds the MODERN set, but
// the finding's head is cosigned by the HISTORIC set. With a resolver returning
// the historic set, Verify PASSES (the head is checked against the set that
// cosigned it); the same finding FAILS without the resolver (snapshot = modern).
func TestGossipVerifier_PositionAware_HistoricalHeadVerifies(t *testing.T) {
	historic := newVGWitnesses(t, 3, 2)
	modern := newVGWitnesses(t, 3, 2) // different keys; shares vgNetworkID via newVGWitnesses

	// Registry (the position-blind snapshot) holds the MODERN set for vgSrc.
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: modern.set}, modern.nid)

	// A head cosigned by the HISTORIC set (e.g. a year-1 STH).
	histHead := historic.cosignedHead(t, 100, 0xAA)
	f, err := findings.NewCosignedTreeHeadFinding(histHead, "ep")
	if err != nil {
		t.Fatal(err)
	}
	ev := signedEventForFinding(t, vgSrc, f)

	// WITHOUT a resolver (legacy snapshot path): the historic head fails against
	// the modern set — the position-blind bug.
	gvBlind, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	if _, err := gvBlind.Verify(context.Background(), ev); err == nil {
		t.Fatal("legacy snapshot path verified a historic head against the modern set — bug not reproduced")
	}

	// WITH the resolver (position-aware): the head is verified against the
	// historic set that cosigned it → PASSES.
	gvAware, _ := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{},
		WitnessSets: reg,
		Resolver:    stubHeadResolver{set: historic.set},
	})
	got, err := gvAware.Verify(context.Background(), ev)
	if err != nil {
		t.Fatalf("position-aware Verify rejected a historic head against its own set: %v", err)
	}
	if got.Kind() != gossip.KindCosignedTreeHead {
		t.Fatalf("kind = %q", got.Kind())
	}
}

// TestGossipVerifier_PositionAware_ResolverFailureFallsBackToSnapshot: a
// resolver error must NOT drop the finding — it falls back to the snapshot
// (legacy path), so a transient ledger/scan hiccup degrades gracefully.
func TestGossipVerifier_PositionAware_ResolverFailureFallsBackToSnapshot(t *testing.T) {
	w := newVGWitnesses(t, 3, 2)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: w.set}, w.nid)
	f, _ := findings.NewCosignedTreeHeadFinding(w.cosignedHead(t, 100, 0xAA), "ep")
	ev := signedEventForFinding(t, vgSrc, f)

	// Resolver errors → fall back to the snapshot (which holds the correct set
	// here) → Verify still PASSES.
	gv, _ := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{},
		WitnessSets: reg,
		Resolver:    stubHeadResolver{err: errors.New("ledger unreachable")},
	})
	if _, err := gv.Verify(context.Background(), ev); err != nil {
		t.Fatalf("resolver failure should fall back to snapshot, not drop: %v", err)
	}
}
