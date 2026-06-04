package monitoring

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// testNetworkID is a valid 64-hex (32-byte) gossip network id for events
// hand-built in tests.
var testNetworkID = strings.Repeat("ab", 32)

// stubVerifier returns a fixed (event, err), simulating the two-tier verifier.
type stubVerifier struct {
	ev  gossip.Event
	err error
}

func (s stubVerifier) Verify(_ context.Context, _ gossip.SignedEvent) (gossip.Event, error) {
	return s.ev, s.err
}

func cthFinding(t *testing.T, size uint64, root byte) *findings.CosignedTreeHeadFinding {
	t.Helper()
	head := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: size, RootHash: [32]byte{root}, SMTRoot: [32]byte{0xBB}, ReceiptRoot: [32]byte{0xCC}},
		Signatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: 1, SigBytes: []byte{0xAA}}},
	}
	f, err := findings.NewCosignedTreeHeadFinding(head, "ep")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// appendErrStore fails only on Append; other gossip.Store methods are
// never called by HandleSignedEvent (embedded nil interface would panic).
type appendErrStore struct{ gossip.Store }

func (appendErrStore) Append(context.Context, gossip.SignedEvent) error {
	return errors.New("boom")
}

// D7: a verified inbound event is persisted to the store.
func TestReconciler_PersistsVerifiedEvent(t *testing.T) {
	store := gossip.NewInMemoryStore()
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: cthFinding(t, 100, 0xAA)},
		Heads:    NewTrustedHeadStore(nil),
		Store:    store,
	})
	ev := gossip.SignedEvent{Version: gossip.WireVersion, NetworkID: testNetworkID, Originator: "did:key:zTest", Kind: gossip.KindCosignedTreeHead, LamportTime: 1}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("HandleSignedEvent: %v", err)
	}
	id, err := gossip.EventIDOf(ev)
	if err != nil {
		t.Fatalf("EventIDOf: %v", err)
	}
	if _, err := store.Get(context.Background(), id); err != nil {
		t.Fatalf("verified event was not persisted: %v", err)
	}
}

// D7: persistence is the async clock — a store failure is logged but must
// not fail the pull (enforcement still ran).
func TestReconciler_PersistFailure_NonFatal(t *testing.T) {
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: cthFinding(t, 100, 0xAA)},
		Heads:    NewTrustedHeadStore(nil),
		Store:    appendErrStore{},
	})
	ev := gossip.SignedEvent{Version: gossip.WireVersion, Originator: "did:key:z", Kind: gossip.KindCosignedTreeHead, LamportTime: 1}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("persist failure must be non-fatal, got %v", err)
	}
}

// A verification failure must error and reach no enforcer.
func TestReconciler_VerifyFails_NoAct(t *testing.T) {
	heads := NewTrustedHeadStore(nil)
	r, _ := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{err: errors.New("forged")}, Heads: heads})
	if err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:peer"}); err == nil {
		t.Fatal("verification failure must surface as an error")
	}
	if _, ok := heads.TrustedHead("did:peer"); ok {
		t.Fatal("no head may be recorded when verification fails")
	}
}

func TestReconciler_CosignedTreeHead_RecordsHead(t *testing.T) {
	heads := NewTrustedHeadStore(nil)
	r, _ := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{ev: cthFinding(t, 100, 0xAA)}, Heads: heads})
	ev := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:peer"}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("handle: %v", err)
	}
	h, ok := heads.TrustedHead("did:peer")
	if !ok || h.TreeSize != 100 {
		t.Fatalf("head not recorded: %+v ok=%v", h, ok)
	}
}

func TestReconciler_Equivocation_DrivesResponder(t *testing.T) {
	ap := &stubApplier{}
	resp, _ := NewEquivocationResponder(ap, nil)
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier:     stubVerifier{ev: &findings.EquivocationFinding{LedgerEndpoint: "https://led"}},
		Heads:        NewTrustedHeadStore(nil),
		Equivocation: resp,
	})
	if err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{Kind: gossip.KindEquivocationFinding}); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !ap.called {
		t.Fatal("equivocation responder/slasher not driven")
	}
}

// A verified Kind with no enforcer wired is logged, not errored.
func TestReconciler_NoEnforcer_NoError(t *testing.T) {
	f, err := findings.NewGhostLeafFinding(7, 3, [32]byte{0xAB}, "did:log", 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{ev: f}, Heads: NewTrustedHeadStore(nil)})
	if err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{Kind: gossip.KindGhostLeaf}); err != nil {
		t.Fatalf("ghost leaf (no enforcer) should not error: %v", err)
	}
}

// stubRotator records the witness-set rotation the reconciler asks it to apply.
type stubRotator struct {
	called bool
	logDID string
	err    error
}

func (s *stubRotator) ApplyVerifiedRotation(logDID string, _ types.WitnessRotation) error {
	s.called = true
	s.logDID = logDID
	return s.err
}

func witnessRotationFinding(t *testing.T) *findings.WitnessRotationFinding {
	t.Helper()
	dummy := types.WitnessSignature{PubKeyID: [32]byte{0x03}, SchemeTag: 1, SigBytes: []byte{0xAA}}
	rot := types.WitnessRotation{
		CurrentSetHash:    [32]byte{0x01},
		NewSet:            []types.WitnessPublicKey{{ID: [32]byte{0x02}, PublicKey: append([]byte{0x04}, make([]byte, 64)...), SchemeTag: 1}},
		SchemeTagOld:      1,
		CurrentSignatures: []types.WitnessSignature{dummy},
		SchemeTagNew:      1,
		NewSignatures:     []types.WitnessSignature{dummy},
	}
	// v1.40 self-contained finding: encode the rotation as the on-log entry
	// payload, wrap + serialize the entry, and bind a one-leaf inclusion proof
	// (LeafHash = OnLogEntryLeafHash(canonical), LeafPosition = EffectivePos).
	payload, err := witness.EncodeWitnessRotationPayload(rot)
	if err != nil {
		t.Fatalf("EncodeWitnessRotationPayload: %v", err)
	}
	entry, err := envelope.NewEntry(
		envelope.ControlHeader{SignerDID: "did:web:ledger.example", Destination: "did:web:ledger.example"},
		payload,
		[]envelope.Signature{{SignerDID: "did:web:ledger.example", AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}},
	)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	const seq = 7
	pos := types.LogPosition{LogDID: "did:web:ledger.example", Sequence: seq}
	proof := &types.MerkleProof{
		LeafPosition: seq,
		LeafHash:     envelope.OnLogEntryLeafHash(canonical),
		TreeSize:     seq + 1,
	}
	f, err := findings.NewWitnessRotationFinding(canonical, pos, proof, "ep")
	if err != nil {
		t.Fatalf("NewWitnessRotationFinding: %v", err)
	}
	return f
}

// A verified witness-set rotation must drive the rotator, keyed by the
// originator (the rotating log's DID — the same key the verifier resolved the
// witness set under).
func TestReconciler_WitnessRotation_DrivesRotator(t *testing.T) {
	rot := &stubRotator{}
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: witnessRotationFinding(t)},
		Heads:    NewTrustedHeadStore(nil),
		Rotator:  rot,
	})
	ev := gossip.SignedEvent{Kind: gossip.KindWitnessRotation, Originator: "did:srclog"}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if !rot.called {
		t.Fatal("verified witness rotation did not drive the rotator")
	}
	if rot.logDID != "did:srclog" {
		t.Fatalf("rotator logDID = %q, want did:srclog (the originator)", rot.logDID)
	}
}

// A verified rotation with no rotator wired is logged, not errored, and never
// advances trust — the fail-safe posture.
func TestReconciler_WitnessRotation_NoRotator_NoError(t *testing.T) {
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: witnessRotationFinding(t)},
		Heads:    NewTrustedHeadStore(nil),
	})
	ev := gossip.SignedEvent{Kind: gossip.KindWitnessRotation, Originator: "did:srclog"}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("nil rotator should not error: %v", err)
	}
}

// A rotator failure (e.g. an untracked log, or a monotonic reject) is
// observable but non-fatal — it must not surface as a pull error.
func TestReconciler_WitnessRotation_RotatorError_NonFatal(t *testing.T) {
	rot := &stubRotator{err: errors.New("no current set")}
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: witnessRotationFinding(t)},
		Heads:    NewTrustedHeadStore(nil),
		Rotator:  rot,
	})
	ev := gossip.SignedEvent{Kind: gossip.KindWitnessRotation, Originator: "did:srclog"}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("rotator error must be non-fatal, got: %v", err)
	}
	if !rot.called {
		t.Fatal("rotator should have been invoked")
	}
}

func TestNewReconciler_Validation(t *testing.T) {
	if _, err := NewReconciler(ReconcilerConfig{Heads: NewTrustedHeadStore(nil)}); err == nil {
		t.Fatal("nil Verifier must error")
	}
	if _, err := NewReconciler(ReconcilerConfig{Verifier: stubVerifier{}}); err == nil {
		t.Fatal("nil Heads must error")
	}
}
