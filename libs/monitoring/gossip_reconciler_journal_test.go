// Reconciler journal-fanout tests (v1.34+).
//
// Pins the contract: when ReconcilerConfig.Journal is non-nil, a
// verified CosignedTreeHeadFinding is recorded into BOTH the live
// in-memory TrustedHeadStore AND the durable HeadsJournal. Journal
// failures must not block the live advance (LAW 4 — durability is
// the async clock, live verification is the action clock).
package monitoring

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/gossip"
)

// fixedClock returns a deterministic CommittedAt the journal stamps
// on each Record. Tests then assert the journal preserved the exact
// timestamp.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// brokenRecJournal returns an error from every Record call. Used to
// pin that journal failures do not break the inner advance.
type brokenRecJournal struct{ MemoryHeadsJournal }

func (b *brokenRecJournal) Record(ctx context.Context, h Head) (RecordVerdict, error) {
	return RecordVerdict{}, errors.New("broken: simulated journal outage")
}

// TestReconciler_Journal_FanOut pins the core contract: a verified
// cosigned head fans out to BOTH the live in-memory anchor AND the
// durable journal.
func TestReconciler_Journal_FanOut(t *testing.T) {
	t.Parallel()
	heads := NewTrustedHeadStore(nil)
	journal := NewMemoryHeadsJournal()
	clock := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	r, err := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: cthFinding(t, 100, 0xAA)},
		Heads:    heads,
		Journal:  journal,
		Now:      fixedClock(clock),
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	ev := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:peer", LamportTime: 42}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("HandleSignedEvent: %v", err)
	}

	// Live anchor advanced.
	live, ok := heads.TrustedHead("did:peer")
	if !ok || live.TreeSize != 100 {
		t.Fatalf("live anchor not advanced: %+v ok=%v", live, ok)
	}

	// Journal recorded with the verified head's wire context.
	got, err := journal.HeadByRootHash(context.Background(), "did:peer", 100, [32]byte{0xAA})
	if err != nil {
		t.Fatalf("journal HeadByRootHash: %v", err)
	}
	if got.TreeSize != 100 || got.RootHash != ([32]byte{0xAA}) {
		t.Errorf("journal head mismatch: got TreeSize=%d RootHash=%x", got.TreeSize, got.RootHash)
	}
	if got.LamportTime != 42 {
		t.Errorf("LamportTime = %d, want 42 (envelope's value)", got.LamportTime)
	}
	if !got.CommittedAt.Equal(clock) {
		t.Errorf("CommittedAt = %v, want %v (injected clock)", got.CommittedAt, clock)
	}
	if len(got.CanonicalBytes) == 0 {
		t.Error("CanonicalBytes empty — wire-format preservation contract violated")
	}
	if len(got.Signatures) != 1 {
		t.Errorf("Signatures len = %d, want 1", len(got.Signatures))
	}
}

// TestReconciler_NilJournal_LiveOnly pins the pre-v1.34 default: when
// Journal is nil, the reconciler behaves identically to its v1.33
// predecessor — only the live anchor advances.
func TestReconciler_NilJournal_LiveOnly(t *testing.T) {
	t.Parallel()
	heads := NewTrustedHeadStore(nil)
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: cthFinding(t, 50, 0xBB)},
		Heads:    heads,
		// Journal: nil (default)
	})
	ev := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:peer"}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("HandleSignedEvent: %v", err)
	}
	live, ok := heads.TrustedHead("did:peer")
	if !ok || live.TreeSize != 50 {
		t.Errorf("live anchor: %+v ok=%v, want size 50", live, ok)
	}
}

// TestReconciler_JournalFailure_NonFatal pins the LAW 4 contract:
// a journal outage is logged but never blocks the live advance.
func TestReconciler_JournalFailure_NonFatal(t *testing.T) {
	t.Parallel()
	heads := NewTrustedHeadStore(nil)
	broken := &brokenRecJournal{*NewMemoryHeadsJournal()}
	r, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: cthFinding(t, 200, 0xCC)},
		Heads:    heads,
		Journal:  broken,
	})
	ev := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:peer"}
	if err := r.HandleSignedEvent(context.Background(), ev); err != nil {
		t.Fatalf("journal failure must not surface: %v", err)
	}
	live, ok := heads.TrustedHead("did:peer")
	if !ok || live.TreeSize != 200 {
		t.Errorf("live anchor must advance even when journal fails: %+v ok=%v", live, ok)
	}
}

// TestReconciler_Journal_BurnTransitionLogged pins that an
// equivocation observed through the journal (same seq, different
// root) transitions the journal's BurnStatus AND is logged.
// LatestHead-style queries on the burned log then fail closed.
func TestReconciler_Journal_BurnTransitionLogged(t *testing.T) {
	t.Parallel()
	heads := NewTrustedHeadStore(nil)
	journal := NewMemoryHeadsJournal()

	// First head.
	r1, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: cthFinding(t, 500, 0xA1)},
		Heads:    heads,
		Journal:  journal,
	})
	ev1 := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:fork", LamportTime: 1}
	if err := r1.HandleSignedEvent(context.Background(), ev1); err != nil {
		t.Fatalf("first event: %v", err)
	}

	// Equivocating fork at the same sequence.
	r2, _ := NewReconciler(ReconcilerConfig{
		Verifier: stubVerifier{ev: cthFinding(t, 500, 0xB2)},
		Heads:    heads,
		Journal:  journal,
	})
	ev2 := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead, Originator: "did:fork", LamportTime: 2}
	if err := r2.HandleSignedEvent(context.Background(), ev2); err != nil {
		t.Fatalf("fork event: %v", err)
	}

	// Journal must now report the log as burned (STRICT FAIL-CLOSED).
	status, err := journal.BurnStatus(context.Background(), "did:fork")
	if err != nil {
		t.Fatalf("BurnStatus: %v", err)
	}
	if !status.Burned {
		t.Error("Burned = false; journal must mark equivocating log burned")
	}
	if status.FirstForkSequence != 500 {
		t.Errorf("FirstForkSequence = %d, want 500", status.FirstForkSequence)
	}

	// LatestHead on a burned log returns ErrEquivocatedLog.
	if _, err := journal.LatestHead(context.Background(), "did:fork"); !errors.Is(err, ErrEquivocatedLog) {
		t.Errorf("LatestHead = %v, want ErrEquivocatedLog", err)
	}

	// Forensic read (HeadsAtSequence) returns BOTH conflicting heads.
	heads2, err := journal.HeadsAtSequence(context.Background(), "did:fork", 500)
	if err != nil {
		t.Fatalf("HeadsAtSequence: %v", err)
	}
	if len(heads2) != 2 {
		t.Errorf("HeadsAtSequence len = %d, want 2 (both forks preserved)", len(heads2))
	}
}
