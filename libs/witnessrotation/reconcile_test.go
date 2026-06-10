// FILE PATH: libs/witnessrotation/reconcile_test.go
//
// Tests for the incremental scan reconciler (reconcile.go). Same real-crypto
// posture as rebuild_test.go: real ECDSA sets, real rotations, a real RFC 6962
// tree, real cosigned heads — only transport and persistence are in-memory.
package witnessrotation

import (
	"context"
	"crypto/sha256"
	"errors"
	"sort"
	"testing"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// memJournal is an in-memory RotationJournal (idempotent on EffectivePos).
type memJournal struct {
	recs map[uint64]types.WitnessRotationRecord
}

func newMemJournal() *memJournal { return &memJournal{recs: map[uint64]types.WitnessRotationRecord{}} }

func (m *memJournal) RecordsFor(_ context.Context, logDID string) ([]types.WitnessRotationRecord, error) {
	out := make([]types.WitnessRotationRecord, 0, len(m.recs))
	for _, r := range m.recs {
		if r.EffectivePos.LogDID == logDID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EffectivePos.Sequence < out[j].EffectivePos.Sequence })
	return out, nil
}

func (m *memJournal) RecordRotation(_ context.Context, rec types.WitnessRotationRecord) error {
	if _, dup := m.recs[rec.EffectivePos.Sequence]; dup {
		return nil // idempotent, like ON CONFLICT DO NOTHING
	}
	m.recs[rec.EffectivePos.Sequence] = rec
	return nil
}

// memCursor is an in-memory CursorStore.
type memCursor struct{ c map[string]uint64 }

func newMemCursor() *memCursor { return &memCursor{c: map[string]uint64{}} }

func (m *memCursor) ScanCursor(_ context.Context, logDID string) (uint64, error) {
	return m.c[logDID], nil
}
func (m *memCursor) SetScanCursor(_ context.Context, logDID string, until uint64) error {
	if until > m.c[logDID] {
		m.c[logDID] = until
	}
	return nil
}

// memHeads is an in-memory VerifiedHeadSource.
type memHeads struct{ h map[string]types.CosignedTreeHead }

func (m *memHeads) LatestVerifiedHead(_ context.Context, logDID string) (types.CosignedTreeHead, bool, error) {
	h, ok := m.h[logDID]
	return h, ok, nil
}

// journalRotation records a gossip-style verified rotation into the journal.
func journalRotation(t *testing.T, j *memJournal, canonical []byte, seq uint64) {
	t.Helper()
	rot, err := witness.DecodeWitnessRotationEntry(canonical)
	if err != nil {
		t.Fatalf("decode rotation: %v", err)
	}
	if err := j.RecordRotation(context.Background(), types.WitnessRotationRecord{
		Rotation:     rot,
		EffectivePos: types.LogPosition{LogDID: rbLogDID, Sequence: seq},
	}); err != nil {
		t.Fatalf("RecordRotation: %v", err)
	}
}

// rotationSeqs returns the positions of the rotation entries in a fakeLog.
func rotationSeqs(fl *fakeLog) []uint64 {
	var seqs []uint64
	for s := range fl.canonical {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs
}

// TestScanReconciler_JournalCurrent_ScanIsIdempotent: the journal already holds
// the full chain (gossip delivered everything); the anchor verifies the live
// horizon directly, the scan re-discovers both rotations as duplicates, and the
// cursor advances. A second pass is a no-op.
func TestScanReconciler_JournalCurrent_ScanIsIdempotent(t *testing.T) {
	const n, k = 5, 3
	s0, s1, s2 := newKit(t, n, k), newKit(t, n, k), newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1, s2}, 50, s2) // horizon cosigned by current set s2

	j := newMemJournal()
	seqs := rotationSeqs(fl)
	journalRotation(t, j, fl.canonical[seqs[0]], seqs[0])
	journalRotation(t, j, fl.canonical[seqs[1]], seqs[1])

	cur := newMemCursor()
	rec, err := NewScanReconciler(ScanReconcilerConfig{
		Src: fl, Journal: j, Cursor: cur, Genesis: s0.set, LogDID: rbLogDID,
	})
	if err != nil {
		t.Fatalf("NewScanReconciler: %v", err)
	}

	report, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if report.DegradedTarget {
		t.Error("anchor is current; the live horizon must verify directly")
	}
	if report.Discovered != 2 || report.NewlyJournaled != 0 {
		t.Errorf("Discovered=%d NewlyJournaled=%d, want 2/0 (all gossip-fed)", report.Discovered, report.NewlyJournaled)
	}
	if report.Until != fl.horizon.TreeSize {
		t.Errorf("Until=%d, want horizon %d", report.Until, fl.horizon.TreeSize)
	}

	// Second pass: nothing new committed ⇒ no-op window.
	report2, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce #2: %v", err)
	}
	if report2.Until != report2.From || report2.Discovered != 0 {
		t.Errorf("second pass not a no-op: %+v", report2)
	}
}

// TestScanReconciler_TailOmission_FallbackTarget: gossip delivered R1 but the
// ledger WITHHELD R2's finding, and the live horizon is already cosigned by
// s2 — unverifiable under the journal anchor (s1). The reconciler must fall
// back to the last VERIFIED head (a transitional s1-cosigned head), discover
// R2 in the scan window, journal it, and advance — closing tail-omission. The
// NEXT pass's anchor includes s2, so the live horizon verifies again
// (self-healing).
func TestScanReconciler_TailOmission_FallbackTarget(t *testing.T) {
	const n, k = 5, 3
	s0, s1, s2 := newKit(t, n, k), newKit(t, n, k), newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1, s2}, 50, s2)

	j := newMemJournal()
	seqs := rotationSeqs(fl)
	journalRotation(t, j, fl.canonical[seqs[0]], seqs[0]) // R1 via gossip; R2 withheld

	// The transitional head: same tree, cosigned by the OUTGOING set s1 — the
	// kind of head the auditor verified and stored during the fuzzy window.
	fallback := &memHeads{h: map[string]types.CosignedTreeHead{
		rbLogDID: cosignHead(t, fl.horizon.TreeHead, s1, k),
	}}

	cur := newMemCursor()
	rec, err := NewScanReconciler(ScanReconcilerConfig{
		Src: fl, Journal: j, Cursor: cur, Fallback: fallback, Genesis: s0.set, LogDID: rbLogDID,
	})
	if err != nil {
		t.Fatalf("NewScanReconciler: %v", err)
	}

	report, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !report.DegradedTarget {
		t.Error("expected the degraded (fallback) target path")
	}
	if report.NewlyJournaled != 1 {
		t.Errorf("NewlyJournaled=%d, want 1 (the withheld R2)", report.NewlyJournaled)
	}
	recs, _ := j.RecordsFor(context.Background(), rbLogDID)
	if len(recs) != 2 {
		t.Fatalf("journal holds %d records, want 2 after reconciliation", len(recs))
	}

	// Self-healing: with R2 journaled, the anchor is s2 and the LIVE horizon
	// verifies directly on the next pass.
	report2, err := rec.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce #2: %v", err)
	}
	if report2.DegradedTarget {
		t.Error("second pass must use the live horizon (anchor now current)")
	}
}

// TestScanReconciler_NoVerifiableTarget_FailsLoud: rotated log, empty journal,
// no fallback — the horizon cannot be authenticated under genesis and the pass
// must fail with ErrNoVerifiableTarget (a fresh auditor catches up via the
// gossip backlog first; the scan never trusts an unverifiable target).
func TestScanReconciler_NoVerifiableTarget_FailsLoud(t *testing.T) {
	const n, k = 5, 3
	s0, s1 := newKit(t, n, k), newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1}, 20, s1)

	rec, err := NewScanReconciler(ScanReconcilerConfig{
		Src: fl, Journal: newMemJournal(), Cursor: newMemCursor(), Genesis: s0.set, LogDID: rbLogDID,
	})
	if err != nil {
		t.Fatalf("NewScanReconciler: %v", err)
	}
	if _, err := rec.RunOnce(context.Background()); !errors.Is(err, ErrNoVerifiableTarget) {
		t.Fatalf("err = %v, want ErrNoVerifiableTarget", err)
	}
}

// TestScanReconciler_InvalidOnLogRotation_NotJournaled: the log contains a
// committed rotation-kind entry that does NOT verify under the authoritative
// set (an s1→s2 rotation on a genesis-s0 log). The scan must surface
// ErrOnLogRotationInvalid, journal nothing, and leave the cursor unmoved so
// every later pass re-flags the evidence.
func TestScanReconciler_InvalidOnLogRotation_NotJournaled(t *testing.T) {
	const n, k = 5, 3
	s0, s1, s2 := newKit(t, n, k), newKit(t, n, k), newKit(t, n, k)
	// One bogus rotation entry (s1→s2: its CurrentSetHash pins s1, not the
	// genesis s0), committed in a log whose horizon is still s0-cosigned —
	// consistent, since no VALID rotation ever happened.
	fl := buildFakeLog(t, []setKit{s0}, 10, s0)
	bogus := rotation(t, s1, s2, k)
	id := leafIDOf(bogus)
	pos, err := fl.tree.AppendLeaf(id[:])
	if err != nil {
		t.Fatalf("AppendLeaf: %v", err)
	}
	fl.canonical[pos] = bogus
	head, _ := fl.tree.Head()
	th := types.TreeHead{RootHash: head.RootHash, SMTRoot: fill(0x5A), ReceiptRoot: fill(0x4C), TreeSize: head.TreeSize}
	fl.horizon = cosignHead(t, th, s0, k)

	j := newMemJournal()
	cur := newMemCursor()
	rec, err := NewScanReconciler(ScanReconcilerConfig{
		Src: fl, Journal: j, Cursor: cur, Genesis: s0.set, LogDID: rbLogDID,
	})
	if err != nil {
		t.Fatalf("NewScanReconciler: %v", err)
	}
	if _, err := rec.RunOnce(context.Background()); !errors.Is(err, ErrOnLogRotationInvalid) {
		t.Fatalf("err = %v, want ErrOnLogRotationInvalid", err)
	}
	if recs, _ := j.RecordsFor(context.Background(), rbLogDID); len(recs) != 0 {
		t.Errorf("journal holds %d records, want 0 (unauthorized rotation must not be journaled)", len(recs))
	}
	if got, _ := cur.ScanCursor(context.Background(), rbLogDID); got != 0 {
		t.Errorf("cursor=%d, want 0 (failed pass must not claim coverage)", got)
	}
}

// TestScanReconciler_BrokenJournalChain_FailsClosed: a journal whose chain does
// not walk from genesis is corruption — RunOnce must refuse to extend it.
func TestScanReconciler_BrokenJournalChain_FailsClosed(t *testing.T) {
	const n, k = 5, 3
	s0, s1, s2 := newKit(t, n, k), newKit(t, n, k), newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1}, 20, s1)

	j := newMemJournal()
	journalRotation(t, j, rotation(t, s1, s2, k), 5) // s1→s2 cannot verify under genesis s0

	rec, err := NewScanReconciler(ScanReconcilerConfig{
		Src: fl, Journal: j, Cursor: newMemCursor(), Genesis: s0.set, LogDID: rbLogDID,
	})
	if err != nil {
		t.Fatalf("NewScanReconciler: %v", err)
	}
	if _, err := rec.RunOnce(context.Background()); !errors.Is(err, ErrJournalChainBroken) {
		t.Fatalf("err = %v, want ErrJournalChainBroken", err)
	}
}

// leafIDOf mirrors buildFakeLog's leaf hashing for appended blobs.
func leafIDOf(b []byte) [32]byte { return sha256.Sum256(b) }
