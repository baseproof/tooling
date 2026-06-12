// Package monitoring HeadsJournal tests.
//
// Each test ties to one or more of the 12 acceptance scenarios
// declared by the network architect (the 15-year lifecycle
// criteria). The scenario reference appears in the test docstring.
package monitoring

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"
)

// ─────────────────────────────────────────────────────────────────────
// Fixture builders
// ─────────────────────────────────────────────────────────────────────

// hdr builds a valid Head fixture with deterministic field values
// derived from logDID + sequence + rootSeed. The rootSeed parameter
// lets a test build two heads at the same (logDID, sequence) with
// different RootHashes — the equivocation case.
func hdr(logDID string, sequence, lamport uint64, rootSeed byte, committedAt time.Time) Head {
	root := [32]byte{rootSeed}
	smt := [32]byte{rootSeed ^ 0xFF}
	rec := [32]byte{}
	return Head{
		LogDID: logDID,
		TreeHead: types.TreeHead{
			RootHash:    root,
			SMTRoot:     smt,
			ReceiptRoot: rec,
			TreeSize:    sequence,
		},
		Signatures: []types.WitnessSignature{
			{
				PubKeyID:  [32]byte{0xAA, rootSeed},
				SchemeTag: 0x01, // ECDSA
				SigBytes:  []byte{0xCD, 0xEF, rootSeed},
			},
		},
		CanonicalBytes: []byte(fmt.Sprintf("wire:%s:%d:%d", logDID, sequence, rootSeed)),
		LamportTime:    lamport,
		CommittedAt:    committedAt,
	}
}

// ts builds a deterministic UTC time.
func ts(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

const (
	tnLogs  = "did:web:tn-logs.example"
	federal   = "did:web:federal-logs.example"
	gaLogs  = "did:web:ga-logs.example"
	corrupted = "did:web:malicious.example"
)

// ─────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────

func TestHeadsJournal_ValidateForRecord(t *testing.T) {
	t.Parallel()

	good := hdr(tnLogs, 1, 1, 0x01, ts(2026, 5, 12))

	cases := []struct {
		name string
		mut  func(*Head)
	}{
		{"empty LogDID", func(h *Head) { h.LogDID = "" }},
		{"zero TreeSize", func(h *Head) { h.TreeSize = 0 }},
		{"empty CanonicalBytes", func(h *Head) { h.CanonicalBytes = nil }},
		{"empty Signatures", func(h *Head) { h.Signatures = nil }},
		{"zero CommittedAt", func(h *Head) { h.CommittedAt = time.Time{} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := good
			c.mut(&h)
			err := ValidateForRecord(h)
			if !errors.Is(err, ErrInvalidHead) {
				t.Fatalf("want errors.Is(ErrInvalidHead), got %v", err)
			}
		})
	}
	if err := ValidateForRecord(good); err != nil {
		t.Errorf("baseline good head failed validation: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Record + idempotence
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_Record_HappyPath_Persists pins the basic Record →
// HeadByRootHash retrieval round-trip with no equivocation.
func TestHeadsJournal_Record_HappyPath_Persists(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()
	h := hdr(tnLogs, 100, 5, 0x01, ts(2026, 5, 12))

	v, err := j.Record(ctx, h)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !v.Persisted {
		t.Error("Persisted = false on a fresh head")
	}
	if v.Equivocation || v.BurnTransition {
		t.Error("flagged equivocation / burn on a clean record")
	}

	got, err := j.HeadByRootHash(ctx, tnLogs, h.TreeSize, h.RootHash)
	if err != nil {
		t.Fatalf("HeadByRootHash: %v", err)
	}
	if got.LogDID != h.LogDID || got.TreeSize != h.TreeSize || got.RootHash != h.RootHash {
		t.Errorf("round-trip mismatch: got %+v want %+v", got.TreeHead, h.TreeHead)
	}
	if string(got.CanonicalBytes) != string(h.CanonicalBytes) {
		t.Errorf("CanonicalBytes drift: got %q want %q", got.CanonicalBytes, h.CanonicalBytes)
	}
}

// TestHeadsJournal_Record_Idempotent_ExactDup pins decision (2):
// duplicate (LogDID, Sequence, RootHash) is a no-op at the
// persistence layer.
func TestHeadsJournal_Record_Idempotent_ExactDup(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()
	h := hdr(tnLogs, 100, 5, 0x01, ts(2026, 5, 12))

	if _, err := j.Record(ctx, h); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	v, err := j.Record(ctx, h)
	if err != nil {
		t.Fatalf("dup Record: %v", err)
	}
	if v.Persisted {
		t.Error("Persisted = true on duplicate (LogDID, Sequence, RootHash)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// SCENARIO 4 + 12 — Equivocation detection & burn transition
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_Equivocation_DetectAndBurn implements scenarios
// 4 (split-brain / fork identification) and 12 (orthogonal
// equivocation detection):
//
//   - two heads at the same (LogDID, Sequence) with different
//     RootHash both persist (forks are physical reality)
//   - the second Record returns Equivocation:true and
//     BurnTransition:true (the watchdog signal)
//   - subsequent reads via HeadAt / HeadAtTime / LatestHead
//     return ErrEquivocatedLog (fail-closed per decision 4)
//   - HeadByRootHash and HeadsAtSequence remain readable for
//     forensic analysis on the burned log
func TestHeadsJournal_Equivocation_DetectAndBurn(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	// First head — clean.
	h1 := hdr(federal, 1_345_000, 5000, 0x01, ts(2027, 7, 4))
	v1, err := j.Record(ctx, h1)
	if err != nil {
		t.Fatalf("first Record: %v", err)
	}
	if v1.Equivocation || v1.BurnTransition {
		t.Fatal("first head should be clean, not equivocation")
	}

	// Second head at SAME sequence, DIFFERENT root — the
	// equivocation event.
	h2 := hdr(federal, 1_345_000, 5001, 0x02, ts(2027, 7, 4))
	v2, err := j.Record(ctx, h2)
	if err != nil {
		t.Fatalf("equivocating Record: %v", err)
	}
	if !v2.Persisted {
		t.Error("the equivocating row MUST persist (both forks are physical reality)")
	}
	if !v2.Equivocation {
		t.Error("Equivocation flag must fire on (Same Sequence, Different RootHash)")
	}
	if !v2.BurnTransition {
		t.Error("BurnTransition must fire on FIRST equivocation observed")
	}
	if v2.ConflictingRoot != h1.RootHash {
		t.Errorf("ConflictingRoot = %x, want %x", v2.ConflictingRoot, h1.RootHash)
	}

	// Burn-aware reads MUST fail closed.
	for _, name := range []string{"HeadAt", "HeadAtTime", "LatestHead"} {
		t.Run("burn_fail_closed_"+name, func(t *testing.T) {
			var err error
			switch name {
			case "HeadAt":
				_, err = j.HeadAt(ctx, federal, 1_345_000)
			case "HeadAtTime":
				_, err = j.HeadAtTime(ctx, federal, ts(2027, 8, 1))
			case "LatestHead":
				_, err = j.LatestHead(ctx, federal)
			}
			if !errors.Is(err, ErrEquivocatedLog) {
				t.Errorf("%s should fail-closed with ErrEquivocatedLog; got %v", name, err)
			}
		})
	}

	// Forensic-surface reads remain available on the burned log.
	t.Run("forensic_HeadByRootHash_h1", func(t *testing.T) {
		got, err := j.HeadByRootHash(ctx, federal, 1_345_000, h1.RootHash)
		if err != nil {
			t.Fatalf("HeadByRootHash h1: %v (forensic retrieval must survive burn)", err)
		}
		if got.RootHash != h1.RootHash {
			t.Errorf("h1 round-trip mismatch")
		}
	})
	t.Run("forensic_HeadByRootHash_h2", func(t *testing.T) {
		got, err := j.HeadByRootHash(ctx, federal, 1_345_000, h2.RootHash)
		if err != nil {
			t.Fatalf("HeadByRootHash h2: %v", err)
		}
		if got.RootHash != h2.RootHash {
			t.Errorf("h2 round-trip mismatch")
		}
	})
	t.Run("forensic_HeadsAtSequence", func(t *testing.T) {
		heads, err := j.HeadsAtSequence(ctx, federal, 1_345_000)
		if err != nil {
			t.Fatalf("HeadsAtSequence: %v", err)
		}
		if len(heads) != 2 {
			t.Fatalf("len(HeadsAtSequence) = %d, want 2 (both forks)", len(heads))
		}
	})

	// BurnStatus reports the transition correctly.
	bs, err := j.BurnStatus(ctx, federal)
	if err != nil {
		t.Fatalf("BurnStatus: %v", err)
	}
	if !bs.Burned {
		t.Error("BurnStatus.Burned = false on equivocated log")
	}
	if bs.FirstForkSequence != 1_345_000 {
		t.Errorf("FirstForkSequence = %d, want 1_345_000", bs.FirstForkSequence)
	}
	if len(bs.ConflictingRoots) != 2 {
		t.Errorf("len(ConflictingRoots) = %d, want 2", len(bs.ConflictingRoots))
	}
}

// TestHeadsJournal_BurnTransition_FiresOnceOnly pins the watchdog
// signal: BurnTransition fires on the FIRST equivocation and never
// again. Lets the responder trigger one-time-only escalation.
func TestHeadsJournal_BurnTransition_FiresOnceOnly(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	// Force the burn.
	mustRecord(t, j, hdr(tnLogs, 100, 1, 0x01, ts(2026, 1, 1)))
	v2, _ := j.Record(ctx, hdr(tnLogs, 100, 2, 0x02, ts(2026, 1, 1)))
	if !v2.BurnTransition {
		t.Fatal("setup: second Record should burn")
	}

	// Third Record on the burned log — Equivocation:true, but
	// BurnTransition:false (the on-call has already been paged).
	v3, err := j.Record(ctx, hdr(tnLogs, 100, 3, 0x03, ts(2026, 1, 2)))
	if err != nil {
		t.Fatalf("third Record on burned log: %v", err)
	}
	if !v3.Equivocation {
		t.Error("third fork should still be flagged as equivocation")
	}
	if v3.BurnTransition {
		t.Error("BurnTransition should fire ONCE; got it on third call too")
	}
}

// ─────────────────────────────────────────────────────────────────────
// HeadAt / HeadAtTime / LatestHead semantics
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_HeadAt_OrderingSemantics pins "at or before":
// HeadAt(N) returns the largest recorded sequence ≤ N.
func TestHeadsJournal_HeadAt_OrderingSemantics(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	mustRecord(t, j, hdr(tnLogs, 10, 1, 0xAA, ts(2026, 1, 1)))
	mustRecord(t, j, hdr(tnLogs, 50, 2, 0xBB, ts(2026, 2, 1)))
	mustRecord(t, j, hdr(tnLogs, 100, 3, 0xCC, ts(2026, 3, 1)))

	cases := []struct {
		asOf uint64
		want uint64
		ok   bool
	}{
		{9, 0, false},    // before first
		{10, 10, true},   // exact match on first
		{25, 10, true},   // between first and second
		{50, 50, true},   // exact match on second
		{99, 50, true},   // between second and third
		{100, 100, true}, // exact match on latest
		{500, 100, true}, // after last → returns last
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("asOf=%d", c.asOf), func(t *testing.T) {
			h, err := j.HeadAt(ctx, tnLogs, c.asOf)
			if c.ok {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if h.TreeSize != c.want {
					t.Errorf("TreeSize = %d, want %d", h.TreeSize, c.want)
				}
			} else if !errors.Is(err, ErrNoHead) {
				t.Errorf("err = %v, want ErrNoHead", err)
			}
		})
	}
}

// TestHeadsJournal_HeadAtTime_Ordering pins "at or before" on
// CommittedAt — symmetric to HeadAt but keyed by wall-clock time.
func TestHeadsJournal_HeadAtTime_Ordering(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	mustRecord(t, j, hdr(tnLogs, 10, 1, 0xAA, ts(2026, 6, 15)))
	mustRecord(t, j, hdr(tnLogs, 20, 2, 0xBB, ts(2027, 6, 15)))
	mustRecord(t, j, hdr(tnLogs, 30, 3, 0xCC, ts(2028, 6, 15)))

	cases := []struct {
		when time.Time
		want uint64
		ok   bool
	}{
		{ts(2026, 1, 1), 0, false},  // before any head
		{ts(2026, 6, 15), 10, true}, // exact match on first
		{ts(2026, 12, 1), 10, true}, // between first and second
		{ts(2028, 12, 1), 30, true}, // after latest → latest
	}
	for _, c := range cases {
		t.Run(c.when.Format("2006-01-02"), func(t *testing.T) {
			h, err := j.HeadAtTime(ctx, tnLogs, c.when)
			if c.ok {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if h.TreeSize != c.want {
					t.Errorf("TreeSize = %d, want %d", h.TreeSize, c.want)
				}
			} else if !errors.Is(err, ErrNoHead) {
				t.Errorf("err = %v, want ErrNoHead", err)
			}
		})
	}
}

// TestHeadsJournal_LatestHead_AfterAdvance pins LatestHead tracking
// across multiple advances.
func TestHeadsJournal_LatestHead_AfterAdvance(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	mustRecord(t, j, hdr(tnLogs, 5, 1, 0x01, ts(2026, 1, 1)))
	mustRecord(t, j, hdr(tnLogs, 12, 2, 0x02, ts(2026, 2, 1)))
	mustRecord(t, j, hdr(tnLogs, 100, 3, 0x03, ts(2026, 3, 1)))

	h, err := j.LatestHead(ctx, tnLogs)
	if err != nil {
		t.Fatalf("LatestHead: %v", err)
	}
	if h.TreeSize != 100 {
		t.Errorf("LatestHead.TreeSize = %d, want 100", h.TreeSize)
	}
}

// TestHeadsJournal_LatestHead_NoEntries pins the empty-log case.
func TestHeadsJournal_LatestHead_NoEntries(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	_, err := j.LatestHead(context.Background(), tnLogs)
	if !errors.Is(err, ErrNoHead) {
		t.Errorf("err = %v, want ErrNoHead", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// SCENARIO 1 — Multi-log isolation
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_MultiLog_Isolation implements scenario 1 (cross-
// network proof resolution): the journal must hold heads for
// multiple LogDIDs without cross-contamination. A TN equivocation
// must NOT burn the federal log; a federal head must NOT shadow a
// TN head at the same sequence.
func TestHeadsJournal_MultiLog_Isolation(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	mustRecord(t, j, hdr(tnLogs, 100, 1, 0x01, ts(2026, 1, 1)))
	mustRecord(t, j, hdr(federal, 100, 1, 0x99, ts(2026, 1, 1)))
	mustRecord(t, j, hdr(gaLogs, 100, 1, 0xCC, ts(2026, 1, 1)))

	// Burn the federal log.
	mustRecord(t, j, hdr(federal, 100, 2, 0xAA, ts(2026, 1, 1)))

	// TN and GA must still respond cleanly.
	for _, did := range []string{tnLogs, gaLogs} {
		if _, err := j.LatestHead(ctx, did); err != nil {
			t.Errorf("%s LatestHead errored after federal burn: %v (cross-log contamination)", did, err)
		}
	}
	// Federal must be burned.
	if _, err := j.LatestHead(ctx, federal); !errors.Is(err, ErrEquivocatedLog) {
		t.Errorf("federal LatestHead should be burned; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// SCENARIO 2 — Year-15 historical verification
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_Year15_HistoricalVerification implements scenario
// 2: a year-1 head + its ORIGINAL W1 witness set must remain
// retrievable byte-for-byte after 15 years of rotation. The
// signature set the verifier reads from the journal must be the
// W1 set, not whatever current rotation has produced.
func TestHeadsJournal_Year15_HistoricalVerification(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	// W1 witness set published a sealing order in May 2026.
	yearOne := hdr(tnLogs, 50_000, 50_000, 0x01, ts(2026, 5, 12))
	yearOne.Signatures = []types.WitnessSignature{
		{PubKeyID: [32]byte{0xA1, 0x1c, 0xe}, SchemeTag: 0x01, SigBytes: []byte("W1-Alice-sig")},
		{PubKeyID: [32]byte{0xB0, 0xB}, SchemeTag: 0x01, SigBytes: []byte("W1-Bob-sig")},
		{PubKeyID: [32]byte{0xCa, 0x40, 0x1}, SchemeTag: 0x01, SigBytes: []byte("W1-Carol-sig")},
	}
	yearOne.CanonicalBytes = []byte("wire:year-1-2026-sealing-order")
	mustRecord(t, j, yearOne)

	// 15 years of rotation: W2 (year-5), W3 (year-10), W4 (year-15).
	w2 := hdr(tnLogs, 5_000_000, 5_000_000, 0x02, ts(2031, 1, 1))
	w2.Signatures = []types.WitnessSignature{
		{PubKeyID: [32]byte{0xD0}, SchemeTag: 0x01, SigBytes: []byte("W2-Dan")},
		{PubKeyID: [32]byte{0xE1}, SchemeTag: 0x01, SigBytes: []byte("W2-Eve")},
		{PubKeyID: [32]byte{0xF2}, SchemeTag: 0x01, SigBytes: []byte("W2-Frank")},
	}
	mustRecord(t, j, w2)

	w4 := hdr(tnLogs, 80_000_000, 80_000_000, 0x04, ts(2041, 5, 12))
	w4.Signatures = []types.WitnessSignature{
		{PubKeyID: [32]byte{0xC1}, SchemeTag: 0x01, SigBytes: []byte("W4-Chen")},
		{PubKeyID: [32]byte{0xC2}, SchemeTag: 0x01, SigBytes: []byte("W4-Singh")},
		{PubKeyID: [32]byte{0xC3}, SchemeTag: 0x01, SigBytes: []byte("W4-Patel")},
	}
	mustRecord(t, j, w4)

	// 2041: defense attorney queries HeadAt(50_000) — asks the
	// journal for the head that was authoritative for the year-1
	// sealing order.
	got, err := j.HeadAt(ctx, tnLogs, 50_000)
	if err != nil {
		t.Fatalf("year-15 HeadAt(year-1-sequence): %v", err)
	}

	// The retrieved head's signatures MUST be the W1 set, not W4.
	if len(got.Signatures) != 3 {
		t.Fatalf("len(Signatures) = %d, want 3 (the W1 set)", len(got.Signatures))
	}
	expectedW1 := []string{"W1-Alice-sig", "W1-Bob-sig", "W1-Carol-sig"}
	for i, want := range expectedW1 {
		if string(got.Signatures[i].SigBytes) != want {
			t.Errorf("Signatures[%d] = %q, want %q (year-15 reading year-1 must see ORIGINAL witness set)",
				i, got.Signatures[i].SigBytes, want)
		}
	}
	// And CanonicalBytes preserves byte-for-byte (scenario 11).
	if string(got.CanonicalBytes) != "wire:year-1-2026-sealing-order" {
		t.Errorf("CanonicalBytes drift on year-15 retrieval: got %q", got.CanonicalBytes)
	}
}

// ─────────────────────────────────────────────────────────────────────
// SCENARIO 3 — Deterministic temporal verdicts
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_DeterministicTemporal implements scenario 3: two
// queries at different wall-clock instants (μs apart, crossing an
// activation boundary) MUST resolve to the SAME head when pinned to
// the same asOf sequence — even if the local clocks disagree.
//
// The journal's contract is: HeadAt(LogDID, asOf) is a pure function
// of the recorded state, independent of when the call happens. This
// test pins that purity.
func TestHeadsJournal_DeterministicTemporal(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	// Record three heads.
	mustRecord(t, j, hdr(tnLogs, 10, 1, 0x01, ts(2026, 1, 1)))
	mustRecord(t, j, hdr(tnLogs, 20, 2, 0x02, ts(2026, 2, 1)))
	mustRecord(t, j, hdr(tnLogs, 30, 3, 0x03, ts(2026, 3, 1)))

	const asOf = 25
	want, err := j.HeadAt(ctx, tnLogs, asOf)
	if err != nil {
		t.Fatalf("first HeadAt: %v", err)
	}
	for i := 0; i < 100; i++ {
		got, err := j.HeadAt(ctx, tnLogs, asOf)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if got.RootHash != want.RootHash || got.TreeSize != want.TreeSize {
			t.Errorf("iter %d: drift in HeadAt(%d): got %x size %d, want %x size %d",
				i, asOf, got.RootHash, got.TreeSize, want.RootHash, want.TreeSize)
		}
		// Time advances between calls (real clock); verdict does not.
		time.Sleep(time.Microsecond)
	}
}

// ─────────────────────────────────────────────────────────────────────
// SCENARIO 7 — Scale tolerance
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_Scale_BoundedTime asserts that HeadAt at journal
// sizes representative of multi-year operation does not regress to
// quadratic / unbounded behavior. The memory implementation walks
// recorded sequences for a log; the test verifies the walk
// completes within a generous bound.
//
// This test is NOT a benchmark; it pins that the time complexity
// remains in the "small constant × N entries for the log" range so
// CI does not regress. For real production scale (250M rows), the
// PostgresHeadsJournal supersedes this implementation.
func TestHeadsJournal_Scale_BoundedTime(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("scale test elided in -short mode")
	}
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	const heads = 10_000
	base := ts(2026, 1, 1)
	for i := uint64(1); i <= heads; i++ {
		mustRecord(t, j, hdr(tnLogs, i, i, byte(i&0xFF), base.Add(time.Duration(i)*time.Second)))
	}

	start := time.Now()
	for i := 0; i < 100; i++ {
		_, err := j.HeadAt(ctx, tnLogs, heads/2)
		if err != nil {
			t.Fatalf("HeadAt under load: %v", err)
		}
	}
	elapsed := time.Since(start)
	// 100 lookups × O(heads-for-log) on a 10k-head log should
	// complete in well under a second on every reasonable runner.
	if elapsed > 5*time.Second {
		t.Errorf("100 HeadAt calls on a %d-head log took %v; complexity regression?",
			heads, elapsed)
	}
}

// ─────────────────────────────────────────────────────────────────────
// SCENARIO 11 — Wire-format preservation
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_WireFormatPreserved implements scenario 11 (Goal
// 11 bundle wire-format freeze): CanonicalBytes survive Record →
// Read byte-for-byte. A year-12 binary reading year-1 bytes will
// not see a JSON re-encoding, key reorder, whitespace change, or
// any other "helpful" mutation.
func TestHeadsJournal_WireFormatPreserved(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	h := hdr(tnLogs, 100, 1, 0x01, ts(2026, 5, 12))
	// Deliberately non-JSON, non-UTF-8 bytes — pure binary wire.
	h.CanonicalBytes = []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02}
	mustRecord(t, j, h)

	got, err := j.HeadByRootHash(ctx, tnLogs, h.TreeSize, h.RootHash)
	if err != nil {
		t.Fatalf("retrieval: %v", err)
	}
	if len(got.CanonicalBytes) != len(h.CanonicalBytes) {
		t.Fatalf("length drift: got %d, want %d", len(got.CanonicalBytes), len(h.CanonicalBytes))
	}
	for i := range h.CanonicalBytes {
		if got.CanonicalBytes[i] != h.CanonicalBytes[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x (wire format MUST be preserved verbatim)",
				i, got.CanonicalBytes[i], h.CanonicalBytes[i])
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Concurrency
// ─────────────────────────────────────────────────────────────────────

// TestHeadsJournal_Concurrent_RecordSafe pins that concurrent
// Record calls from N goroutines do not corrupt the journal. Each
// goroutine records its own (LogDID, Sequence) range; LatestHead
// after the wave reflects the highest sequence each log received.
func TestHeadsJournal_Concurrent_RecordSafe(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	ctx := context.Background()

	const workers = 8
	const perWorker = 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			logDID := fmt.Sprintf("did:web:log-%d.example", workerID)
			for i := uint64(1); i <= perWorker; i++ {
				h := hdr(logDID, i, i, byte(workerID), ts(2026, 1, 1).Add(time.Duration(i)*time.Second))
				if _, err := j.Record(ctx, h); err != nil {
					t.Errorf("worker %d Record(%d): %v", workerID, i, err)
				}
			}
		}(w)
	}
	wg.Wait()

	for w := 0; w < workers; w++ {
		logDID := fmt.Sprintf("did:web:log-%d.example", w)
		h, err := j.LatestHead(ctx, logDID)
		if err != nil {
			t.Errorf("LatestHead(%s): %v", logDID, err)
			continue
		}
		if h.TreeSize != perWorker {
			t.Errorf("LatestHead(%s).TreeSize = %d, want %d", logDID, h.TreeSize, perWorker)
		}
	}
}

// TestHeadsJournal_ContextCancellation pins that all read & write
// operations honor ctx.Err — a caller's deadline / cancellation
// surfaces immediately instead of silently completing.
func TestHeadsJournal_ContextCancellation(t *testing.T) {
	t.Parallel()
	j := NewMemoryHeadsJournal()
	mustRecord(t, j, hdr(tnLogs, 1, 1, 0x01, ts(2026, 1, 1)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, name := range []string{"Record", "HeadAt", "HeadAtTime", "HeadByRootHash", "HeadsAtSequence", "LatestHead", "BurnStatus"} {
		t.Run(name, func(t *testing.T) {
			var err error
			switch name {
			case "Record":
				_, err = j.Record(ctx, hdr(tnLogs, 2, 2, 0x02, ts(2026, 1, 1)))
			case "HeadAt":
				_, err = j.HeadAt(ctx, tnLogs, 1)
			case "HeadAtTime":
				_, err = j.HeadAtTime(ctx, tnLogs, ts(2026, 1, 1))
			case "HeadByRootHash":
				_, err = j.HeadByRootHash(ctx, tnLogs, 1, [32]byte{0x01})
			case "HeadsAtSequence":
				_, err = j.HeadsAtSequence(ctx, tnLogs, 1)
			case "LatestHead":
				_, err = j.LatestHead(ctx, tnLogs)
			case "BurnStatus":
				_, err = j.BurnStatus(ctx, tnLogs)
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%s should surface context.Canceled; got %v", name, err)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func mustRecord(t *testing.T, j HeadsJournal, h Head) RecordVerdict {
	t.Helper()
	v, err := j.Record(context.Background(), h)
	if err != nil {
		t.Fatalf("Record(%s, %d, %x): %v", h.LogDID, h.TreeSize, h.RootHash, err)
	}
	return v
}
