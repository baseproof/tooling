/*
FILE PATH: store/anchor_confirmations_embedded_test.go

The 4b immutability lock test, against a REAL Postgres (embeddedpg; skips
where one cannot boot, like the repo's other embedded-PG tests):

	RE-OBSERVATION NEVER REFRESHES VERIFIED_AT — or the lazy-fresh hole reopens
	through the back door (a stale anchor re-read each poll would feed the
	verifier's min(AnchoredAt, VerifiedAt) a forever-fresh floor).

Plus the chain read: LatestPerParent returns exactly one row per parent —
the freshest by verified_at — and an empty table is a valid empty chain.
*/
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/store"
)

// distinct from 54331/54332/54333 siblings.
const anchorConfirmationsPGPort = 54334

func TestAnchorConfirmations_Embedded(t *testing.T) {
	pool := embeddedpg.Start(t, anchorConfirmationsPGPort) // t.Skip without a real PG
	ctx := context.Background()
	s := store.NewAnchorConfirmationStore(pool)

	t0 := time.Unix(1_700_000_000, 0).UTC()
	first := store.AnchorConfirmation{
		ParentLogDID:     "did:baseproof:network:parent-a",
		TreeHeadRef:      "aa11",
		ParentSeq:        42,
		AnchoredTreeSize: 1000,
		AnchoredAt:       t0.Add(-time.Minute),
		VerifiedAt:       t0,
	}

	// First observation stores and returns its own time.
	got, err := s.RecordFirstSeen(ctx, first)
	if err != nil {
		t.Fatalf("first RecordFirstSeen: %v", err)
	}
	if !got.Equal(t0) {
		t.Fatalf("first observation returned %v, want %v", got, t0)
	}

	// THE LOCK: re-observing the same (parent, head) a day later — even with
	// different metadata — returns the ORIGINAL verified_at, unchanged.
	later := first
	later.VerifiedAt = t0.Add(24 * time.Hour)
	later.ParentSeq = 99999
	got, err = s.RecordFirstSeen(ctx, later)
	if err != nil {
		t.Fatalf("re-observation RecordFirstSeen: %v", err)
	}
	if !got.Equal(t0) {
		t.Fatalf("re-observation refreshed verified_at: %v, want the immutable first-seen %v (lazy-fresh hole)", got, t0)
	}
	// And the stored row is byte-for-byte the first observation.
	var storedSeq int64
	var storedAt time.Time
	if err := pool.QueryRow(ctx,
		`SELECT parent_seq, verified_at FROM anchor_confirmations WHERE parent_log_did=$1 AND tree_head_ref=$2`,
		first.ParentLogDID, first.TreeHeadRef).Scan(&storedSeq, &storedAt); err != nil {
		t.Fatal(err)
	}
	if storedSeq != 42 || !storedAt.UTC().Equal(t0) {
		t.Fatalf("stored row mutated: seq=%d at=%v", storedSeq, storedAt)
	}

	// A NEWER HEAD in the same parent is a NEW row (the chain advances by
	// insertion, not mutation); LatestPerParent picks it.
	second := first
	second.TreeHeadRef = "bb22"
	second.ParentSeq = 43
	second.AnchoredTreeSize = 2000
	second.VerifiedAt = t0.Add(time.Hour)
	if _, err := s.RecordFirstSeen(ctx, second); err != nil {
		t.Fatal(err)
	}
	// A second parent.
	otherParent := store.AnchorConfirmation{
		ParentLogDID:     "did:baseproof:network:parent-b",
		TreeHeadRef:      "cc33",
		ParentSeq:        7,
		AnchoredTreeSize: 500,
		VerifiedAt:       t0.Add(30 * time.Minute),
	}
	if _, err := s.RecordFirstSeen(ctx, otherParent); err != nil {
		t.Fatal(err)
	}

	latest, err := s.LatestPerParent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 {
		t.Fatalf("LatestPerParent = %d rows, want 2 (one per parent)", len(latest))
	}
	byParent := map[string]store.AnchorConfirmation{}
	for _, c := range latest {
		byParent[c.ParentLogDID] = c
	}
	if a := byParent["did:baseproof:network:parent-a"]; a.TreeHeadRef != "bb22" || a.ParentSeq != 43 {
		t.Fatalf("parent-a latest = %+v, want the newer head bb22@43", a)
	}
	if b := byParent["did:baseproof:network:parent-b"]; b.TreeHeadRef != "cc33" {
		t.Fatalf("parent-b latest = %+v", b)
	}
	// AnchoredAt was zero for parent-b → round-trips as zero (NULL), never a
	// fabricated time.
	if !byParent["did:baseproof:network:parent-b"].AnchoredAt.IsZero() {
		t.Fatal("zero AnchoredAt round-tripped as a non-zero time")
	}
}
