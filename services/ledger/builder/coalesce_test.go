package builder

import (
	"testing"

	"github.com/baseproof/baseproof/types"
)

// TestCoalesceLeafMutations_LastWritePerKey pins the SQLSTATE-21000 fix: a builder
// batch whose ordered mutation log writes the same leaf_key more than once (a root
// then same-batch amendments of it) must collapse to ONE leaf per key, carrying the
// LAST write — so the single ON CONFLICT (leaf_key) upsert never sees a duplicate
// conflict key, and the persisted state matches the committed root.
func TestCoalesceLeafMutations_LastWritePerKey(t *testing.T) {
	kA := [32]byte{0xAA}
	kB := [32]byte{0xBB}
	pos := func(s uint64) types.LogPosition { return types.LogPosition{LogDID: "did:web:x", Sequence: s} }

	// Application order: create A, create B, amend A (origin→3), amend A again (origin→5).
	muts := []types.LeafMutation{
		{LeafKey: kA, NewOriginTip: pos(1), NewAuthorityTip: pos(1)},
		{LeafKey: kB, NewOriginTip: pos(2), NewAuthorityTip: pos(2)},
		{LeafKey: kA, NewOriginTip: pos(3), NewAuthorityTip: pos(1)},
		{LeafKey: kA, NewOriginTip: pos(5), NewAuthorityTip: pos(1)},
	}

	got := coalesceLeafMutations(muts)

	if len(got) != 2 {
		t.Fatalf("want 2 unique leaves, got %d", len(got))
	}
	seen := make(map[[32]byte]types.SMTLeaf, len(got))
	for _, l := range got {
		if _, dup := seen[l.Key]; dup {
			t.Fatalf("duplicate leaf_key %x in coalesced output — would break ON CONFLICT", l.Key[:4])
		}
		seen[l.Key] = l
	}
	if seen[kA].OriginTip.Sequence != 5 {
		t.Fatalf("A origin tip = %d, want 5 (the LAST write)", seen[kA].OriginTip.Sequence)
	}
	if seen[kA].AuthorityTip.Sequence != 1 {
		t.Fatalf("A authority tip = %d, want 1 (Path A keeps authority at creation)", seen[kA].AuthorityTip.Sequence)
	}
	if seen[kB].OriginTip.Sequence != 2 {
		t.Fatalf("B origin tip = %d, want 2", seen[kB].OriginTip.Sequence)
	}
}

// TestCoalesceLeafMutations_NoDuplicates is the common case — distinct keys pass
// through 1:1, order-preserved.
func TestCoalesceLeafMutations_NoDuplicates(t *testing.T) {
	pos := func(s uint64) types.LogPosition { return types.LogPosition{LogDID: "did:web:x", Sequence: s} }
	muts := make([]types.LeafMutation, 0, 100)
	for i := uint64(0); i < 100; i++ {
		var k [32]byte
		k[0], k[1], k[2], k[3] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		muts = append(muts, types.LeafMutation{LeafKey: k, NewOriginTip: pos(i), NewAuthorityTip: pos(i)})
	}
	got := coalesceLeafMutations(muts)
	if len(got) != 100 {
		t.Fatalf("want 100 leaves (all distinct), got %d", len(got))
	}
	for i, l := range got {
		if l.OriginTip.Sequence != uint64(i) {
			t.Fatalf("leaf %d origin tip = %d, want %d (order preserved)", i, l.OriginTip.Sequence, i)
		}
	}
}

// TestCoalesceLeafMutations_Empty — an all-commentary batch produces no mutations.
func TestCoalesceLeafMutations_Empty(t *testing.T) {
	if got := coalesceLeafMutations(nil); len(got) != 0 {
		t.Fatalf("want 0 leaves for an empty mutation log, got %d", len(got))
	}
}
