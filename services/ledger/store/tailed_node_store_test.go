package store

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

func leaf(b byte) *smt.LeafNode {
	var k [32]byte
	k[0], k[31] = b, b
	return &smt.LeafNode{Value: types.SMTLeaf{
		Key:          k,
		OriginTip:    types.LogPosition{LogDID: "did:test", Sequence: uint64(b)},
		AuthorityTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(b)},
	}}
}

func TestTailedNodeStore_TailThenTilesReadThroughAndPrune(t *testing.T) {
	ctx := context.Background()
	durable := smt.NewInMemoryNodeStore() // stands in for durable tiles
	tn := NewTailedNodeStore(durable)

	// (1) A node Put into the tail is readable from the tail.
	n1 := leaf(1)
	h1, _ := tn.Put(n1)
	if got, _ := tn.Get(h1); got == nil {
		t.Fatal("Get(tail node) returned nil")
	}
	if tn.TailLen() != 1 {
		t.Fatalf("TailLen = %d, want 1", tn.TailLen())
	}

	// (2) A node only in the durable tiles is read through.
	n2 := leaf(2)
	h2, _ := durable.Put(n2)
	if got, _ := tn.Get(h2); got == nil {
		t.Fatal("Get did not read through to durable tiles")
	}

	// (3) EmptyHash → (nil, nil).
	if got, err := tn.Get(smt.EmptyHash); got != nil || err != nil {
		t.Fatalf("Get(EmptyHash) = (%v,%v), want (nil,nil)", got, err)
	}

	// (4) PruneTiled evicts tail nodes now present in tiles. Model the reconciler
	// having tiled n1: copy it to durable, then prune.
	_, _ = durable.Put(n1)
	tn.PruneTiled(ctx, func(_ context.Context, id [32]byte) (bool, error) { return id == h1, nil })
	if tn.TailLen() != 0 {
		t.Fatalf("TailLen after prune = %d, want 0", tn.TailLen())
	}
	// Still readable — now from the durable tiles, not the tail.
	if got, _ := tn.Get(h1); got == nil {
		t.Fatal("Get(pruned node) nil; should read through to durable tiles")
	}
}

// TestTailedNodeStore_TailSnapshot: Tail() returns the dirty set as an INDEPENDENT
// copy (mutating it never touches the store) and tracks Put/PruneTiled — so the
// reconciler can hand it to BuildDirtyTiles while the builder keeps writing.
func TestTailedNodeStore_TailSnapshot(t *testing.T) {
	ctx := context.Background()
	tn := NewTailedNodeStore(smt.NewInMemoryNodeStore())
	h1, _ := tn.Put(leaf(1))
	h2, _ := tn.Put(leaf(2))

	snap := tn.Tail()
	if len(snap) != 2 {
		t.Fatalf("Tail() len = %d, want 2", len(snap))
	}
	if _, ok := snap[h1]; !ok {
		t.Fatal("Tail() missing h1")
	}
	if _, ok := snap[h2]; !ok {
		t.Fatal("Tail() missing h2")
	}

	// COPY: deleting from the snapshot must not evict from the store.
	delete(snap, h1)
	if tn.TailLen() != 2 {
		t.Fatalf("store TailLen = %d after snapshot mutation, want 2 — Tail() is not a copy", tn.TailLen())
	}
	if got, _ := tn.Get(h1); got == nil {
		t.Fatal("h1 evicted from the store by mutating the snapshot")
	}

	// Tail() shrinks as nodes become durable (the dirty set the next emit recurses).
	_, _ = tn.Put(leaf(1)) // ensure h1 is durable-checkable; prune evicts it
	tn.PruneTiled(ctx, func(_ context.Context, id [32]byte) (bool, error) { return id == h1, nil })
	if got := tn.Tail(); len(got) != 1 {
		t.Fatalf("Tail() after prune = %d, want 1", len(got))
	}
}
