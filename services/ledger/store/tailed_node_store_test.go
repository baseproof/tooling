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
