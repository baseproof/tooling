package store

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// Recovery from leaves alone: build a committed root in one tree, then rebuild
// the node tail in a FRESH TailedNodeStore (empty tail + empty tiles) by
// replaying just the leaf set. The rebuilt root must match, and a membership
// proof must resolve against the recovered tail — i.e. the un-tiled gap is fully
// reconstructed from smt_leaves (root = f(leaves)).
func TestRecoverTail_RebuildsFromLeavesAndProofResolves(t *testing.T) {
	ctx := context.Background()

	// Authoritative tree → committed root + the leaf set.
	src := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	leaves := make([]types.SMTLeaf, 0, 12)
	for i := byte(1); i <= 12; i++ {
		var k [32]byte
		k[0], k[31] = i, 0xff-i
		leaf := types.SMTLeaf{Key: k, OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i)}, AuthorityTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i)}}
		if err := src.SetLeaf(ctx, k, leaf); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, err)
		}
		leaves = append(leaves, leaf)
	}
	committed, err := src.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}

	// Fresh substrate: empty tail, empty durable tiles (nothing pre-tiled).
	tailed := NewTailedNodeStore(smt.NewInMemoryNodeStore())
	if err := RecoverTail(ctx, leaves, tailed, committed); err != nil {
		t.Fatalf("RecoverTail: %v", err)
	}
	if tailed.TailLen() == 0 {
		t.Fatal("recovery wrote no nodes into the tail")
	}

	// A proof at the committed root resolves against the recovered substrate.
	var k1 [32]byte
	k1[0], k1[31] = 1, 0xff-1
	proof, perr := smt.GenerateProofAt(tailed, committed, k1)
	if perr != nil {
		t.Fatalf("proof against recovered tail did not resolve: %v", perr)
	}
	if proof.TerminalKind != types.SMTTerminalLeaf || proof.TerminalLeaf == nil || proof.TerminalLeaf.Key != k1 {
		t.Fatalf("expected membership for k1, got terminal kind %d", proof.TerminalKind)
	}

	// Wrong committed root → integrity error (leaf set inconsistent).
	var bogus [32]byte
	bogus[0] = 0x9e
	if err := RecoverTail(ctx, leaves, NewTailedNodeStore(smt.NewInMemoryNodeStore()), bogus); err == nil {
		t.Fatal("expected error when rebuilt root != committed root")
	}

	// Empty tree → no-op.
	if err := RecoverTail(ctx, nil, tailed, smt.EmptyHash); err != nil {
		t.Fatalf("RecoverTail(empty): %v", err)
	}
}
