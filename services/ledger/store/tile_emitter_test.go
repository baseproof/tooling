package store

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// Builds a real SMT in the SDK's in-memory stores, emits its tiles, and proves
// a membership proof RESOLVES against only the emitted tiles — the core
// integrity guarantee (published ⇒ tiles present ⇒ proof resolves). Then checks
// idempotent re-emit (Exists prunes) and the empty-root no-op.
func TestBuildTilesEmitter_EmitsResolvableTilesThenPrunes(t *testing.T) {
	ctx := context.Background()
	nodes := smt.NewInMemoryNodeStore()
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), nodes)

	for i := byte(1); i <= 8; i++ {
		var key [32]byte
		key[0], key[31] = i, i
		leaf := types.SMTLeaf{
			Key:          key,
			OriginTip:    types.LogPosition{LogDID: "did:test", Sequence: uint64(i)},
			AuthorityTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i)},
		}
		if err := tree.SetLeaf(ctx, key, leaf); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, err)
		}
	}
	root, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if root == smt.EmptyHash {
		t.Fatal("root empty after inserts")
	}

	tiles := NewMemSMTTileStore()
	em := NewBuildTilesEmitter(nodes, tiles)

	if err := em.EmitDurable(ctx, smt.EmptyHash, root, 8); err != nil {
		t.Fatalf("EmitDurable: %v", err)
	}
	emitted := tiles.Len()
	if emitted == 0 {
		t.Fatal("no tiles emitted for a non-empty root")
	}

	// THE integrity check: a proof at root, served ONLY from the emitted tiles,
	// must resolve — i.e. the emitted set is complete for root.
	ts := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1024))
	var key1 [32]byte
	key1[0], key1[31] = 1, 1
	proof, perr := smt.GenerateProofAt(ts, root, key1)
	if perr != nil {
		t.Fatalf("proof against emitted tiles did not resolve: %v", perr)
	}
	if proof.TerminalKind != types.SMTTerminalLeaf || proof.TerminalLeaf == nil || proof.TerminalLeaf.Key != key1 {
		t.Fatalf("expected a membership proof for key1, got terminal kind %d", proof.TerminalKind)
	}

	// Idempotent re-emit: Exists prunes the whole set, no new tiles.
	if err := em.EmitDurable(ctx, smt.EmptyHash, root, 8); err != nil {
		t.Fatalf("second EmitDurable: %v", err)
	}
	if tiles.Len() != emitted {
		t.Fatalf("re-emit changed tile count %d → %d (Exists did not prune)", emitted, tiles.Len())
	}

	// Empty root → no-op.
	empty := NewMemSMTTileStore()
	if err := NewBuildTilesEmitter(nodes, empty).EmitDurable(ctx, smt.EmptyHash, smt.EmptyHash, 0); err != nil {
		t.Fatalf("EmitDurable(empty): %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("empty-root emit wrote %d tiles, want 0", empty.Len())
	}
}
