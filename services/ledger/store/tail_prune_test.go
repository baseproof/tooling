package store

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// Regression guard for the unbounded in-memory SMT node tail — the writer OOM
// (anon-rss ~5.6 GiB, ~23 KB of live heap per committed entry) caused by the tail
// never being pruned. The tail is bounded ONLY because, after a checkpoint makes a
// root's tiles durable, the reconciler evicts exactly the nodes EmitDurable reports
// durable. These tests pin:
//
//	(+) EmitDurable returns precisely the node set its tiles made durable;
//	(+) evicting that set bounds the tail while every node stays servable;
//	(−) a node NOT made durable is never evicted (fail-closed retention).
//
// (key3band lives in tile_emitter_test.go; leaf in tailed_node_store_test.go.)

// fillTree inserts n leaves (≥3 tile bands deep via key3band) and returns the root.
func fillTree(t *testing.T, ctx context.Context, tree *smt.Tree, n int) [32]byte {
	t.Helper()
	for i := 0; i < n; i++ {
		k := key3band(i)
		if err := tree.SetLeaf(ctx, k, types.SMTLeaf{
			Key:       k,
			OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i + 1)},
		}); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, err)
		}
	}
	root, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	return root
}

// (+) EmitDurable returns exactly the distinct nodes across the tiles it made durable
// (the prune signal), and an empty set for the empty root. If this returned nothing,
// the loop would evict nothing and the tail would grow unbounded.
func TestEmitDurable_ReturnsDurableNodeSet(t *testing.T) {
	ctx := context.Background()
	tiles := NewMemSMTTileStore()
	nodes := smt.NewInMemoryNodeStore()
	root := fillTree(t, ctx, smt.NewTree(smt.NewInMemoryLeafStore(), nodes), 16)

	durable, err := NewBuildTilesEmitter(nodes, tiles).EmitDurable(ctx, smt.EmptyHash, root, 16)
	if err != nil {
		t.Fatalf("EmitDurable: %v", err)
	}
	if len(durable) == 0 {
		t.Fatal("EmitDurable returned no durable nodes for a non-empty root — the tail would never be pruned (OOM regression)")
	}

	// It must equal exactly the distinct nodes across the emitted tiles — complete
	// (prune everything now durable) and tight (never claim a node is durable when it
	// is not, which would let an undurable node be evicted).
	oracle, err := smt.BuildTiles(nodes, root, smt.TileHeight)
	if err != nil {
		t.Fatalf("oracle BuildTiles: %v", err)
	}
	want := map[[32]byte]struct{}{}
	for _, tile := range oracle {
		for i := range tile.Nodes {
			want[smt.HashNode(tile.Nodes[i])] = struct{}{}
		}
	}
	if len(durable) != len(want) {
		t.Fatalf("durable set size %d != emitted tiles' node set %d", len(durable), len(want))
	}
	for h := range want {
		if _, ok := durable[h]; !ok {
			t.Fatalf("durable set missing node %x that is in the emitted tiles", h[:6])
		}
	}

	empty, err := NewBuildTilesEmitter(nodes, NewMemSMTTileStore()).EmitDurable(ctx, smt.EmptyHash, smt.EmptyHash, 0)
	if err != nil {
		t.Fatalf("EmitDurable(empty): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty root returned %d durable nodes, want 0", len(empty))
	}
}

// (+/−) The reconciler's Step 5a end to end: emit a root, then evict exactly the
// returned durable set. The tail is BOUNDED (the durable nodes leave it), every node
// stays SERVABLE (now from the durable tiles), and an un-tiled node is RETAINED — the
// fail-closed retention invariant. Reverting the prune (the original bug) makes the
// bounding assertion fail.
//
// Note: per-leaf inserts orphan some intermediate branch nodes (superseded by a later
// leaf, never reachable from the final root, hence never tiled). Those are not durable,
// so they are correctly RETAINED here; on a real restart RecoverTail rebuilds the tail
// gap-only and they vanish. So we assert bounding (< before), not an exact residual.
func TestEmitThenPrune_BoundsTailKeepsServable(t *testing.T) {
	ctx := context.Background()
	tiles := NewMemSMTTileStore()
	tailed := NewTailedNodeStore(smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16)))
	root := fillTree(t, ctx, smt.NewTree(smt.NewInMemoryLeafStore(), tailed), 32)

	tailBefore := tailed.TailLen()
	if tailBefore == 0 {
		t.Fatal("precondition: tail empty after inserts")
	}

	// An orphan node EmitDurable(root) will NOT cover (never inserted into the tree).
	orphanHash, _ := tailed.Put(leaf(200))

	durable, err := NewBuildTilesEmitter(tailed, tiles).EmitDurable(ctx, smt.EmptyHash, root, 32)
	if err != nil {
		t.Fatalf("EmitDurable: %v", err)
	}
	if _, ok := durable[orphanHash]; ok {
		t.Fatal("orphan (un-tiled) must NOT be reported durable")
	}

	// Step 5a: evict exactly the durable set (membership oracle = fail-closed).
	tailed.PruneTiled(ctx, func(_ context.Context, h [32]byte) (bool, error) {
		_, ok := durable[h]
		return ok, nil
	})

	// (+) BOUNDED: the durable tree nodes left the tail.
	if got := tailed.TailLen(); got >= tailBefore {
		t.Fatalf("prune did not bound the tail: %d → %d (the unbounded-tail OOM regression)", tailBefore, got)
	}
	// (−) the un-tiled orphan is RETAINED (never evict an undurable node) and servable.
	if n, _ := tailed.Get(orphanHash); n == nil {
		t.Fatal("RETENTION VIOLATED: un-tiled orphan evicted (data loss / GC window)")
	}
	// (+) every tree node remains servable — a proof resolves from the durable tiles
	// alone (a fresh TiledNodeStore, no tail), proving the evicted nodes are durable.
	fresh := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16))
	for _, i := range []int{0, 15, 31} {
		k := key3band(i)
		if _, perr := smt.GenerateProofAt(fresh, root, k); perr != nil {
			t.Fatalf("proof key#%d unservable from durable tiles after prune: %v", i, perr)
		}
	}
}
