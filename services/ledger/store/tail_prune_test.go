package store

import (
	"context"
	"crypto/sha256"
	"errors"
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

// TestProof_ResidualIsOrphanGarbage_EmitterComplete is the SAFETY PROOF that the tail
// residual left by the durable-set prune is 100% orphaned intra-batch garbage — NOT a
// live node the tile emitter silently dropped. It is the precondition for any fix that
// DISCARDS the residual: if even one live node were stuck in the tail, discarding it
// would be data loss. Two independent assertions, from a full graph traversal:
//
//	(a) residual ∩ live = ∅  — no node reachable from the final committed root is stuck
//	    in the tail (the emitter did not drop a live node into a permanent tail trap);
//	(b) emitter COMPLETE — the entire live tree reconstructs from the TILE STORE ALONE
//	    (a fresh TiledNodeStore, no tail), and that tiles-only node set EQUALS the live
//	    set. If the emitter had dropped a live node, this reconstruction would fault
//	    ("missing node") or come up short.
func TestProof_ResidualIsOrphanGarbage_EmitterComplete(t *testing.T) {
	ctx := context.Background()
	tiles := NewMemSMTTileStore()
	tailed := NewTailedNodeStore(smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16)))
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), tailed)
	emitter := NewBuildTilesEmitter(tailed, tiles)
	root := smt.EmptyHash

	const batches, perBatch = 30, 64
	total := 0
	for b := 0; b < batches; b++ {
		prevRoot := root // prior committed+tiled root (EmptyHash at genesis) — the warm-walk anchor production threads
		batch := make([]types.SMTLeaf, 0, perBatch)
		for i := 0; i < perBatch; i++ {
			k := sha256.Sum256([]byte{byte(total), byte(total >> 8), byte(total >> 16)})
			batch = append(batch, types.SMTLeaf{Key: k, OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(total + 1)}})
			total++
		}
		if err := tree.SetLeaves(ctx, batch); err != nil {
			t.Fatalf("SetLeaves: %v", err)
		}
		var err error
		if root, err = tree.Root(ctx); err != nil {
			t.Fatalf("Root: %v", err)
		}
		durable, err := emitter.EmitDurable(ctx, prevRoot, root, uint64(total))
		if err != nil {
			t.Fatalf("EmitDurable: %v", err)
		}
		tailed.PruneTiled(ctx, func(_ context.Context, h [32]byte) (bool, error) { _, ok := durable[h]; return ok, nil })
	}

	// The exact LIVE set: a full graph traversal from the final committed root over the
	// combined substrate (tail + tiles), so every reachable node is collected.
	liveTiles, err := smt.BuildTiles(tailed, root, smt.TileHeight)
	if err != nil {
		t.Fatalf("BuildTiles(live): %v", err)
	}
	live := map[[32]byte]struct{}{}
	for _, tile := range liveTiles {
		for i := range tile.Nodes {
			live[smt.HashNode(tile.Nodes[i])] = struct{}{}
		}
	}

	// (a) NO live node is stuck in the residual tail.
	stuck := 0
	for h := range tailed.Tail() {
		if _, ok := live[h]; ok {
			stuck++
		}
	}
	if stuck != 0 {
		t.Fatalf("DATA-LOSS RISK: %d LIVE nodes are stuck in the tail — emitter dropped them; residual is NOT all garbage", stuck)
	}

	// (b) emitter COMPLETE: reconstruct the live tree from TILES ALONE. A dropped live
	// node faults here; a short node set means the emitter under-emitted.
	tilesOnly := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16))
	rebuilt, err := smt.BuildTiles(tilesOnly, root, smt.TileHeight)
	if err != nil {
		t.Fatalf("EMITTER INCOMPLETE: live tree not reconstructable from tiles alone: %v", err)
	}
	got := map[[32]byte]struct{}{}
	for _, tile := range rebuilt {
		for i := range tile.Nodes {
			got[smt.HashNode(tile.Nodes[i])] = struct{}{}
		}
	}
	if len(got) != len(live) {
		t.Fatalf("EMITTER MISMATCH: tiles-only reconstruct = %d nodes, live = %d", len(got), len(live))
	}
	for h := range live {
		if _, ok := got[h]; !ok {
			t.Fatalf("EMITTER DROPPED live node %x (absent from tiles-only reconstruct)", h[:6])
		}
	}

	t.Logf("PROOF: entries=%d  residual=%d  live=%d  stuck(live∩residual)=0  tiles-only-reconstruct=%d",
		total, tailed.TailLen(), len(live), len(got))
	t.Logf("⇒ residual is 100%% orphaned intra-batch garbage; the emitter dropped ZERO live nodes (whole tree durable from tiles alone).")
}

// TestTailBound_ReachableMutationsEndToEnd is the end-to-end guard for the complete
// fix: it drives the builder's EXACT commit→checkpoint loop — overlay SetLeaves,
// PutBatch(overlayNodes.ReachableMutations(newRoot)) [the SDK orphan filter],
// EmitDurable, durable-set prune — over many batches, and asserts the tail stays
// BOUNDED (the un-tiled gap), not O(history). With plain Mutations() this same loop
// leaks ~5.8 nodes/entry (the writer OOM); ReachableMutations + prune holds it flat.
func TestTailBound_ReachableMutationsEndToEnd(t *testing.T) {
	ctx := context.Background()
	tiles := NewMemSMTTileStore()
	tailed := NewTailedNodeStore(smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16)))
	leafStore := smt.NewInMemoryLeafStore()
	emitter := NewBuildTilesEmitter(tailed, tiles)
	root := smt.EmptyHash

	const batches, perBatch = 40, 64
	total, maxTail := 0, 0
	for b := 0; b < batches; b++ {
		prevRoot := root // prior committed+tiled root (EmptyHash at genesis) — the warm-walk anchor production threads
		// Builder shape: overlay over the tail; leaves persist directly.
		overlayNodes := smt.NewOverlayNodeStore(tailed)
		tree := smt.NewTree(leafStore, overlayNodes)
		tree.SetRoot(root)
		batch := make([]types.SMTLeaf, 0, perBatch)
		for i := 0; i < perBatch; i++ {
			k := sha256.Sum256([]byte{byte(total), byte(total >> 8), byte(total >> 16)})
			batch = append(batch, types.SMTLeaf{Key: k, OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(total + 1)}})
			total++
		}
		if err := tree.SetLeaves(ctx, batch); err != nil {
			t.Fatalf("SetLeaves: %v", err)
		}
		var err error
		if root, err = tree.Root(ctx); err != nil {
			t.Fatalf("Root: %v", err)
		}
		// THE FIX: only the final-reachable delta enters the tail (orphans excluded).
		dirty := overlayNodes.ReachableMutations(root)
		nodes := make([]smt.Node, 0, len(dirty))
		for _, n := range dirty {
			nodes = append(nodes, n)
		}
		tailed.PutBatch(nodes)
		// Checkpoint: emit + durable-set prune (the committed #1).
		durable, err := emitter.EmitDurable(ctx, prevRoot, root, uint64(total))
		if err != nil {
			t.Fatalf("EmitDurable: %v", err)
		}
		tailed.PruneTiled(ctx, func(_ context.Context, h [32]byte) (bool, error) { _, ok := durable[h]; return ok, nil })
		if tl := tailed.TailLen(); tl > maxTail {
			maxTail = tl
		}
	}
	// BOUNDED: with orphans filtered + durable-prune, the tail collapses to the gap.
	// Generous ceiling (one batch's delta worth), FAR below the ~5.8*total leak.
	if maxTail > 4*perBatch {
		t.Fatalf("tail not bounded: maxTail=%d over %d entries (orphan filter or prune regressed) — want ≤ %d", maxTail, total, 4*perBatch)
	}
	// SERVABLE: every entry's proof resolves from the durable tiles alone.
	fresh := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16))
	for _, idx := range []int{0, total / 2, total - 1} {
		k := sha256.Sum256([]byte{byte(idx), byte(idx >> 8), byte(idx >> 16)})
		if _, perr := smt.GenerateProofAt(fresh, root, k); perr != nil {
			t.Fatalf("proof idx=%d unservable from tiles after fix: %v", idx, perr)
		}
	}
	t.Logf("BOUNDED: %d entries, maxTail=%d nodes (%.3f/entry) — vs ~5.8/entry unfixed", total, maxTail, float64(maxTail)/float64(total))
}

// TestTileEmitter_FreshStore_FromRootResolvesPrunedInteriors is the production-
// faithful capstone for the OOM-prune + tiling fix together. It emits each batch
// through a FRESH TiledNodeStore the builder never warmed, so a re-emitted tile's
// unchanged interiors — pruned from the tail and never fetched as tiles — resolve
// ONLY via the fromRoot warm-walk that EmitDurable threads into BuildDirtyTiles.
// (The other tail-bound tests share one long-lived store that SetLeaves incidentally
// warms, so they would pass even if fromRoot were mis-threaded; this one would not.)
// ± over a warm flag:
//
//	warm=true  (fromRoot=prevRoot): every batch emits cleanly under the pruned tail;
//	warm=false (fromRoot=EmptyHash): the same flow strands a pruned interior
//	                                 (ErrNodeMissing), proving the threading is load-bearing.
func TestTileEmitter_FreshStore_FromRootResolvesPrunedInteriors(t *testing.T) {
	if b, err := runFreshStoreEmit(t, 20, 64, true); err != nil {
		t.Fatalf("fromRoot-warmed fresh-store emit must resolve every interior; failed at batch %d: %v", b, err)
	}
	b, err := runFreshStoreEmit(t, 20, 64, false)
	if !errors.Is(err, smt.ErrNodeMissing) {
		t.Fatalf("without fromRoot the fresh-store emit must strand a pruned interior (ErrNodeMissing); got (batch=%d) %v", b, err)
	}
}

// runFreshStoreEmit drives the commit→checkpoint loop but emits each batch through
// a FRESH store (never warmed by the builder). warm selects fromRoot=prevRoot (the
// fix) vs EmptyHash (warming disabled). Returns the batch index and error of the
// first emit failure, or (-1, nil) if all batches emit and the tree stays servable.
func runFreshStoreEmit(t *testing.T, batches, perBatch int, warm bool) (int, error) {
	t.Helper()
	ctx := context.Background()
	tiles := NewMemSMTTileStore() // shared durable tile sink

	// Builder substrate: long-lived, warmed by its own top-down reads (realistic).
	builderTailed := NewTailedNodeStore(smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16)))
	leafStore := smt.NewInMemoryLeafStore()

	root, prevRoot := smt.EmptyHash, smt.EmptyHash
	total := 0
	for b := 0; b < batches; b++ {
		overlay := smt.NewOverlayNodeStore(builderTailed)
		tree := smt.NewTree(leafStore, overlay)
		tree.SetRoot(root)
		batch := make([]types.SMTLeaf, 0, perBatch)
		for i := 0; i < perBatch; i++ {
			k := sha256.Sum256([]byte{byte(total), byte(total >> 8), byte(total >> 16)})
			batch = append(batch, types.SMTLeaf{Key: k, OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(total + 1)}})
			total++
		}
		if err := tree.SetLeaves(ctx, batch); err != nil {
			t.Fatalf("SetLeaves: %v", err)
		}
		var err error
		if root, err = tree.Root(ctx); err != nil {
			t.Fatalf("Root: %v", err)
		}
		dirty := overlay.ReachableMutations(root)
		nodes := make([]smt.Node, 0, len(dirty))
		for _, n := range dirty {
			nodes = append(nodes, n)
		}
		builderTailed.PutBatch(nodes)

		// Emit through a FRESH store seeded with ONLY this batch's committed-but-not-
		// tiled delta — never warmed by the builder. Pruned prior interiors can resolve
		// only if EmitDurable warms the prior tile from fromRoot.
		emitTailed := NewTailedNodeStore(smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(4096)))
		emitTailed.PutBatch(nodes)
		from := smt.EmptyHash
		if warm {
			from = prevRoot
		}
		durable, err := NewBuildTilesEmitter(emitTailed, tiles).EmitDurable(ctx, from, root, uint64(total))
		if err != nil {
			return b, err
		}
		builderTailed.PruneTiled(ctx, func(_ context.Context, h [32]byte) (bool, error) { _, ok := durable[h]; return ok, nil })
		prevRoot = root
	}
	// Servable from tiles alone — the warmed path emitted a complete, correct set.
	fresh := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16))
	for _, idx := range []int{0, total / 2, total - 1} {
		k := sha256.Sum256([]byte{byte(idx), byte(idx >> 8), byte(idx >> 16)})
		if _, perr := smt.GenerateProofAt(fresh, root, k); perr != nil {
			t.Fatalf("proof idx=%d unservable from tiles: %v", idx, perr)
		}
	}
	return -1, nil
}

// TestTileEmitter_CappedEmitNodes_ResolvesViaFreshStore is the direct guard for the
// fresh-unbounded-read-through fix, and it pins the fix to the EMIT path — where the
// bug lives — not the tree path.
//
// The tree is built on an UNBOUNDED store. That is faithful: in production the
// long-lived cache (65 536) dwarfs a single tile (≤256 nodes), and SetLeaves walks
// TOP-DOWN addressing only tile TOPS, which a TiledNodeStore can always re-fetch from
// the sink — so an eviction there costs a re-fetch, never an ErrNodeMissing. The tree
// path is structurally not the fault site; only the emit walk is.
//
// The emitter is handed an e.nodes whose durable read-through is capped at 64 NODES —
// below one tiling pass's working set; the production stall (cap 65 536 → strand at
// ~172k entries) writ small. The emit walk re-reads warm-walked CLEAN INTERIORS BY
// HASH, which a TiledNodeStore cannot re-fetch once their tile is evicted, so the
// pre-fix emit — BuildDirtyTiles(e.nodes, ...) — strands here exactly as in
// production. Because the fix reads the tiling walk through a FRESH UNBOUNDED store
// over the tile sink (never e.nodes' capped Get), every batch must resolve and the
// tree must be tiles-complete. Revert the fix and the 64-node cap strands it: the
// trap that holds the fix in place.
func TestTileEmitter_CappedEmitNodes_ResolvesViaFreshStore(t *testing.T) {
	ctx := context.Background()
	tiles := NewMemSMTTileStore()
	// Tree substrate: UNBOUNDED. SetLeaves (top-down, tile-top addressed, re-fetchable)
	// is never the fault — in production its cache is always >> a tile, so the bug, and
	// thus this guard, lives strictly on the emit path below.
	tailed := NewTailedNodeStore(smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16)))
	leafStore := smt.NewInMemoryLeafStore()

	const batches, perBatch = 40, 64
	root, total := smt.EmptyHash, 0
	for b := 0; b < batches; b++ {
		prevRoot := root
		overlay := smt.NewOverlayNodeStore(tailed)
		tree := smt.NewTree(leafStore, overlay)
		tree.SetRoot(root)
		batch := make([]types.SMTLeaf, 0, perBatch)
		for i := 0; i < perBatch; i++ {
			k := sha256.Sum256([]byte{byte(total), byte(total >> 8), byte(total >> 16)})
			batch = append(batch, types.SMTLeaf{Key: k, OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(total + 1)}})
			total++
		}
		if err := tree.SetLeaves(ctx, batch); err != nil {
			t.Fatalf("SetLeaves b=%d: %v", b, err)
		}
		var err error
		if root, err = tree.Root(ctx); err != nil {
			t.Fatalf("Root: %v", err)
		}
		dirty := overlay.ReachableMutations(root)
		nodes := make([]smt.Node, 0, len(dirty))
		for _, n := range dirty {
			nodes = append(nodes, n)
		}
		tailed.PutBatch(nodes)

		// EMIT through an adversarial e.nodes: its Tail() is the live committed-but-not-
		// tiled dirty set, but its Get reads through a 64-node-capped durable store that
		// evicts a band's interiors mid-walk. The fix's fresh unbounded store must make
		// that cap irrelevant.
		emitNodes := &cappedEmitNodes{
			tail:   tailed.Tail(),
			capped: smt.NewTiledNodeStoreCapped(ctx, tiles, nil, 64),
		}
		durable, err := NewBuildTilesEmitter(emitNodes, tiles).EmitDurable(ctx, prevRoot, root, uint64(total))
		if err != nil {
			t.Fatalf("EmitDurable stranded at batch %d with a 64-node e.nodes read-through cap — the fresh-store fix regressed (emit is reading the tiling walk through e.nodes' bounded cache again): %v", b, err)
		}
		tailed.PruneTiled(ctx, func(_ context.Context, h [32]byte) (bool, error) { _, ok := durable[h]; return ok, nil })
	}
	// Tiles-complete: every entry's proof reconstructs from the durable tiles alone.
	fresh := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16))
	for _, idx := range []int{0, total / 2, total - 1} {
		k := sha256.Sum256([]byte{byte(idx), byte(idx >> 8), byte(idx >> 16)})
		if _, perr := smt.GenerateProofAt(fresh, root, k); perr != nil {
			t.Fatalf("proof idx=%d unservable from tiles after a capped-emit run: %v", idx, perr)
		}
	}
}

// cappedEmitNodes is an adversarial emitter substrate: Tail() is the live committed-
// but-not-tiled dirty set, while Get reads through a TIGHTLY capped durable store.
// It exists to pin the fresh-store fix to the emit path. The emitter must read its
// tiling walk through its OWN fresh unbounded store (over the tile sink), never this
// capped Get — so a 64-node cap here is invisible to the fix but strands the pre-fix
// BuildDirtyTiles(e.nodes, ...) on an evicted, un-re-fetchable interior.
type cappedEmitNodes struct {
	tail   map[[32]byte]smt.Node
	capped smt.NodeStore
}

func (v *cappedEmitNodes) Tail() map[[32]byte]smt.Node { return v.tail }
func (v *cappedEmitNodes) Get(h [32]byte) (smt.Node, error) {
	if h == smt.EmptyHash {
		return nil, nil
	}
	if n, ok := v.tail[h]; ok {
		return n, nil
	}
	return v.capped.Get(h)
}
func (v *cappedEmitNodes) Put(n smt.Node) ([32]byte, error) { return smt.HashNode(n), nil }
