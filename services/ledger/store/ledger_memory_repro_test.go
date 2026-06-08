package store

import (
	"context"
	"crypto/sha256"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// TestLedgerMemory_NodeStoreHeapGrowth reproduces the production writer's anon-heap
// growth in-process (the e2e showed RssAnon ~3.5 GiB at ~43K entries, RssFile 47 MiB
// — a Go-heap retention, not file/WAL). It drives the EXACT production node-store
// shape — ONE long-lived TailedNodeStore over ONE long-lived TiledNodeStore
// (wire.go:540), builder overlay + ReachableMutations + PutBatch per entry, async
// checkpoint EmitDurable(fromRoot) + durable-set prune — and measures HeapInuse.
//
// Run with a heap profile to name the allocation site:
//
//	GOWORK=off go test ./store/ -run NodeStoreHeapGrowth -v
//	go tool pprof -top -inuse_space /tmp/ledgermem.heap
//
// PROFILED RESULT (evidence, not a guess): the retained heap is dominated by
// smt.DecodeNode (~65% of inuse_objects), reached via smt.(*TiledNodeStore).Get
// under EmitDurable→BuildDirtyTiles→collectBandTile — decoded tile nodes kept
// forever in the ONE long-lived TiledNodeStore.s.nodes map (the fromRoot warm-walk
// fetches the prior tile into it every checkpoint). The tail (TailLen, logged) is a
// second, smaller leak: the async-checkpoint durable-set prune does not reclaim
// cross-batch superseded nodes, so it grows O(entries). (Discount MemSMTTileStore.Put
// in the profile — production writes tiles to the object store, not heap.) The lean
// PG-off reader avoids both by building a request-scoped store per request.
//
// FIX: request-scope the emit (and builder) node store + a tail-GC. This harness
// PASSES today (characterization); it will be tightened to ASSERT bounded heap/tail
// once that fix lands.
func TestLedgerMemory_NodeStoreHeapGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("heap-growth repro is slow; skipped under -short")
	}
	ctx := context.Background()
	tiles := NewMemSMTTileStore()
	// EXACTLY production: one long-lived TiledNodeStore (cacheSize 4096 default), one
	// long-lived TailedNodeStore, used by BOTH the builder reads and the emitter.
	tailed := NewTailedNodeStore(smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(4096)))
	leafStore := smt.NewInMemoryLeafStore()
	emitter := NewBuildTilesEmitter(tailed, tiles)

	measure := func(label string, n int) uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		t.Logf("%-6s entries=%-6d HeapInuse=%4dMiB HeapObjects=%d tail=%d",
			label, n, m.HeapInuse>>20, m.HeapObjects, tailed.TailLen())
		return m.HeapInuse
	}

	const total, checkpointEvery = 12000, 100
	root, prevRoot := smt.EmptyHash, smt.EmptyHash
	h0 := measure("start", 0)
	pending := 0
	for i := 0; i < total; i++ {
		overlay := smt.NewOverlayNodeStore(tailed)
		tree := smt.NewTree(leafStore, overlay)
		tree.SetRoot(root)
		k := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		if err := tree.SetLeaf(ctx, k, types.SMTLeaf{Key: k, OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i + 1)}}); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, err)
		}
		var err error
		if root, err = tree.Root(ctx); err != nil {
			t.Fatalf("Root %d: %v", i, err)
		}
		dirty := overlay.ReachableMutations(root)
		ns := make([]smt.Node, 0, len(dirty))
		for _, n := range dirty {
			ns = append(ns, n)
		}
		tailed.PutBatch(ns)
		pending++
		if pending >= checkpointEvery {
			durable, derr := emitter.EmitDurable(ctx, prevRoot, root, uint64(i+1))
			if derr != nil {
				t.Fatalf("EmitDurable @%d: %v", i, derr)
			}
			tailed.PruneTiled(ctx, func(_ context.Context, h [32]byte) (bool, error) { _, ok := durable[h]; return ok, nil })
			prevRoot = root
			pending = 0
		}
		if i%3000 == 2999 {
			measure("at", i+1)
		}
	}
	hN := measure("end", total)
	perEntry := int64(hN-h0) / total
	t.Logf("HEAP GREW %d MiB over %d entries = %d bytes/entry (tail stayed %d)",
		int64(hN-h0)>>20, total, perEntry, tailed.TailLen())

	// Write a heap profile WHILE the long-lived store is still referenced, so the
	// retained allocations are in the inuse profile (a -memprofile at test end would
	// miss them — tailed would already be unreachable).
	if f, err := os.Create("/tmp/ledgermem.heap"); err == nil {
		runtime.GC()
		_ = pprof.WriteHeapProfile(f)
		_ = f.Close()
		t.Log("heap profile → /tmp/ledgermem.heap")
	}
	runtime.KeepAlive(tailed)
}
