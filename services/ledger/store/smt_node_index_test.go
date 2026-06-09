package store

import (
	"context"
	"sync"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// memNodeIndex is an in-memory NodeIndexStore: the producer/consumer contract
// without PG, so the emitter wiring is testable everywhere. First-writer-wins
// mirrors the PG ON CONFLICT DO NOTHING (content-addressed mappings are immutable).
type memNodeIndex struct {
	mu sync.Mutex
	m  map[[32]byte][32]byte
}

func newMemNodeIndex() *memNodeIndex { return &memNodeIndex{m: map[[32]byte][32]byte{}} }

func (x *memNodeIndex) OwningTile(node [32]byte) ([32]byte, bool, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	t, ok := x.m[node]
	return t, ok, nil
}

func (x *memNodeIndex) PutNodes(_ context.Context, es []NodeIndexEntry) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, e := range es {
		if _, ok := x.m[e.Node]; !ok {
			x.m[e.Node] = e.Top
		}
	}
	return nil
}

func (x *memNodeIndex) len() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.m)
}

// TestBuildTilesEmitter_PopulatesNodeIndex_ResolvesInterior is the producer-side
// red→green: the emitter writes node→owning-top entries for the interiors it makes
// durable, and a TiledNodeStore with that index resolves an interior that is
// UNRESOLVABLE from the top-keyed tiles alone — closing the leaf-loss gap end to
// end (emit populates → read-through resolves).
func TestBuildTilesEmitter_PopulatesNodeIndex_ResolvesInterior(t *testing.T) {
	ctx := context.Background()
	tailed := NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), tailed)
	// key3band forces a ≥3-band tree, so tiles have genuine interiors and boundary
	// children (the structure the index is for).
	for i := 0; i < 64; i++ {
		k := key3band(i)
		if err := tree.SetLeaf(ctx, k, types.SMTLeaf{
			Key: k, OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i + 1)},
		}); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, err)
		}
	}
	root, err := tree.Root(ctx)
	if err != nil || root == smt.EmptyHash {
		t.Fatalf("root: %v (empty=%v)", err, root == smt.EmptyHash)
	}

	tiles := NewMemSMTTileStore()
	idx := newMemNodeIndex()
	em := NewBuildTilesEmitter(tailed, tiles)
	em.SetNodeIndex(idx)
	if _, err := em.EmitDurable(ctx, smt.EmptyHash, root, 64); err != nil {
		t.Fatalf("EmitDurable: %v", err)
	}
	if idx.len() == 0 {
		t.Fatal("emitter populated no node-index entries for a multi-band tree")
	}

	// Pick an indexed (⇒ interior, non-top) node.
	var interior, owningTop [32]byte
	idx.mu.Lock()
	for n, top := range idx.m {
		interior, owningTop = n, top
		break
	}
	idx.mu.Unlock()

	// It must NOT be a tile top (else the index would be indexing tops).
	if ok, _ := tiles.Exists(ctx, interior); ok {
		t.Fatalf("indexed node %x is itself a tile top; expected an interior", interior[:6])
	}

	// Without the index: a clean miss (interiors are not top-fetchable).
	bare := smt.NewTiledNodeStore(ctx, tiles, nil)
	if n, err := bare.Get(interior); err != nil || n != nil {
		t.Fatalf("without index: interior %x should be a clean miss, got (node=%v, err=%v)", interior[:6], n != nil, err)
	}

	// With the index: resolves to the genuine node via its owning tile.
	withIdx := smt.NewTiledNodeStore(ctx, tiles, nil)
	withIdx.SetNodeIndex(idx)
	n, err := withIdx.Get(interior)
	if err != nil || n == nil {
		t.Fatalf("with index: interior %x should resolve, got (node=%v, err=%v)", interior[:6], n != nil, err)
	}
	if got := smt.HashNode(n); got != interior {
		t.Fatalf("resolved node hashes to %x, want %x", got[:6], interior[:6])
	}
	if ok, _ := tiles.Exists(ctx, owningTop); !ok {
		t.Fatalf("owning top %x is not a durable tile", owningTop[:6])
	}
}

// TestPGNodeIndex_RoundTrip exercises the durable index against a real Postgres
// schema (skips without BASEPROOF_TEST_DSN): put/lookup, an unknown-node miss, and
// the first-writer-wins idempotency that makes re-emit safe.
func TestPGNodeIndex_RoundTrip(t *testing.T) {
	pool := IsolatedDB(t) // t.Skip when BASEPROOF_TEST_DSN is unset
	ctx := context.Background()
	idx := NewPGNodeIndex(ctx, pool)

	mk := func(b byte) [32]byte { var h [32]byte; h[0], h[31] = b, b; return h }
	n1, t1 := mk(0x11), mk(0xA1)
	n2, t2 := mk(0x22), mk(0xA2)

	if err := idx.PutNodes(ctx, []NodeIndexEntry{{Node: n1, Top: t1}, {Node: n2, Top: t2}}); err != nil {
		t.Fatalf("PutNodes: %v", err)
	}

	for _, c := range []struct {
		node, top [32]byte
	}{{n1, t1}, {n2, t2}} {
		got, ok, err := idx.OwningTile(c.node)
		if err != nil || !ok || got != c.top {
			t.Fatalf("OwningTile(%x) = (%x, ok=%v, err=%v), want (%x, true, nil)", c.node[:4], got[:4], ok, err, c.top[:4])
		}
	}

	// Unknown node → clean miss, not an error.
	if _, ok, err := idx.OwningTile(mk(0xFF)); ok || err != nil {
		t.Fatalf("unknown OwningTile: want (_, false, nil), got (ok=%v, err=%v)", ok, err)
	}

	// Idempotent: re-asserting n1 under a DIFFERENT top is a no-op (first writer
	// wins), so a re-emit can never repoint an existing immutable mapping.
	if err := idx.PutNodes(ctx, []NodeIndexEntry{{Node: n1, Top: mk(0xEE)}}); err != nil {
		t.Fatalf("re-PutNodes: %v", err)
	}
	if got, ok, _ := idx.OwningTile(n1); !ok || got != t1 {
		t.Fatalf("after conflicting re-put, OwningTile(n1) = (%x, ok=%v), want unchanged %x", got[:4], ok, t1[:4])
	}
}
