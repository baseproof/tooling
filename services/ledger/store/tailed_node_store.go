/*
FILE PATH: store/tailed_node_store.go

TailedNodeStore — the de-polluted SMT node substrate (replaces PostgresNodeStore).

PG no longer stores the Jellyfish node DAG; it stores only smt_leaves (the
irreducible state) + smt_root_state + tile_frontier. The ~2N node DAG lives in
content-addressed tiles (object store). This store is what the builder computes
over and what the reconciler emits from:

	Get:  in-memory TAIL (nodes committed since the last frontier advance, not yet
	      tiled) → read-through to durable TILES (TiledNodeStore, ≤ frontier).
	Put:  appends to the tail (the builder's post-commit handoff).

root = f(smt_leaves), so the tail is a rebuildable cache: on boot it is empty and
the recovery path replays smt_leaves to re-derive the gap (frontier→committed)
before serving. Losing the tail is never data loss.

CONCURRENCY: a single writer (the builder, via Put/PutBatch) and a single reader
(the reconciler, via Get during BuildTiles + PruneTiled after a frontier advance),
guarded by one RWMutex. Reads from the tile substrate happen outside the lock.
*/
package store

import (
	"context"

	"sync"

	"github.com/baseproof/baseproof/core/smt"
)

// TailedNodeStore implements smt.NodeStore over an in-memory tail + tiles.
type TailedNodeStore struct {
	mu    sync.RWMutex
	tail  map[[32]byte]smt.Node
	tiles smt.NodeStore // durable read-through (a *smt.TiledNodeStore)
}

var _ smt.NodeStore = (*TailedNodeStore)(nil)

// NewTailedNodeStore wraps a durable tile-backed NodeStore with an in-memory
// tail of not-yet-tiled nodes.
func NewTailedNodeStore(tiles smt.NodeStore) *TailedNodeStore {
	return &TailedNodeStore{tail: make(map[[32]byte]smt.Node), tiles: tiles}
}

// Get returns the node for hash: the un-tiled tail first, then durable tiles.
// (nil, nil) for EmptyHash or an absent node, per the smt.NodeStore contract.
func (s *TailedNodeStore) Get(hash [32]byte) (smt.Node, error) {
	if hash == smt.EmptyHash {
		return nil, nil
	}
	s.mu.RLock()
	n, ok := s.tail[hash]
	s.mu.RUnlock()
	if ok {
		return n, nil
	}
	return s.tiles.Get(hash)
}

// Put appends a node to the tail (content-addressed; dedup by hash).
func (s *TailedNodeStore) Put(node smt.Node) ([32]byte, error) {
	h := smt.HashNode(node)
	s.mu.Lock()
	s.tail[h] = node
	s.mu.Unlock()
	return h, nil
}

// PutBatch appends many nodes to the tail — the builder's post-commit handoff of
// a batch's dirty nodes, so the next batch reads them as siblings before they are
// tiled.
func (s *TailedNodeStore) PutBatch(nodes []smt.Node) {
	s.mu.Lock()
	for _, n := range nodes {
		s.tail[smt.HashNode(n)] = n
	}
	s.mu.Unlock()
}

// PruneTiled evicts tail nodes that are now durably present in tiles. Called by
// the reconciler after it advances the frontier, bounding the tail to the
// un-tiled gap. `exists` is the tile store's existence oracle (S3 HEAD / stat).
// Off the hot path; a transient existence error leaves the node in the tail
// (re-checked next cycle — never wrongly evicts a still-needed node).
//
// RETENTION INVARIANT (load-bearing for offline as-of regeneration at the
// 15-year horizon): a node leaves the tail ONLY after `exists` confirms it is
// durably present in tiles, so for every committed node, at every instant,
// (in tail) OR (durably in tiles) holds — there is never a window in which a
// published checkpoint root's node is unservable (no GC window). This is the
// only SMT-node eviction in the store and it is fail-closed on an inconclusive
// existence check. Guarded by tailed_node_store_retention_test.go.
func (s *TailedNodeStore) PruneTiled(ctx context.Context, exists func(ctx context.Context, id [32]byte) (bool, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for h := range s.tail {
		if ok, err := exists(ctx, h); err == nil && ok {
			delete(s.tail, h)
		}
	}
}

// TailLen reports the un-tiled node count (metrics / tests).
func (s *TailedNodeStore) TailLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tail)
}
