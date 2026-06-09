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
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/baseproof/baseproof/core/smt"
)

// TailedNodeStore implements smt.NodeStore over an in-memory tail + tiles.
type TailedNodeStore struct {
	mu    sync.RWMutex
	tail  map[[32]byte]smt.Node
	tiles smt.NodeStore // durable read-through (a *smt.TiledNodeStore)

	// committedRoot is the SMT root of the LATEST batch handed to the tail, set
	// ATOMICALLY with that batch's nodes (PutBatchCommitted) so PruneOrphans can
	// walk from a root that is always consistent with the tail's contents — the
	// race-free coupling that lets the orphan-prune drop cross-batch orphans
	// without ever stranding a just-committed, not-yet-tiled node. Zero until the
	// first committed batch.
	committedRoot [32]byte

	// probe + missLogged: leaf-loss tracing (LEDGER_TILE_VERIFY_FETCH=1, via the
	// emitter's tileVerifyFetch). When set, a Get that resolves to neither the tail
	// nor a fetchable tile — the exact point jellyfishInsert faults "missing node X
	// (referenced by ancestor)" → PathD → leaf loss — is classified against the tile
	// store: Exists(X) HEAD true ⇒ X is a durable tile-TOP that GET could not read
	// (a builder-side fetch / HEAD-GET issue); false ⇒ X is a tile INTERIOR the walk
	// reached without its top (the compression top-skip). probe nil ⇒ trace off.
	probe      SMTTileStore
	missLogged atomic.Int64
}

// SetMissProbe wires the durable tile store used to classify a Get miss under the
// leaf-loss trace (see probe). nil disables it. Set once at boot, before serving.
func (s *TailedNodeStore) SetMissProbe(p SMTTileStore) { s.probe = p }

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
	tn, err := s.tiles.Get(hash)
	if tileVerifyFetch && s.probe != nil && err == nil && tn == nil {
		s.probeMiss(hash) // the leaf-loss point: classify X (tile-top vs interior)
	}
	return tn, err
}

// probeMiss classifies a node X that resolved from neither the tail nor a fetchable
// tile — the "missing node X (referenced by ancestor)" the SDK insert faults on.
// Exists(X) (HEAD) true ⇒ X is a durable tile-TOP that GET could not read (builder
// fetch / HEAD-GET issue); false ⇒ X is a tile INTERIOR reached without its top
// (compression top-skip). Detailed logging is capped so a 6k-miss soak does not
// flood; the classification from the first samples is sufficient.
func (s *TailedNodeStore) probeMiss(hash [32]byte) {
	if s.missLogged.Add(1) > 64 {
		return
	}
	v := ClassifyTileMiss(context.Background(), s.probe, hash)
	slog.Default().Error("BUILDER NODE MISS: not in tail, not fetchable from tiles (leaf-loss point)",
		"node", fmt.Sprintf("%x", hash[:]),
		"tile_path", smt.TilePath(hash),
		"verdict", v.Kind, // INTERIOR_TOP_SKIP | STRANDED_TOP_HEAD_GET | RESOLVES_NOW
		"is_tile_top_HEAD", v.IsTileTopHEAD, // false ⇒ band INTERIOR (compression top-skip)
		"get_bytes", v.GetBytes,
		"get_err", v.GetErr,
	)
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

// PutBatchCommitted is PutBatch plus, in the SAME critical section, recording the
// batch's committed SMT root. This atomicity is load-bearing for PruneOrphans: a
// reader holding the lock always sees committedRoot consistent with the nodes in
// the tail, so the orphan-prune can never walk from a stale root and drop a
// just-committed node. The builder uses this (one writer); plain PutBatch remains
// for tests/primitives that don't drive the prune.
func (s *TailedNodeStore) PutBatchCommitted(nodes []smt.Node, committedRoot [32]byte) {
	s.mu.Lock()
	for _, n := range nodes {
		s.tail[smt.HashNode(n)] = n
	}
	s.committedRoot = committedRoot
	s.mu.Unlock()
}

// PruneOrphans evicts every tail node NOT reachable from the latest committed
// root — the cross-batch ORPHANS (interior-node versions superseded by a later
// batch, so on no committed path and never tiled, hence invisible to PruneTiled's
// durability check). It is the O(entries)→O(gap) bound that keeps the tail flat.
//
// SAFE (validated by TailGCAudit in soak): a tail node unreachable from the
// committed root is either durable in tiles (servable there) or referenced by no
// published root (published ⇒ durable). RACE-FREE: walks from s.committedRoot —
// the tail's own notion, set atomically with the nodes by PutBatchCommitted —
// under the write lock, so a concurrent commit cannot make it drop a live node.
// Fails toward RETENTION (keeps everything reachable) and is a no-op until the
// first committed batch. The tail is rebuildable from smt_leaves regardless, so a
// mis-drop is at worst a transient recompute, never data loss. Returns the count
// dropped. Bounded by the un-tiled gap, not history.
func (s *TailedNodeStore) PruneOrphans() (dropped int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Never drop blindly: the zero value means no batch has set a root yet, and
	// EmptyHash means an empty tree — in either degenerate case a walk would reach
	// nothing and evict the whole tail. Fail toward retention and no-op.
	if s.committedRoot == ([32]byte{}) || s.committedRoot == smt.EmptyHash {
		return 0
	}
	reachable := s.reachableInTail(s.committedRoot)
	for h := range s.tail {
		if _, keep := reachable[h]; !keep {
			delete(s.tail, h)
			dropped++
		}
	}
	return dropped
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

// reachableInTail returns the set of TAIL-RESIDENT node hashes reachable from
// root via tail-only paths. A hash absent from the tail ends that branch: tiles
// emit complete band subtrees, so a durable (tiled, non-tail) node has durable
// children — no tail node hangs below it. Caller holds s.mu (read is enough).
// Cost is bounded by the un-tiled gap, not history.
func (s *TailedNodeStore) reachableInTail(root [32]byte) map[[32]byte]struct{} {
	seen := make(map[[32]byte]struct{})
	var visit func(h [32]byte)
	visit = func(h [32]byte) {
		if h == smt.EmptyHash {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		n, ok := s.tail[h]
		if !ok {
			return // durable/absent ⇒ this branch is fully tiled
		}
		seen[h] = struct{}{}
		if b, isBranch := n.(*smt.BranchNode); isBranch {
			visit(b.LeftHash)
			visit(b.RightHash)
		}
	}
	visit(root)
	return seen
}

// TailGCAudit is a NON-DESTRUCTIVE check of the assumption the orphan-prune will
// rely on: every tail node the prune would drop (i.e. not reachable from
// committedRoot) is safe to drop because it is EITHER durable in tiles (servable
// there) OR not reachable from any retained published root (published ⇒ durable).
//
// It computes the RISKY set — tail nodes reachable from some publishedRoot but
// NOT from committedRoot (these would be dropped, yet a published root needs
// them) — and counts how many are NOT durable in tiles. That count is the number
// of VIOLATIONS: a non-zero value means dropping them would strand a published
// root, i.e. the assumption is FALSE. In a correct system (published ⇒ durable)
// it is always 0, cheaply: a fully-tiled published root reaches no tail node.
//
// Durability is checked against the store's own durable read-through (s.tiles),
// outside the lock (it may do I/O). Run this in a soak BEFORE enabling the prune.
func (s *TailedNodeStore) TailGCAudit(committedRoot [32]byte, publishedRoots [][32]byte) (candidates, violations int, sample [32]byte) {
	s.mu.RLock()
	committedReach := s.reachableInTail(committedRoot)
	candSet := make(map[[32]byte]struct{})
	for _, pr := range publishedRoots {
		for h := range s.reachableInTail(pr) {
			if _, retained := committedReach[h]; retained {
				continue // reachable from committed ⇒ the prune keeps it
			}
			candSet[h] = struct{}{}
		}
	}
	s.mu.RUnlock()

	candidates = len(candSet)
	for h := range candSet {
		if n, err := s.tiles.Get(h); err == nil && n != nil {
			continue // durable in tiles ⇒ safe to drop from the tail
		}
		violations++
		sample = h
	}
	return candidates, violations, sample
}

// TailLen reports the un-tiled node count (metrics / tests).
func (s *TailedNodeStore) TailLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tail)
}

// Tail returns a SNAPSHOT (copy) of the un-tiled node set — the dirty set
// smt.BuildDirtyTiles recurses over to emit only a checkpoint's changed tiles.
// "Committed-but-not-tiled" IS exactly the set of nodes whose tiles still need
// emitting (the retention invariant partitions every committed node into tail OR
// durably-tiled), so it is the correct `dirty` argument. A copy under the read lock,
// so the reconciler walks a stable set while the single writer keeps Put-ing the next
// batch; mutating the returned map never touches the store.
func (s *TailedNodeStore) Tail() map[[32]byte]smt.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[[32]byte]smt.Node, len(s.tail))
	for h, n := range s.tail {
		out[h] = n
	}
	return out
}
