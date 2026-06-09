/*
FILE PATH: store/smt_node_index.go

PGNodeIndex — the durable node→owning-tile-top index (migration 0018) that makes
the content-addressed SMT tile store COMPLETE by hash.

SMT tiles are keyed by their TOP node's hash, so the tile store can only fetch a
node that is a tile top. A band-INTERIOR reached by a compressed pointer (a branch
whose depth jumps a band boundary, so a walk steps parent→interior without ever
loading that interior's band top) is not independently fetchable:
smt.TiledNodeStore.Get returns a clean miss, which one frame up becomes "missing
node (referenced by ancestor)" — the builder dropping a leaf (PathD) and the
emitter's BuildDirtyTiles stalling. This index is the completeness backstop the
SDK's smt.NodeIndex consumes on that miss: node_hash → the top of its owning tile,
so Get fetches THAT tile and the interior resolves regardless of walk order.

PRODUCER/CONSUMER:

  - Producer: store.BuildTilesEmitter.EmitDurable calls PutNodes for every
    interior of every tile it makes durable, BEFORE the reconciler prunes the
    tail (GC-consistency: a node is index-resolvable before it can be evicted).
  - Consumer: the builder's and the emitter's TiledNodeStore read-throughs call
    OwningTile on a Get miss (wired in boot when LEDGER_NODE_INDEX is enabled).

Content-addressed ⇒ a (node, top) mapping is immutable, so writes are idempotent
(ON CONFLICT DO NOTHING) and the table never needs invalidation.
*/
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/core/smt"
)

// NodeIndexEntry maps one interior node to the top of its owning band tile.
type NodeIndexEntry struct {
	Node [32]byte
	Top  [32]byte
}

// NodeIndexStore is the durable node→owning-tile-top index as both producer
// (PutNodes, at tile-emit time) and consumer (smt.NodeIndex.OwningTile, on a
// TiledNodeStore.Get miss). PGNodeIndex is the production implementation.
type NodeIndexStore interface {
	smt.NodeIndex // OwningTile(node) (top, ok, err) — the read backstop
	PutNodes(ctx context.Context, entries []NodeIndexEntry) error
}

// PGNodeIndex is the Postgres-backed smt_node_index: node_hash PRIMARY KEY →
// tile_top. Reads are O(log n) PK lookups; writes are idempotent. The read ctx is
// bound at construction because smt.NodeIndex.OwningTile is ctx-free (it serves
// proof replay, which must not block on a threaded ctx) — mirroring
// smt.TiledNodeStore.
type PGNodeIndex struct {
	db  *pgxpool.Pool
	ctx context.Context
}

// NewPGNodeIndex binds the index to a pool and the long-lived ctx its ctx-free
// reads run under.
func NewPGNodeIndex(ctx context.Context, db *pgxpool.Pool) *PGNodeIndex {
	return &PGNodeIndex{db: db, ctx: ctx}
}

// OwningTile returns the tile-top whose band contains node; ok=false when the
// index has no entry (an un-emitted / un-indexed node — a genuine miss, not an
// error). Implements smt.NodeIndex.
func (x *PGNodeIndex) OwningTile(node [32]byte) ([32]byte, bool, error) {
	var top []byte
	err := x.db.QueryRow(x.ctx,
		`SELECT tile_top FROM smt_node_index WHERE node_hash = $1`, node[:]).Scan(&top)
	if errors.Is(err, pgx.ErrNoRows) {
		return [32]byte{}, false, nil
	}
	if err != nil {
		return [32]byte{}, false, fmt.Errorf("store/node-index: lookup %x: %w", node[:8], err)
	}
	if len(top) != 32 {
		return [32]byte{}, false, fmt.Errorf("store/node-index: %x → malformed top (%d bytes)", node[:8], len(top))
	}
	var t [32]byte
	copy(t[:], top)
	return t, true, nil
}

// nodeIndexPutChunk bounds one INSERT's parameter-array length. A band tile holds
// < 2^9 nodes and an emit's dirty set is the checkpoint delta, so chunks are small
// in practice; this only guards a pathological backfill from one huge statement.
const nodeIndexPutChunk = 5000

// PutNodes idempotently records node→top mappings. Called at tile-emit time,
// BEFORE the tail is pruned, so a node is index-resolvable before it can be
// evicted (GC-consistency). ON CONFLICT DO NOTHING: a re-emit of an
// already-durable tile re-asserts the same immutable mappings at no cost.
func (x *PGNodeIndex) PutNodes(ctx context.Context, entries []NodeIndexEntry) error {
	for start := 0; start < len(entries); start += nodeIndexPutChunk {
		end := start + nodeIndexPutChunk
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[start:end]
		nodes := make([][]byte, len(chunk))
		tops := make([][]byte, len(chunk))
		for i := range chunk {
			n, t := chunk[i].Node, chunk[i].Top // copy out of the array fields
			nodes[i] = n[:]
			tops[i] = t[:]
		}
		if _, err := x.db.Exec(ctx,
			`INSERT INTO smt_node_index (node_hash, tile_top)
			 SELECT * FROM unnest($1::bytea[], $2::bytea[])
			 ON CONFLICT (node_hash) DO NOTHING`,
			nodes, tops); err != nil {
			return fmt.Errorf("store/node-index: put %d nodes: %w", len(chunk), err)
		}
	}
	return nil
}

// Compile-time checks: PGNodeIndex is both the SDK read backstop and the
// producer-side store.
var (
	_ smt.NodeIndex  = (*PGNodeIndex)(nil)
	_ NodeIndexStore = (*PGNodeIndex)(nil)
)
