-- 0018_smt_node_index.sql — node → owning-tile-top index (complete-by-hash reads).
--
-- SMT tiles are content-addressed by their TOP node's hash, so the tile store can
-- only fetch a node that is a tile top. A band-INTERIOR reached by a compressed
-- pointer (a branch whose depth jumps a band boundary, so a walk steps
-- parent→interior without ever loading that interior's band top) is therefore not
-- independently fetchable: smt.TiledNodeStore.Get returns a clean miss, which one
-- frame up becomes "missing node (referenced by ancestor)" — the builder demoting
-- a ProcessBatch entry to PathD and dropping its leaf, and the emitter's
-- BuildDirtyTiles stalling on a pruned interior. Both faces resolve through that
-- one Get.
--
-- This table is the completeness backstop: node_hash → the top of the tile whose
-- band contains it. On a Get miss the node store looks up the owning top and
-- fetches THAT tile, so ANY emitted node resolves by hash regardless of walk
-- order. Written at tile-emit time (store.BuildTilesEmitter), BEFORE the tail is
-- pruned, so a node is never evicted from the tail before it is index-resolvable
-- (GC-consistent). Content-addressed ⇒ a (node, top) mapping is immutable, so
-- writes are idempotent (ON CONFLICT DO NOTHING) and the table never needs
-- invalidation.
--
-- NOTE (storage): this is O(non-top tree nodes) rows — the same order as
-- smt_leaves. It re-introduces node-keyed PG state that 0013 dropped, but stores
-- only the 32-byte owning-top pointer per node (not node bytes), and exists solely
-- to make the durable tile store complete. It is gated by LEDGER_NODE_INDEX on the
-- ledger; the read side is a no-op when the table is empty / unconsulted.
CREATE TABLE IF NOT EXISTS smt_node_index (
    node_hash BYTEA PRIMARY KEY, -- 32-byte content hash of an interior node
    tile_top  BYTEA NOT NULL     -- 32-byte top hash of its owning band tile
);
