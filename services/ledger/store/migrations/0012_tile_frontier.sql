-- =============================================================================
-- Migration 0012 — tile_frontier singleton table (the Tile Clock)
-- =============================================================================
--
-- Purpose: a DURABLE watermark for SMT tile durability, decoupled from the
-- commit cursor (smt_root_state.committed_through_seq, the Commit Clock).
--
--   committed_through_seq  — highest seq whose SMT NODES are durable in PG
--                            (advanced in the commit tx by the builder).
--   tile_frontier (here)   — highest seq whose SMT TILES are durable in the
--                            object store (advanced by the reconciler ONLY
--                            after a PUT-ack/fsync).
--
-- The published cosigned-checkpoint horizon is gated on tile_frontier, so a
-- published root never advertises an SMTRoot whose tiles are missing:
--
--   published root  ⟸  tile_frontier_root (tiles durable)  ⟸  committed root (nodes durable)
--
-- Why a SEPARATE row from smt_root_state: the two are written by DIFFERENT
-- owners — the builder's commit tx writes smt_root_state; the async reconciler
-- writes tile_frontier. Co-locating them would make two writers contend on one
-- row. And recovery is exact: on boot the reconciler reads tile_frontier and
-- re-emits the precise gap up to the committed root — no stranded tiles, no
-- permanent holes, bounded by the gap (never the whole tree).
--
-- Singleton pattern (id = 1 + CHECK), mirroring smt_root_state / builder_cursor:
-- one row, never DELETEd, only UPDATEd. Seeded with the Jellyfish empty-tree
-- root (sha256("") — see migration 0003) at seq 0, so at genesis
-- tile_frontier_root == smt_root_state.current_root and the reconciler is idle
-- until the first batch commits.

CREATE TABLE IF NOT EXISTS tile_frontier (
    id                  SMALLINT PRIMARY KEY DEFAULT 1
        CONSTRAINT tile_frontier_singleton CHECK (id = 1),
    frontier_root       BYTEA NOT NULL
        CONSTRAINT tile_frontier_root_size CHECK (octet_length(frontier_root) = 32),
    frontier_seq        BIGINT NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tile_frontier (id, frontier_root, frontier_seq)
VALUES (
    1,
    -- Jellyfish empty-tree root sha256("") — matches smt_root_state after 0003.
    decode('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'),
    0
)
ON CONFLICT (id) DO NOTHING;
