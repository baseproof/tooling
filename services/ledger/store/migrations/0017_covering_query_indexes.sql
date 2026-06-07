-- 0017_covering_query_indexes.sql — Phase 2, 2.3 (read-cost bounding).
--
-- The QueryBy{SignerDID,TargetRoot,SchemaRef,CosignatureOf} endpoints run
--   SELECT sequence_number, log_time, canonical_hash
--   FROM entry_index WHERE <col> = $1 ORDER BY sequence_number ASC [keyset LIMIT]
-- The original single-column indexes (0001) force a heap fetch per row plus a sort.
-- These COMPOUND COVERING indexes — (<col>, sequence_number) INCLUDE (log_time,
-- canonical_hash) — serve the WHERE, the ORDER BY, and the projection index-only and
-- pre-sorted: O(page) with no heap fetch and no sort, and the keyset cursor
-- (sequence_number > $2) seeks straight to the next page.
--
-- ADDITIVE: the compound index's leading column subsumes every <col> = $1 lookup the
-- single-column index served, so the originals are now redundant and can be dropped
-- in a later CONCURRENTLY migration (E3) once verified unused — this migration adds
-- only, to stay zero-downtime here.

CREATE INDEX IF NOT EXISTS idx_signer_did_seq
    ON entry_index (signer_did, sequence_number) INCLUDE (log_time, canonical_hash);

CREATE INDEX IF NOT EXISTS idx_target_root_seq
    ON entry_index (target_root, sequence_number) INCLUDE (log_time, canonical_hash)
    WHERE target_root IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cosignature_of_seq
    ON entry_index (cosignature_of, sequence_number) INCLUDE (log_time, canonical_hash)
    WHERE cosignature_of IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_schema_ref_seq
    ON entry_index (schema_ref, sequence_number) INCLUDE (log_time, canonical_hash)
    WHERE schema_ref IS NOT NULL;
