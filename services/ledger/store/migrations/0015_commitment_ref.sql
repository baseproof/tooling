-- 0015_commitment_ref.sql — ledger#193 Phase 2 (closes #190).
--
-- The derivation-commitment publisher now emits a content-addressed
-- storage.SMTDerivationCommitmentRef instead of inlining the full mutation set:
-- the mutations move off-log into the artifact store (addressed by CID) and the
-- on-log commentary entry becomes O(1) (~431 B), so it can never exceed the
-- 65,535-byte envelope cap (the #190 422 overflow). The lookup table follows —
-- it stores the mutations CID + count, not the bulk JSON. Hard cutover: there
-- are no back-compat consumers, and the table is a rebuildable index (the bulk
-- is reconstructable from entries / fetchable by CID).

ALTER TABLE derivation_commitments
    ADD COLUMN IF NOT EXISTS mutations_cid  TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS mutation_count BIGINT NOT NULL DEFAULT 0;

ALTER TABLE derivation_commitments
    DROP COLUMN IF EXISTS mutations_json;
