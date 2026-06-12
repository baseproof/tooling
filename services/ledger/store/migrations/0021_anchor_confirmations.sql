-- =============================================================================
-- Migration 0021 — anchor_confirmations: the durable read-back record
-- =============================================================================
--
-- WHY (PR-4b, the child-side half of the anchoring WHERE design):
--
-- The anchor publisher was fire-and-forget: SubmitToHTTPEndpoint demands a
-- 202 and learns nothing — the child never knew whether its anchor LANDED in
-- the parent log, at what position, or when. This table is the durable
-- CONFIRMATION: one row per (parent log, anchored head), written when the
-- read-back finds the anchor via the parent's by-source discovery page and
-- reads it back through the parent's trust root.
--
-- NAMED anchor_confirmations, not *receipts*: the ledger already has receipt
-- roots, receipt proofs, and receipt_archive_* — three meanings of "receipt".
-- A fourth would blur census greps and operator vocabulary.
--
-- VERIFIED_AT IS FIRST-SEEN, IMMUTABLE. It feeds the verifier's freshness
-- floor min(AnchoredAt, VerifiedAt): if re-observation could refresh it, a
-- single stale anchor re-polled every cycle would read permanently fresh —
-- the lazy-fresh hole through the back door. Enforced three ways:
--   1. the PRIMARY KEY makes re-observation an INSERT conflict;
--   2. the store writes with ON CONFLICT DO NOTHING and returns the STORED
--      verified_at (RecordFirstSeen);
--   3. the table is in the H4 append-only guard list — application code
--      containing UPDATE/DELETE/TRUNCATE against it fails the build (and F2
--      grants deny it at the DB role).
--
-- parent_network_id is the WHICH (the parent's constitutional identity),
-- nullable in the env-config era — the 4d derivation chain (constitutional
-- Targets → declaration endpoints) always knows it and fills it; rows
-- confirmed before that carry NULL, honestly.

CREATE TABLE IF NOT EXISTS anchor_confirmations (
    parent_log_did     TEXT        NOT NULL,
    tree_head_ref      TEXT        NOT NULL,
    parent_network_id  BYTEA,
    parent_seq         BIGINT      NOT NULL,
    anchored_tree_size BIGINT      NOT NULL,
    anchored_at        TIMESTAMPTZ,
    verified_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (parent_log_did, tree_head_ref)
);

COMMENT ON COLUMN anchor_confirmations.tree_head_ref IS
    '64-hex network-bound digest (cosign.TreeHeadDigest) of THIS log''s anchored head';
COMMENT ON COLUMN anchor_confirmations.verified_at IS
    'FIRST successful read-back observation; immutable (H4 + ON CONFLICT DO NOTHING)';

-- Latest-per-parent reads (the /v1/network/anchors chain + monitors).
CREATE INDEX IF NOT EXISTS idx_anchor_confirmations_latest
    ON anchor_confirmations (parent_log_did, verified_at DESC);
