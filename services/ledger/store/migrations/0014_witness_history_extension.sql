-- =============================================================================
-- Migration 0014 — witness_sets history extension (Part II.2)
-- =============================================================================
--
-- Extends the witness_sets table from a "latest-set cache" to a full audit
-- history with content-addressable lookup and live/retired classification.
-- Enables three new public endpoints (II.1):
--   GET /v1/network/witnesses/current     — partial-index O(1)
--   GET /v1/network/witnesses/{set_hash}  — unique-index O(1)
--   GET /v1/network/witnesses/at/{seq}    — range scan (effective_seq, retired_seq)
--
-- Schema changes (additive; no column drops):
--
--   set_hash                 — semantically RE-INTERPRETED from "the OLD
--                              set's hash (rotation authorization anchor)"
--                              to "the HASH OF THIS ROW'S keys_json"
--                              (content-addressable identity per
--                              baseproof/crypto/cosign.SetHash, SDK §I.3).
--                              The hash function is SHA-256(JCS({
--                                  network_id, quorum_k, witnesses[]
--                              })).
--   effective_seq BIGINT     — log's tree_size at the moment this set
--                              became active. 0 for the genesis baseline
--                              (no rotation produced it; loaded from
--                              config at boot).
--   retired_seq BIGINT       — log's tree_size when this set was retired.
--                              NULL = currently active. Exactly ONE row
--                              has retired_seq IS NULL at any moment.
--   rotation_event_id BYTEA  — EventID of the WitnessRotation gossip event
--                              that authorized this row (NULL for genesis
--                              baseline; populated by ProcessRotation
--                              when the emitter exposes the SignedEvent).
--
-- Indexes added:
--   witness_sets_active     — PARTIAL on (retired_seq) WHERE retired_seq
--                              IS NULL. O(1) lookup of the current set.
--                              ~1 row over the lifetime of the partial
--                              predicate.
--   witness_sets_set_hash   — UNIQUE on (set_hash). O(1) historical
--                              lookup by content-addressable identity.
--                              ~100 rows over 20 years.
--   witness_sets_effective  — on (effective_seq). Range-scan support
--                              for "set active at seq N" queries.
--
-- DATA SEMANTICS — PRE-LAUNCH RESET
--
-- Existing rows (if any) hold set_hash under the OLD interpretation
-- (rotation anchor, not row identity). A UNIQUE constraint on set_hash
-- under the NEW interpretation would CONFLICT with existing data;
-- worse, leaving the old interpretation in place would silently make
-- the new content-addressable endpoints return wrong results.
--
-- We follow the discipline of migration 0011 (wipe-pre-v1.14): the
-- network is pre-launch, witness rotations are a source-of-truth on the
-- gossip log and reconstruct on demand, and the table is intentionally
-- mutable (excluded from store/append_only_guard_test.go). DELETE
-- existing rows; LoadCurrentSet then falls back to the genesis config
-- (witnessclient/rotation_handler.go:LoadCurrentSet → genesis path
-- in cmd/ledger/boot/wire/gossip.go), which stamps the canonical
-- v1.3 SetHash interpretation for free.
--
-- This DELETE is idempotent: a re-run on an empty table is a no-op.
-- Production deployments past v1.3 launch must adopt this migration
-- BEFORE accepting their first rotation; the new INSERT path
-- (witnessclient/rotation_handler.go ProcessRotation) populates the
-- new columns under the new semantic.
-- =============================================================================

DELETE FROM witness_sets;

ALTER TABLE witness_sets
    ADD COLUMN effective_seq     BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN retired_seq       BIGINT,
    ADD COLUMN rotation_event_id BYTEA;

-- Partial index — O(1) "current set" lookup. ~1 row matches at any
-- moment; the index file footprint is negligible.
CREATE UNIQUE INDEX witness_sets_active
    ON witness_sets (retired_seq)
    WHERE retired_seq IS NULL;

-- Unique index on set_hash — content-addressable lookup.
-- ~100 rows over 20 years; the unique constraint enforces the
-- v1.3 contract that set_hash IS the row's identity.
CREATE UNIQUE INDEX witness_sets_set_hash
    ON witness_sets (set_hash);

-- Range-scan support for "set active at seq N" queries
-- (GET /v1/network/witnesses/at/{seq}).
CREATE INDEX witness_sets_effective
    ON witness_sets (effective_seq);
