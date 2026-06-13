-- =============================================================================
-- Migration 0022 — entry-kind projection column + partial covering index
-- =============================================================================
--
-- WHY (PRE-11/M7, baseproof/tooling#114 Phase A):
--
-- The AuthoritativeResolver needs the LATEST schema-declaration entry per kind
-- to derive its five schema positions from the log itself (instead of the
-- dormant LEDGER_*_SCHEMA env vars). Nothing in entry_index records an entry's
-- payload KIND today, so "the latest BP-ENTRY-SCHEMA-SHARD-GENESIS-V1" is an
-- unbounded full-log scan — a boot-budget violation at 10M entries/day. This
-- column makes it one index seek.
--
-- kind is a DISCOVERY projection, not authority: it is the entry payload's own
-- `kind` discriminator, extracted at sequencing time from the one extraction
-- home (store.EntryKindProjection), bounded to the SDK's closed kinds.AllEntryKinds()
-- set so a garbage discriminator projects nothing. Everything trust-bearing
-- (the declaration's content, its validity) is re-established by the consumer
-- from the entry bytes; a missing/NULL projection therefore fails toward the
-- resolver finding no declaration (the env canary or boot-refusal path), never
-- toward a forged one. Rows whose payload carries no recognized kind carry NULL.
--
-- The index follows the 0017/0020 covering discipline: partial (only
-- recognized-kind rows; most entries in a busy log are domain payloads without
-- a platform `kind`, so the index stays proportional to platform entries),
-- keyed (kind, sequence_number ASC) so BOTH a keyset page AND the latest-per-kind
-- seek (ORDER BY sequence_number DESC LIMIT 1, served by the same btree in
-- reverse) are index-only, INCLUDE-ing exactly the projection the shared
-- runIndexQuery scans (log_time, canonical_hash).
--
-- Existing rows predate the projection and are left NULL here. entry_index is
-- APPEND-ONLY (H4 code guard + F2 DB grants), so there is no UPDATE-based
-- backfill by design: the retrofit path is the existing administrator rebuild
-- (cmd/rebuild-projection), which re-derives every entry_index row from the
-- durable tiles through recovery.entryRowFor — the same one-home extraction the
-- sequencer uses — and therefore projects this column for historical entries as
-- a side effect of the standard DR flow. (This mirrors migration 0020's
-- source_log_did retrofit exactly.)

ALTER TABLE entry_index ADD COLUMN IF NOT EXISTS kind TEXT;

CREATE INDEX IF NOT EXISTS idx_entry_kind
    ON entry_index (kind, sequence_number ASC)
    INCLUDE (log_time, canonical_hash)
    WHERE kind IS NOT NULL;
