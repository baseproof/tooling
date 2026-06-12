-- =============================================================================
-- Migration 0020 — anchor-source projection column + partial covering index
-- =============================================================================
--
-- WHY (PR-4c, the parent-side half of the anchoring WHERE design):
--
-- When this log acts as a PARENT — admitting BP-ENTRY-ANCHOR-COSIGNED-HEAD-V1
-- entries by which a CHILD network anchors its cosigned heads here — nothing in
-- entry_index records WHICH child an anchor entry belongs to. The anchor's
-- SourceLogDID lives only inside the domain payload, so "every anchor of child
-- X" is an O(log) payload scan. That blocks the two consumers the WHERE design
-- introduces: the child publisher's read-back (closing its 202-and-forget) and
-- the auditor's forensic feed (by-source → inclusion-verified entries →
-- verifier.AnchorEvidence).
--
-- source_log_did is a DISCOVERY projection, not authority: it is extracted at
-- sequencing time from the entry's own payload (store.AnchorSourceLogDID), and
-- a verifier trusts only what the payload + inclusion proof + parent quorum
-- establish. A missing/NULL projection therefore fails toward ALARM (the feed
-- finds nothing, the monitor degrades toward Critical) — never toward false
-- compliance. Rows whose payload is not a cosigned anchor carry NULL.
--
-- The index follows the 0017 covering discipline: partial (only anchor rows —
-- the overwhelming majority of entries are NOT anchors, so the index stays
-- proportional to anchors, not entries), keyed for the keyset cursor
-- (source_log_did, sequence_number ASC), INCLUDE-ing exactly the projection
-- the shared runIndexQuery scans (log_time, canonical_hash) so a read page is
-- index-only and pre-sorted: O(page), not O(matches).
--
-- Existing rows predate the projection and are left NULL here. entry_index is
-- APPEND-ONLY (H4 code guard + F2 DB grants), so there is no UPDATE-based
-- backfill by design: the retrofit path is the existing administrator rebuild
-- (cmd/rebuild-projection), which re-derives every entry_index row from the
-- durable tiles through recovery.entryRowFor — the same one-home extraction
-- the sequencer uses — and therefore projects this column for historical
-- anchors as a side effect of the standard DR flow. (With no legacy networks
-- in production, the forward path covers reality; the rebuild covers DR.)

ALTER TABLE entry_index ADD COLUMN IF NOT EXISTS source_log_did TEXT;

CREATE INDEX IF NOT EXISTS idx_anchor_source
    ON entry_index (source_log_did, sequence_number ASC)
    INCLUDE (log_time, canonical_hash)
    WHERE source_log_did IS NOT NULL;
