-- 0016_artifact_reservations.sql — ledger#193 Phase 4.
--
-- The staging table for the RESERVE -> token -> UPLOAD -> FINISH protocol. A row
-- is created (pending_upload) when admission accepts an artifact genesis entry
-- and accounting clears; it advances to committed only at FINISH (bytes present
-- + validated), or to a terminal expired/rejected. The CID lives forever on the
-- log; this table is transient staging state, rebuildable, and reaped.
--
-- Keyed by artifact_cid (the content address, known synchronously at submission),
-- NOT by entry sequence: the artifact-genesis entry's sequence is assigned
-- asynchronously by the sequencer, after the submission handler has already
-- staged the reservation and returned the upload token.

CREATE TABLE IF NOT EXISTS artifact_reservations (
    artifact_cid   TEXT PRIMARY KEY,
    content_digest TEXT        NOT NULL DEFAULT '',
    mime_type      TEXT        NOT NULL DEFAULT '',
    max_size       BIGINT      NOT NULL DEFAULT 0,
    owner          TEXT        NOT NULL DEFAULT '',
    status         TEXT        NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The reaper's work-set query: non-terminal rows past their expiry.
CREATE INDEX IF NOT EXISTS idx_artifact_reservations_reap
    ON artifact_reservations (status, expires_at);
