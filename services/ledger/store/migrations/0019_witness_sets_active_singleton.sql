-- =============================================================================
-- Migration 0019 — enforce the "exactly one active witness set" invariant
-- =============================================================================
--
-- 0014 documented an invariant it never actually enforced. It created:
--
--     CREATE UNIQUE INDEX witness_sets_active
--         ON witness_sets (retired_seq)
--         WHERE retired_seq IS NULL;
--
-- and its comment claimed "exactly one row has retired_seq IS NULL at any
-- moment." But PostgreSQL treats NULLs as DISTINCT in a UNIQUE index, so a
-- unique index keyed on a column that is NULL for every row in the partial set
-- admits an UNBOUNDED number of those rows. The backstop was inert: a regression
-- in ProcessRotation's retire-then-insert (or any direct write) that left two
-- active rows would NOT be rejected, and "the current witness set" — which the
-- cosign quorum and rotation chain are anchored to — would become ambiguous.
--
-- Fix: key the partial unique index on the constant expression
-- (retired_seq IS NULL), which is TRUE for exactly the rows in the partial set.
-- UNIQUE over a single constant value admits at most one such row, so the index
-- now enforces the singleton invariant. The expression form is portable across
-- all supported PostgreSQL versions (no dependency on the PG15 NULLS NOT
-- DISTINCT clause).
--
-- This is an additive correctness fix: no columns change, and a healthy
-- single-active-row table is untouched by the cleanup below.

-- Defensive cleanup: if a deployment accumulated more than one active row while
-- the broken index was in force, retire all but the newest (greatest
-- effective_seq; ctid breaks exact ties) and stamp them retired at the newest
-- set's effective_seq — exactly the row ProcessRotation's retire-then-insert
-- would have kept live. No-op when at most one active row exists.
WITH extra_active AS (
    SELECT ctid
    FROM (
        SELECT ctid,
               row_number() OVER (ORDER BY effective_seq DESC, ctid DESC) AS rn
        FROM witness_sets
        WHERE retired_seq IS NULL
    ) ranked
    WHERE rn > 1
)
UPDATE witness_sets w
SET retired_seq = (
        SELECT max(effective_seq) FROM witness_sets WHERE retired_seq IS NULL
    )
FROM extra_active
WHERE w.ctid = extra_active.ctid;

DROP INDEX IF EXISTS witness_sets_active;

CREATE UNIQUE INDEX witness_sets_active
    ON witness_sets ((retired_seq IS NULL))
    WHERE retired_seq IS NULL;
