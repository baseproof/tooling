// FILE PATH: services/auditor/internal/store/heads_journal.go
//
// PostgresHeadsJournal — the durable production implementation of
// libs/monitoring.HeadsJournal.
//
// Lives in services/auditor/internal/store/ (alongside the gossip
// PostgresStore) because Custody belongs to the auditor by
// Separation-of-Duties (LAW 4 in scripts/dependency-law.sh). The
// JN's verifier consumes this journal via the auditor's gossip
// surface; the JN never persists heads itself.
//
// # Schema
//
//	heads_journal (
//	  log_did         TEXT        NOT NULL,
//	  sequence        BIGINT      NOT NULL,
//	  root_hash       BYTEA       NOT NULL,
//	  smt_root        BYTEA       NOT NULL,
//	  receipt_root    BYTEA       NOT NULL,
//	  signatures      BYTEA       NOT NULL,   -- JSON-encoded []WitnessSignature
//	  canonical_bytes BYTEA       NOT NULL,
//	  lamport_time    BIGINT      NOT NULL,
//	  committed_at    TIMESTAMPTZ NOT NULL,
//	  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
//	  PRIMARY KEY (log_did, sequence, root_hash)
//	)
//
//	heads_journal_burns (
//	  log_did               TEXT        PRIMARY KEY,
//	  burned_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
//	  first_fork_sequence   BIGINT      NOT NULL,
//	  conflicting_roots     BYTEA       NOT NULL    -- JSON-encoded [][32]byte
//	)
//
// Two indexes beyond the primary key:
//
//	heads_journal_log_seq_desc:  (log_did, sequence DESC)
//	  serves HeadAt's "largest sequence ≤ asOf" descending scan.
//
//	heads_journal_log_committed: (log_did, committed_at DESC)
//	  serves HeadAtTime's "largest committed_at ≤ t" descending scan.
//
// The primary key already covers HeadByRootHash and HeadsAtSequence
// lookups via index prefix.
//
// # Retention
//
// NEVER DELETE. The auditor's gossip PruneJob explicitly excludes
// heads_journal — see decision 3 in the network architect's
// specification. ~250M rows × ~150 B ≈ 38 GB over 15 years is
// trivial for production Postgres. The journal is permanent
// cryptographic bedrock; transient gossip evidence prunes
// independently from a different table.
//
// # Concurrency
//
// Equivocation detection requires a read-then-write race-free check
// at the (log_did, sequence) row. We use a per-log_did advisory
// lock — the same shape gossip's PostgresStore uses for chain
// discipline. Distinct logs proceed in parallel.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/monitoring"
)

// PostgresHeadsJournal is the production HeadsJournal backed by
// PostgreSQL. Construct via NewPostgresHeadsJournal; call Migrate
// at boot to ensure the table + indexes exist.
type PostgresHeadsJournal struct {
	db *sql.DB
}

// Static interface conformance — the monitoring.HeadsJournal
// contract is enforced at build time.
var _ monitoring.HeadsJournal = (*PostgresHeadsJournal)(nil)

// NewPostgresHeadsJournal wraps an open pool. The store does NOT
// take ownership of the pool — the caller (typically the auditor
// boot wire) owns it and shares it with the gossip PostgresStore.
func NewPostgresHeadsJournal(db *sql.DB) (*PostgresHeadsJournal, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: nil *sql.DB", ErrInvalidConfig)
	}
	return &PostgresHeadsJournal{db: db}, nil
}

// schemaSQLHeadsJournal creates the heads_journal + heads_journal_burns
// tables + the two reach indexes. Idempotent (IF NOT EXISTS).
const schemaSQLHeadsJournal = `
CREATE TABLE IF NOT EXISTS heads_journal (
    log_did         TEXT        NOT NULL,
    sequence        BIGINT      NOT NULL,
    root_hash       BYTEA       NOT NULL,
    smt_root        BYTEA       NOT NULL,
    receipt_root    BYTEA       NOT NULL,
    signatures      BYTEA       NOT NULL,
    canonical_bytes BYTEA       NOT NULL,
    lamport_time    BIGINT      NOT NULL,
    committed_at    TIMESTAMPTZ NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (log_did, sequence, root_hash)
);
CREATE INDEX IF NOT EXISTS heads_journal_log_seq_desc
    ON heads_journal (log_did, sequence DESC);
CREATE INDEX IF NOT EXISTS heads_journal_log_committed
    ON heads_journal (log_did, committed_at DESC);

CREATE TABLE IF NOT EXISTS heads_journal_burns (
    log_did               TEXT        PRIMARY KEY,
    burned_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_fork_sequence   BIGINT      NOT NULL,
    conflicting_roots     BYTEA       NOT NULL
);`

// Migrate creates the heads_journal + heads_journal_burns tables +
// indexes if absent. Idempotent; safe to call on every boot.
func (j *PostgresHeadsJournal) Migrate(ctx context.Context) error {
	if _, err := j.db.ExecContext(ctx, schemaSQLHeadsJournal); err != nil {
		return fmt.Errorf("heads_journal: migrate: %w", err)
	}
	return nil
}

// Record implements monitoring.HeadsJournal.
//
// Atomicity:
//  1. Per-log_did advisory lock (xact-scoped, auto-released on
//     commit/rollback). Distinct logs proceed in parallel.
//  2. Idempotence check on (log_did, sequence, root_hash) — exact
//     duplicate is a no-op.
//  3. Existence check on (log_did, sequence, *) for OTHER root —
//     equivocation signal + conflicting-root capture.
//  4. INSERT the new row.
//  5. If equivocation AND not already burned: INSERT into
//     heads_journal_burns to record the transition.
//
// The whole sequence runs in a single transaction. A crash midway
// rolls back cleanly — no half-burn states.
func (j *PostgresHeadsJournal) Record(ctx context.Context, head monitoring.Head) (monitoring.RecordVerdict, error) {
	if err := monitoring.ValidateForRecord(head); err != nil {
		return monitoring.RecordVerdict{}, err
	}
	if head.RecordedAt.IsZero() {
		head.RecordedAt = time.Now().UTC()
	}

	sigBytes, err := json.Marshal(head.Signatures)
	if err != nil {
		return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: marshal signatures: %w", err)
	}

	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Per-log critical section.
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1))`, head.LogDID); err != nil {
		return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: advisory lock: %w", err)
	}

	// Idempotence: exact (log_did, sequence, root_hash) duplicate
	// is a no-op. Returns Equivocation:true if the log was
	// already burned (a re-publish of an already-known fork
	// member during recovery is still equivocation evidence).
	var dupExists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(
		     SELECT 1 FROM heads_journal
		     WHERE log_did = $1 AND sequence = $2 AND root_hash = $3
		 )`,
		head.LogDID, int64(head.TreeSize), head.RootHash[:]).Scan(&dupExists); err != nil {
		return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: dup check: %w", err)
	}
	if dupExists {
		burned, _, err := j.queryBurnStatusLocked(ctx, tx, head.LogDID)
		if err != nil {
			return monitoring.RecordVerdict{}, err
		}
		if err := tx.Commit(); err != nil {
			return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: commit dup: %w", err)
		}
		return monitoring.RecordVerdict{Persisted: false, Equivocation: burned}, nil
	}

	// Equivocation check: ANY other root at (log_did, sequence)?
	// If so, capture the FIRST conflicting root for the verdict.
	var conflictingRootBytes []byte
	row := tx.QueryRowContext(ctx,
		`SELECT root_hash FROM heads_journal
		 WHERE log_did = $1 AND sequence = $2
		 LIMIT 1`,
		head.LogDID, int64(head.TreeSize))
	switch err := row.Scan(&conflictingRootBytes); {
	case errors.Is(err, sql.ErrNoRows):
		conflictingRootBytes = nil
	case err != nil:
		return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: equivocation check: %w", err)
	}
	equivocation := len(conflictingRootBytes) > 0

	// INSERT the new row.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO heads_journal (
		     log_did, sequence, root_hash, smt_root, receipt_root,
		     signatures, canonical_bytes, lamport_time, committed_at, recorded_at
		 ) VALUES (
		     $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		 )`,
		head.LogDID,
		int64(head.TreeSize),
		head.RootHash[:],
		head.SMTRoot[:],
		head.ReceiptRoot[:],
		sigBytes,
		head.CanonicalBytes,
		int64(head.LamportTime),
		head.CommittedAt.UTC(),
		head.RecordedAt.UTC(),
	); err != nil {
		return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: insert: %w", err)
	}

	// Burn-transition: if equivocation AND not already burned,
	// INSERT into heads_journal_burns.
	burnTransition := false
	if equivocation {
		alreadyBurned, _, err := j.queryBurnStatusLocked(ctx, tx, head.LogDID)
		if err != nil {
			return monitoring.RecordVerdict{}, err
		}
		if !alreadyBurned {
			rootsBytes, _ := json.Marshal([][]byte{conflictingRootBytes, head.RootHash[:]})
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO heads_journal_burns (
				     log_did, burned_at, first_fork_sequence, conflicting_roots
				 ) VALUES ($1, $2, $3, $4)
				 ON CONFLICT (log_did) DO NOTHING`,
				head.LogDID,
				head.RecordedAt.UTC(),
				int64(head.TreeSize),
				rootsBytes,
			); err != nil {
				return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: insert burn: %w", err)
			}
			burnTransition = true
		}
	}

	if err := tx.Commit(); err != nil {
		return monitoring.RecordVerdict{}, fmt.Errorf("heads_journal: commit: %w", err)
	}

	var conflicting [32]byte
	if len(conflictingRootBytes) == 32 {
		copy(conflicting[:], conflictingRootBytes)
	}
	return monitoring.RecordVerdict{
		Persisted:       true,
		Equivocation:    equivocation,
		BurnTransition:  burnTransition,
		ConflictingRoot: conflicting,
	}, nil
}

// HeadAt implements monitoring.HeadsJournal.
func (j *PostgresHeadsJournal) HeadAt(ctx context.Context, logDID string, asOfSequence uint64) (monitoring.Head, error) {
	burned, err := j.burnedQuick(ctx, logDID)
	if err != nil {
		return monitoring.Head{}, err
	}
	if burned {
		return monitoring.Head{}, monitoring.ErrEquivocatedLog
	}
	return j.scanOneRow(ctx,
		`SELECT log_did, sequence, root_hash, smt_root, receipt_root,
		        signatures, canonical_bytes, lamport_time, committed_at, recorded_at
		 FROM heads_journal
		 WHERE log_did = $1 AND sequence <= $2
		 ORDER BY sequence DESC
		 LIMIT 1`,
		logDID, int64(asOfSequence))
}

// HeadAtTime implements monitoring.HeadsJournal.
func (j *PostgresHeadsJournal) HeadAtTime(ctx context.Context, logDID string, t time.Time) (monitoring.Head, error) {
	burned, err := j.burnedQuick(ctx, logDID)
	if err != nil {
		return monitoring.Head{}, err
	}
	if burned {
		return monitoring.Head{}, monitoring.ErrEquivocatedLog
	}
	return j.scanOneRow(ctx,
		`SELECT log_did, sequence, root_hash, smt_root, receipt_root,
		        signatures, canonical_bytes, lamport_time, committed_at, recorded_at
		 FROM heads_journal
		 WHERE log_did = $1 AND committed_at <= $2
		 ORDER BY committed_at DESC
		 LIMIT 1`,
		logDID, t.UTC())
}

// HeadByRootHash implements monitoring.HeadsJournal. Works on
// burned logs — forensic retrieval bypasses the burn check.
func (j *PostgresHeadsJournal) HeadByRootHash(ctx context.Context, logDID string, sequence uint64, rootHash [32]byte) (monitoring.Head, error) {
	return j.scanOneRow(ctx,
		`SELECT log_did, sequence, root_hash, smt_root, receipt_root,
		        signatures, canonical_bytes, lamport_time, committed_at, recorded_at
		 FROM heads_journal
		 WHERE log_did = $1 AND sequence = $2 AND root_hash = $3`,
		logDID, int64(sequence), rootHash[:])
}

// HeadsAtSequence implements monitoring.HeadsJournal. Works on
// burned logs — forensic retrieval bypasses the burn check.
func (j *PostgresHeadsJournal) HeadsAtSequence(ctx context.Context, logDID string, sequence uint64) ([]monitoring.Head, error) {
	rows, err := j.db.QueryContext(ctx,
		`SELECT log_did, sequence, root_hash, smt_root, receipt_root,
		        signatures, canonical_bytes, lamport_time, committed_at, recorded_at
		 FROM heads_journal
		 WHERE log_did = $1 AND sequence = $2
		 ORDER BY recorded_at ASC`,
		logDID, int64(sequence))
	if err != nil {
		return nil, fmt.Errorf("heads_journal: HeadsAtSequence: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []monitoring.Head
	for rows.Next() {
		h, err := scanHead(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("heads_journal: HeadsAtSequence rows: %w", err)
	}
	return out, nil
}

// LatestHead implements monitoring.HeadsJournal.
func (j *PostgresHeadsJournal) LatestHead(ctx context.Context, logDID string) (monitoring.Head, error) {
	burned, err := j.burnedQuick(ctx, logDID)
	if err != nil {
		return monitoring.Head{}, err
	}
	if burned {
		return monitoring.Head{}, monitoring.ErrEquivocatedLog
	}
	return j.scanOneRow(ctx,
		`SELECT log_did, sequence, root_hash, smt_root, receipt_root,
		        signatures, canonical_bytes, lamport_time, committed_at, recorded_at
		 FROM heads_journal
		 WHERE log_did = $1
		 ORDER BY sequence DESC
		 LIMIT 1`,
		logDID)
}

// BurnStatus implements monitoring.HeadsJournal.
func (j *PostgresHeadsJournal) BurnStatus(ctx context.Context, logDID string) (monitoring.BurnStatus, error) {
	var burnedAt time.Time
	var firstFork int64
	var rootsBytes []byte
	err := j.db.QueryRowContext(ctx,
		`SELECT burned_at, first_fork_sequence, conflicting_roots
		 FROM heads_journal_burns
		 WHERE log_did = $1`,
		logDID).Scan(&burnedAt, &firstFork, &rootsBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return monitoring.BurnStatus{}, nil
	}
	if err != nil {
		return monitoring.BurnStatus{}, fmt.Errorf("heads_journal: burn status: %w", err)
	}
	var rawRoots [][]byte
	if err := json.Unmarshal(rootsBytes, &rawRoots); err != nil {
		return monitoring.BurnStatus{}, fmt.Errorf("heads_journal: burn roots decode: %w", err)
	}
	out := monitoring.BurnStatus{
		Burned:            true,
		BurnedAt:          burnedAt,
		FirstForkSequence: uint64(firstFork),
		ConflictingRoots:  make([][32]byte, 0, len(rawRoots)),
	}
	for _, r := range rawRoots {
		var root [32]byte
		copy(root[:], r)
		out.ConflictingRoots = append(out.ConflictingRoots, root)
	}
	return out, nil
}

// burnedQuick returns whether the log is burned, using a read-only
// single-row lookup. Cheap because heads_journal_burns is keyed by
// log_did.
func (j *PostgresHeadsJournal) burnedQuick(ctx context.Context, logDID string) (bool, error) {
	var exists bool
	if err := j.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM heads_journal_burns WHERE log_did = $1)`,
		logDID).Scan(&exists); err != nil {
		return false, fmt.Errorf("heads_journal: burn check: %w", err)
	}
	return exists, nil
}

// queryBurnStatusLocked checks burn status WITHIN an open tx so the
// per-log advisory lock makes the check + insert atomic. Returns
// (burned, burnedAt, error). Used only by Record's burn-transition
// path.
func (j *PostgresHeadsJournal) queryBurnStatusLocked(ctx context.Context, tx *sql.Tx, logDID string) (bool, time.Time, error) {
	var burnedAt time.Time
	err := tx.QueryRowContext(ctx,
		`SELECT burned_at FROM heads_journal_burns WHERE log_did = $1`,
		logDID).Scan(&burnedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, fmt.Errorf("heads_journal: locked burn check: %w", err)
	}
	return true, burnedAt, nil
}

// scanOneRow runs the supplied SELECT, returns the single Head, or
// ErrNoHead if zero rows.
func (j *PostgresHeadsJournal) scanOneRow(ctx context.Context, q string, args ...any) (monitoring.Head, error) {
	row := j.db.QueryRowContext(ctx, q, args...)
	return scanHeadRow(row)
}

// rowScanner abstracts *sql.Row and *sql.Rows for shared scanHead.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanHeadRow(r *sql.Row) (monitoring.Head, error) {
	h, err := scanHead(r)
	if errors.Is(err, sql.ErrNoRows) {
		return monitoring.Head{}, monitoring.ErrNoHead
	}
	return h, err
}

func scanHead(r rowScanner) (monitoring.Head, error) {
	var (
		logDID                            string
		sequence, lamport                 int64
		rootHashB, smtRootB, receiptRootB []byte
		sigBytes, canonicalBytes          []byte
		committedAt, recordedAt           time.Time
	)
	if err := r.Scan(&logDID, &sequence, &rootHashB, &smtRootB, &receiptRootB,
		&sigBytes, &canonicalBytes, &lamport, &committedAt, &recordedAt); err != nil {
		return monitoring.Head{}, err
	}
	var sigs []types.WitnessSignature
	if err := json.Unmarshal(sigBytes, &sigs); err != nil {
		return monitoring.Head{}, fmt.Errorf("heads_journal: decode signatures: %w", err)
	}
	var root, smt, receipt [32]byte
	copy(root[:], rootHashB)
	copy(smt[:], smtRootB)
	copy(receipt[:], receiptRootB)
	return monitoring.Head{
		LogDID: logDID,
		TreeHead: types.TreeHead{
			RootHash:    root,
			SMTRoot:     smt,
			ReceiptRoot: receipt,
			TreeSize:    uint64(sequence),
		},
		Signatures:     sigs,
		CanonicalBytes: canonicalBytes,
		LamportTime:    uint64(lamport),
		CommittedAt:    committedAt,
		RecordedAt:     recordedAt,
	}, nil
}
