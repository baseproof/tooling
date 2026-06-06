/*
FILE PATH: store/rotation_archive_source.go

RotationSeqsFromWitnessSets — the PG source that feeds the rotation-index archive
(1.2b). Kept apart from rotation_archive.go so the format/fetcher/writer stay PG-free
and unit-testable; this is the one place that reads the witness_sets table.
*/
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RotationSeqsFromWitnessSets enumerates the witness-rotation log positions
// (effective_seq) from witness_sets, ascending — the stable index the archive writer
// persists and the fetcher rebuilds inclusion proofs over. The genesis set
// (effective_seq 0, no on-log rotation entry) is excluded: it is supplied to the v2
// proof separately (FetchGenesisBootstrap), not as a rotation element.
func RotationSeqsFromWitnessSets(ctx context.Context, db *pgxpool.Pool) ([]uint64, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.Query(ctx, `
		SELECT effective_seq
		  FROM witness_sets
		 WHERE effective_seq > 0
		 ORDER BY effective_seq ASC`)
	if err != nil {
		return nil, fmt.Errorf("store/rotation-archive: enumerate witness_sets: %w", err)
	}
	defer rows.Close()

	var seqs []uint64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("store/rotation-archive: scan effective_seq: %w", err)
		}
		seqs = append(seqs, uint64(s))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/rotation-archive: rows: %w", err)
	}
	return seqs, nil
}

// RotationIndexArchiveJob enumerates the rotation index from witness_sets and writes
// it to the object store — the single operation shared by the post-rotation refresh
// (witnessclient ProcessRotation) and the archive backfill (1.x). Best-effort at
// both call sites: the caller logs the error and never stalls on it.
type RotationIndexArchiveJob struct {
	db     *pgxpool.Pool
	writer *RotationIndexArchiveWriter
}

// NewRotationIndexArchiveJob composes the PG source and the object-store writer. A nil
// db or obj makes ArchiveCurrentIndex a no-op, so it can be wired unconditionally.
func NewRotationIndexArchiveJob(db *pgxpool.Pool, obj objectPutGetter) *RotationIndexArchiveJob {
	return &RotationIndexArchiveJob{db: db, writer: NewRotationIndexArchiveWriter(obj)}
}

// ArchiveCurrentIndex enumerates the current rotation seqs and archives the index.
func (j *RotationIndexArchiveJob) ArchiveCurrentIndex(ctx context.Context) error {
	if j == nil || j.db == nil {
		return nil
	}
	seqs, err := RotationSeqsFromWitnessSets(ctx, j.db)
	if err != nil {
		return err
	}
	return j.writer.ArchiveRotationIndex(ctx, seqs)
}
