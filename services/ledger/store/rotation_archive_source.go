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
