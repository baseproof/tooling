/*
FILE PATH: store/indexes/target_root.go

QueryByTargetRoot — one read-page of entries targeting a specific root entity.
*/
package indexes

import (
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store"
)

// targetRootQuery is the keyset query for QueryByTargetRoot. See runIndexQuery
// for the projection + cursor contract; the LIMIT clause is appended there.
const targetRootQuery = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE target_root = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC`

// QueryByTargetRoot returns one read-page of entries whose Target_Root matches
// pos, from sequence startSeq (inclusive), capped at count ([1, MaxScanCount]).
func (q *PostgresQueryAPI) QueryByTargetRoot(pos types.LogPosition, startSeq uint64, count int) ([]types.EntryWithMetadata, error) {
	return q.runIndexQuery(q.ctx, targetRootQuery, store.SerializeLogPosition(pos), startSeq, clampPageCount(count))
}
