/*
FILE PATH: store/indexes/cosignature_of.go

QueryByCosignatureOf — certification-required per governance spec.
Returns one read-page of entries whose Cosignature_Of field matches the
given position.
*/
package indexes

import (
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store"
)

// cosignatureOfQuery is the keyset query for QueryByCosignatureOf. See
// runIndexQuery for the projection + cursor contract; LIMIT is appended there.
const cosignatureOfQuery = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE cosignature_of = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC`

// QueryByCosignatureOf returns one read-page of entries whose Cosignature_Of
// matches pos, from sequence startSeq (inclusive), capped at count
// ([1, MaxScanCount]).
func (q *PostgresQueryAPI) QueryByCosignatureOf(pos types.LogPosition, startSeq uint64, count int) ([]types.EntryWithMetadata, error) {
	return q.runIndexQuery(q.ctx, cosignatureOfQuery, store.SerializeLogPosition(pos), startSeq, clampPageCount(count))
}
