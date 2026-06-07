/*
FILE PATH: store/indexes/signer_did.go

QueryBySignerDID — one read-page of entries signed by a specific DID.
Postgres provides sequence numbers + metadata. EntryReader provides bytes.
*/
package indexes

import (
	"github.com/baseproof/baseproof/types"
)

// signerDIDQuery is the keyset query for QueryBySignerDID. See runIndexQuery
// for the projection + cursor contract; the LIMIT clause is appended there.
const signerDIDQuery = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE signer_did = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC`

// QueryBySignerDID returns one read-page of entries signed by the given DID,
// starting at sequence startSeq (inclusive) and capped at count (clamped to
// [1, MaxScanCount]). Callers walk pages by advancing startSeq past the last
// returned sequence_number.
func (q *PostgresQueryAPI) QueryBySignerDID(did string, startSeq uint64, count int) ([]types.EntryWithMetadata, error) {
	return q.runIndexQuery(q.ctx, signerDIDQuery, did, startSeq, clampPageCount(count))
}
