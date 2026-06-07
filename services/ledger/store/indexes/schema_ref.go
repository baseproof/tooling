/*
FILE PATH: store/indexes/schema_ref.go

QueryBySchemaRef — every entry governed by a specific schema (unbounded full
scan, for internal resolvers). QueryBySchemaRefPage — one read-page, for the
HTTP read endpoint.
*/
package indexes

import (
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store"
)

// schemaRefQuery is the keyset query shared by QueryBySchemaRef (full scan,
// limit 0) and QueryBySchemaRefPage (bounded). See runIndexQuery for the
// projection + cursor contract; LIMIT is appended there only when limit > 0.
const schemaRefQuery = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE schema_ref = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC`

// QueryBySchemaRef returns EVERY entry referencing the given schema position,
// ordered by sequence_number ASC — the unbounded full scan the custody chain
// reconstruction (custody/query_source.go) and the admission authority/policy
// resolvers (cmd/ledger boot) require: they fetch all schema entries and filter
// in-memory on a sub-field (ContentDigest / record identity) the entry_index
// does not column. This path is NOT read-cost-bounded by design; cache at the
// resolver layer if the scan cost matters. The HTTP read endpoint uses
// QueryBySchemaRefPage instead.
func (q *PostgresQueryAPI) QueryBySchemaRef(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	return q.runIndexQuery(q.ctx, schemaRefQuery, store.SerializeLogPosition(pos), 0, 0)
}

// QueryBySchemaRefPage returns one read-page of entries referencing pos, from
// sequence startSeq (inclusive), capped at count ([1, MaxScanCount]). Backs
// GET /v1/query/schema_ref/{pos}; the unbounded sibling QueryBySchemaRef is for
// internal resolvers only.
func (q *PostgresQueryAPI) QueryBySchemaRefPage(pos types.LogPosition, startSeq uint64, count int) ([]types.EntryWithMetadata, error) {
	return q.runIndexQuery(q.ctx, schemaRefQuery, store.SerializeLogPosition(pos), startSeq, clampPageCount(count))
}
