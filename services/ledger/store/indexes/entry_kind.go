/*
FILE PATH: store/indexes/entry_kind.go

QueryByKind — every entry of a given payload kind (keyset page), for the
AuthoritativeResolver's schema-position derivation (#114). LatestByKind — the
single most recent entry of a kind, the resolver's actual primitive: "the
latest BP-ENTRY-SCHEMA-SHARD-GENESIS-V1" in one index seek instead of a
full-log scan.

Backed by idx_entry_kind (migration 0022). DISCOVERY, not authority: the
caller re-verifies the returned entry from its bytes.
*/
package indexes

import (
	"github.com/baseproof/baseproof/types"
)

// entryKindPageSQL is the keyset query for QueryByKind — the same projection
// (sequence_number, log_time, canonical_hash) and ASC keyset shape every
// covering index serves through runIndexQuery; LIMIT is appended there.
const entryKindPageSQL = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE kind = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC`

// QueryByKind returns one read-page of entries whose payload kind == kind,
// from sequence startSeq (inclusive), capped at count ([1, MaxScanCount]).
// Ordered by sequence_number ASC for the keyset cursor.
func (q *PostgresQueryAPI) QueryByKind(kind string, startSeq uint64, count int) ([]types.EntryWithMetadata, error) {
	if kind == "" {
		return nil, nil // "" is the no-projection marker; never a query key
	}
	return q.runIndexQuery(q.ctx, entryKindPageSQL, kind, startSeq, clampPageCount(count))
}

// entryKindLatestSQL serves LatestByKind: the same partial btree
// (kind, sequence_number) walked in REVERSE, capped to one row via
// runIndexQuery's LIMIT — index-only, O(1) seek, never a scan. The
// startSeq parameter ($2) is the shared runIndexQuery contract; LatestByKind
// passes 0 (no lower bound — DESC takes the true maximum).
const entryKindLatestSQL = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE kind = $1 AND sequence_number >= $2 ORDER BY sequence_number DESC`

// LatestByKind returns the single most recent entry whose payload kind == kind,
// or (zero, false, nil) when the log carries no such entry. This is the
// AuthoritativeResolver's derivation primitive (#114 Phase B): the latest
// schema-declaration of each family, resolved from the log in one seek. Routes
// through the shared runIndexQuery path (close-discipline + hydrate in one
// home) with limit 1.
func (q *PostgresQueryAPI) LatestByKind(kind string) (types.EntryWithMetadata, bool, error) {
	if kind == "" {
		return types.EntryWithMetadata{}, false, nil
	}
	out, err := q.runIndexQuery(q.ctx, entryKindLatestSQL, kind, 0, 1)
	if err != nil {
		return types.EntryWithMetadata{}, false, err
	}
	if len(out) == 0 {
		return types.EntryWithMetadata{}, false, nil
	}
	return out[0], true, nil
}
