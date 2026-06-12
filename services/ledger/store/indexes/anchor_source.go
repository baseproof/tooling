/*
FILE PATH: store/indexes/anchor_source.go

QueryAnchorsBySource — one read-page of the cosigned-anchor entries a given
CHILD log has anchored into THIS (parent) log. The seventh keyset query, same
clamp/cursor contract as its six siblings; served index-only by the 0020
partial covering index (idx_anchor_source).

DISCOVERY, NOT AUTHORITY: source_log_did is the publisher's own payload field
projected at sequencing (store.AnchorSourceLogDID). The page exists so a
consumer can FIND the anchor entries; every trust-bearing fact (inclusion,
parent quorum, child-lineage binding) is re-established by the consumer from
the returned entry bytes. An anchor missing from this projection fails toward
ALARM (its child's read-back and the auditors' feed simply don't see it) —
never toward false compliance.
*/
package indexes

import (
	"github.com/baseproof/baseproof/types"
)

// anchorSourceQuery is the keyset query for QueryAnchorsBySource. See
// runIndexQuery for the projection + cursor contract; the LIMIT clause is
// appended there. Only rows with a non-NULL source_log_did exist in the
// partial index, so the predicate matches the index exactly.
const anchorSourceQuery = `SELECT sequence_number, log_time, canonical_hash
	FROM entry_index WHERE source_log_did = $1 AND sequence_number >= $2 ORDER BY sequence_number ASC`

// QueryAnchorsBySource returns one read-page of cosigned-anchor entries whose
// projected SourceLogDID equals sourceLogDID, starting at startSeq (inclusive)
// and capped at count (clamped to [1, MaxScanCount] — ALWAYS bounded; there is
// no unbounded by-source scan). Callers walk pages by advancing startSeq past
// the last returned sequence_number.
func (q *PostgresQueryAPI) QueryAnchorsBySource(sourceLogDID string, startSeq uint64, count int) ([]types.EntryWithMetadata, error) {
	return q.runIndexQuery(q.ctx, anchorSourceQuery, sourceLogDID, startSeq, clampPageCount(count))
}
