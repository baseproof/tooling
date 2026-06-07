/*
FILE PATH: store/indexes/query_api.go

PostgresQueryAPI satisfies sdk log.LedgerQueryAPI. Methods are spread
across the package files — each file provides one method's SQL query.

DESIGN RULE: Postgres is an index. Tessera is the source of truth for
entry bytes. Always.

  - Queries hit entry_index for sequence numbers + metadata.
  - Entry bytes hydrated via EntryReader (bytestore.Reader).
  - scanAndHydrate: query rows → collect seqs + metadata → batch hydrate.
  - ReadEntryBatch is tile-aware: entries in the same tile = 1 read.

EntryWithMetadata field set: under v6 the SDK type carries only
CanonicalBytes, LogTime, Position. Signatures live inside
CanonicalBytes (in the v6 multi-sig section) and are extracted via
envelope.Deserialize when callers need them. No sidecar sig
fields exist on the type or in the entry_index schema.
*/
package indexes

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// MaxScanCount is the hard upper limit per scan request.
const MaxScanCount = 10000

// DefaultScanCount is the default page size when count is not specified.
const DefaultScanCount = 100

// PostgresQueryAPI implements sdk log.LedgerQueryAPI.
// Metadata from entry_index (Postgres). Bytes from EntryReader (Tessera).
type PostgresQueryAPI struct {
	db     *pgxpool.Pool
	reader bytestore.Reader
	logDID string

	// ctx is the process-lifetime context bound at construction.
	// The SDK's log.LedgerQueryAPI interface methods
	// (QueryByCosignatureOf, QueryBySchemaRef, QueryBySignerDID,
	// QueryByTargetRoot, ScanFromPosition) do not accept a
	// context. Binding here so SIGTERM cancels in-flight queries.
	ctx context.Context
}

// NewPostgresQueryAPI creates the query API for a log. ctx is the
// process-lifetime context (parent of every internal query issued
// by the no-ctx LedgerQueryAPI interface methods).
func NewPostgresQueryAPI(ctx context.Context, db *pgxpool.Pool, reader bytestore.Reader, logDID string) *PostgresQueryAPI {
	if ctx == nil {
		ctx = context.Background()
	}
	return &PostgresQueryAPI{db: db, reader: reader, logDID: logDID, ctx: ctx}
}

// indexMeta holds the metadata columns scanned from entry_index.
// canonical_hash is required to construct the bytestore object key
// for the read-side hydrate; log_time and seq populate the response.
type indexMeta struct {
	Seq  uint64
	Time time.Time
	Hash [32]byte
}

// scanAndHydrate queries entry_index for metadata, then batch-hydrates
// bytes from EntryReader. Shared path for all 5 query methods.
//
// SQL projection contract: per-method queries that call this helper
// MUST select exactly (sequence_number, log_time, canonical_hash)
// in that order.
func (q *PostgresQueryAPI) scanAndHydrate(ctx context.Context, rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}) ([]types.EntryWithMetadata, error) {
	defer rows.Close()

	// (1) Collect sequence numbers + metadata from Postgres.
	var metas []indexMeta
	for rows.Next() {
		var (
			seq     uint64
			lt      time.Time
			hashCol []byte
		)
		if err := rows.Scan(&seq, &lt, &hashCol); err != nil {
			return nil, fmt.Errorf("store/indexes: scan: %w", err)
		}
		if len(hashCol) != 32 {
			return nil, fmt.Errorf("store/indexes: corrupt canonical_hash seq=%d (len=%d, want 32)", seq, len(hashCol))
		}
		var meta indexMeta
		meta.Seq = seq
		meta.Time = lt
		copy(meta.Hash[:], hashCol)
		metas = append(metas, meta)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/indexes: rows: %w", err)
	}

	if len(metas) == 0 {
		return []types.EntryWithMetadata{}, nil
	}

	// (2) Batch-hydrate wire bytes from EntryReader.
	refs := make([]bytestore.EntryRef, len(metas))
	for i, m := range metas {
		refs[i] = bytestore.EntryRef{Seq: m.Seq, Hash: m.Hash}
	}
	wires, err := q.reader.ReadEntryBatch(ctx, refs)
	if err != nil {
		return nil, fmt.Errorf("store/indexes: hydrate: %w", err)
	}

	// (3) Assemble []EntryWithMetadata. Three-field type per the v6
	// SDK; signatures live inside CanonicalBytes (wire bytes ARE the
	// canonical bytes) and surface via envelope.Deserialize.
	results := make([]types.EntryWithMetadata, len(metas))
	for i, m := range metas {
		results[i] = types.EntryWithMetadata{
			CanonicalBytes: wires[i],
			LogTime:        m.Time,
			Position:       types.LogPosition{LogDID: q.logDID, Sequence: m.Seq},
		}
	}
	return results, nil
}

// clampPageCount bounds an HTTP read-page request to [1, MaxScanCount]. A
// non-positive count (the ?count= param omitted, or a malformed value parsed
// to 0) defaults to MaxScanCount — the documented hard per-request ceiling —
// so the public /v1/query/* read path is ALWAYS bounded even when the caller
// asks for "everything". The unbounded full scan the custody/admission
// resolvers need is a SEPARATE path (QueryBySchemaRef) that never flows
// through this clamp.
func clampPageCount(count int) int {
	if count <= 0 || count > MaxScanCount {
		return MaxScanCount
	}
	return count
}

// runIndexQuery is the shared keyset query backing the control-header index
// endpoints. baseSQL is a per-method static query of the exact form
//
//	SELECT sequence_number, log_time, canonical_hash
//	FROM entry_index WHERE <col> = $1 AND sequence_number >= $2
//	ORDER BY sequence_number ASC
//
// key binds $1 (a []byte serialized LogPosition or a string DID); startSeq
// binds $2, the INCLUSIVE keyset cursor a caller advances to walk pages
// (sequence numbers are 0-indexed, so the first page starts at 0). When
// limit > 0 a `LIMIT $3` clause caps the page — the read-cost bound; when
// limit <= 0 no LIMIT is appended and every matching row is returned (the
// unbounded full scan). The 0017 covering index (<col>, sequence_number)
// INCLUDE (log_time, canonical_hash) serves the WHERE, the ORDER BY, and the
// projection index-only and pre-sorted, so a page is O(page), not O(matches).
func (q *PostgresQueryAPI) runIndexQuery(ctx context.Context, baseSQL string, key any, startSeq uint64, limit int) ([]types.EntryWithMetadata, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if limit > 0 {
		rows, err = q.db.Query(ctx, baseSQL+" LIMIT $3", key, startSeq, limit)
	} else {
		rows, err = q.db.Query(ctx, baseSQL, key, startSeq)
	}
	if err != nil {
		return nil, fmt.Errorf("store/indexes: index query: %w", err)
	}
	return q.scanAndHydrate(ctx, rows)
}
