// FILE PATH: services/auditor/internal/store/store.go
//
// DESCRIPTION:
//
//	A durable gossip.Store backed by Postgres — the JN's sovereign
//	auditor memory. Replaces the in-memory store so a daemon restart
//	never loses verified findings (rotations, equivocation proofs):
//	the JN's worldview survives in its own database, on its own disk,
//	never in the custody of the ledgers it polices.
//
//	Integrity is enforced by the SDK at READ time, not here: every row
//	is a cryptographically-signed gossip.SignedEvent. A tampered row
//	fails signature verification the moment it is pulled, so the store
//	may be "dumb" durable bytes while remaining unforgeable. This store
//	does, however, faithfully enforce the gossip.Store CHAIN discipline
//	(prev-hash linkage + Lamport monotonicity per originator) so it is a
//	correct drop-in for the in-memory reference, not a weaker buffer.
//
//	Schema (single table; created idempotently by Migrate):
//
//	  peer_gossip(event_id PK, originator, kind, lamport, payload, inserted_at)
//
//	payload is BYTEA, NOT JSONB: the signed Body is a json.RawMessage
//	whose exact bytes are covered by the signature. JSONB would reorder
//	keys and strip whitespace, changing the canonical bytes and breaking
//	verification. The queryable dimensions (originator/kind/lamport) are
//	broken out into typed columns + a (originator, lamport) index, so the
//	payload only needs byte-exact fidelity.
//
// KEY DEPENDENCIES:
//   - baseproof/gossip: Store, SignedEvent, EventIDOf, Filter, IterCursor,
//     StoreStats, and the Err* sentinels (ChainBreak / LamportRegression
//     / EventNotFound / InvalidWireRequest).
package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/gossip"
)

// PostgresStore implements gossip.Store over a *sql.DB. Safe for
// concurrent use: per-originator Append serialization is enforced with
// a transaction-scoped Postgres advisory lock, so writes for distinct
// originators proceed in parallel while a single originator's chain
// advances atomically.
type PostgresStore struct {
	db *sql.DB
}

var _ gossip.Store = (*PostgresStore)(nil)

// schemaSQL creates the table + indexes. Idempotent (IF NOT EXISTS) so
// it doubles as the migration — JN has no migration framework; the
// aggregator applies schema.sql out-of-band, and this store ensures its
// own table at boot.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS peer_gossip (
    event_id    TEXT        PRIMARY KEY,
    originator  TEXT        NOT NULL,
    kind        TEXT        NOT NULL,
    lamport     BIGINT      NOT NULL,
    payload     BYTEA       NOT NULL,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS peer_gossip_chain ON peer_gossip (originator, lamport);
CREATE INDEX IF NOT EXISTS peer_gossip_inserted_at ON peer_gossip (inserted_at);`

// ErrInvalidConfig is returned when NewPostgresStore is misconfigured.
var ErrInvalidConfig = errors.New("store: invalid config")

// NewPostgresStore wraps an open pool. The store takes ownership: Close
// closes the pool.
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: nil *sql.DB", ErrInvalidConfig)
	}
	return &PostgresStore{db: db}, nil
}

// Migrate creates the peer_gossip table + indexes if absent. Idempotent;
// safe to call on every boot.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("gossipfeed: migrate peer_gossip: %w", err)
	}
	return nil
}

// Append implements gossip.Store with full chain discipline, mirroring
// the InMemoryStore reference: idempotent by EventID, ErrChainBreak on
// prev-hash mismatch, ErrLamportRegression on non-monotonic Lamport,
// atomic insert under a per-originator advisory lock.
func (s *PostgresStore) Append(ctx context.Context, ev gossip.SignedEvent) error {
	if ev.Originator == "" {
		return fmt.Errorf("%w: originator empty", gossip.ErrInvalidWireRequest)
	}
	id, err := gossip.EventIDOf(ev)
	if err != nil {
		return err
	}
	idHex := hex.EncodeToString(id[:])
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("gossipfeed: marshal event: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("gossipfeed: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Per-originator critical section; auto-released at tx end. Distinct
	// originators hash to distinct lock keys and proceed in parallel.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, ev.Originator); err != nil {
		return fmt.Errorf("gossipfeed: advisory lock: %w", err)
	}

	// I9: re-receiving the same EventID is an idempotent success; keep
	// the first version stored.
	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM peer_gossip WHERE event_id = $1)`, idHex).Scan(&exists); err != nil {
		return fmt.Errorf("gossipfeed: idempotency check: %w", err)
	}
	if exists {
		return tx.Commit()
	}

	// Chain head for this originator = the max-Lamport row (Append
	// enforces strict monotonicity, so the latest row IS the head).
	// head.prev is that row's EventID; PrevHash is the same lowercase
	// hex form Sign emits, so a string compare is exact.
	var headHex string
	var headLamport int64
	switch err := tx.QueryRowContext(ctx,
		`SELECT event_id, lamport FROM peer_gossip WHERE originator = $1 ORDER BY lamport DESC LIMIT 1`,
		ev.Originator).Scan(&headHex, &headLamport); {
	case errors.Is(err, sql.ErrNoRows):
		headHex, headLamport = "", 0
	case err != nil:
		return fmt.Errorf("gossipfeed: head lookup: %w", err)
	}

	if ev.PrevHash != headHex {
		return fmt.Errorf("%w: originator %s", gossip.ErrChainBreak, ev.Originator)
	}
	if headLamport > 0 && ev.LamportTime <= uint64(headLamport) {
		return fmt.Errorf("%w: originator %s: lamport %d <= head %d",
			gossip.ErrLamportRegression, ev.Originator, ev.LamportTime, headLamport)
	}
	if headLamport == 0 && ev.LamportTime == 0 {
		return fmt.Errorf("%w: first event lamport must be non-zero", gossip.ErrInvalidWireRequest)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO peer_gossip (event_id, originator, kind, lamport, payload) VALUES ($1, $2, $3, $4, $5)`,
		idHex, ev.Originator, string(ev.Kind), int64(ev.LamportTime), payload); err != nil {
		return fmt.Errorf("gossipfeed: insert: %w", err)
	}
	return tx.Commit()
}

// Head implements gossip.Store.
func (s *PostgresStore) Head(ctx context.Context, originator string) ([32]byte, uint64, error) {
	var headHex string
	var lamport int64
	err := s.db.QueryRowContext(ctx,
		`SELECT event_id, lamport FROM peer_gossip WHERE originator = $1 ORDER BY lamport DESC LIMIT 1`,
		originator).Scan(&headHex, &lamport)
	if errors.Is(err, sql.ErrNoRows) {
		return [32]byte{}, 0, nil
	}
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("gossipfeed: head: %w", err)
	}
	id, err := decodeEventID(headHex)
	if err != nil {
		return [32]byte{}, 0, err
	}
	return id, uint64(lamport), nil
}

// Get implements gossip.Store.
func (s *PostgresStore) Get(ctx context.Context, eventID [32]byte) (gossip.SignedEvent, error) {
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT payload FROM peer_gossip WHERE event_id = $1`,
		hex.EncodeToString(eventID[:])).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return gossip.SignedEvent{}, gossip.ErrEventNotFound
	}
	if err != nil {
		return gossip.SignedEvent{}, fmt.Errorf("gossipfeed: get: %w", err)
	}
	return unmarshalEvent(payload)
}

// Iterate implements gossip.Store.
func (s *PostgresStore) Iterate(ctx context.Context, f gossip.Filter, fn func(gossip.SignedEvent) error) error {
	q := `SELECT payload FROM peer_gossip WHERE lamport > $1`
	args := []any{int64(f.SinceLamport)}
	if f.Originator != nil {
		args = append(args, *f.Originator)
		q += fmt.Sprintf(" AND originator = $%d", len(args))
	}
	if f.Kind != nil {
		args = append(args, string(*f.Kind))
		q += fmt.Sprintf(" AND kind = $%d", len(args))
	}
	q += " ORDER BY originator, lamport"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("gossipfeed: iterate query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return fmt.Errorf("gossipfeed: iterate scan: %w", err)
		}
		ev, err := unmarshalEvent(payload)
		if err != nil {
			return err
		}
		// Binding is a content-keyed post-filter; no inverted index yet
		// (gossip volume is TTL-bounded, so a scan over the filtered set
		// is acceptable — matches the reference impl's note).
		if f.Binding != nil && !eventHasBinding(ev, *f.Binding) {
			continue
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Stats implements gossip.Store. EventCount uses an exact count: the
// table is bounded by the retention window (gossip is low-volume
// metadata, not ledger entries), so the count stays cheap; Heads is
// O(#originators) via the (originator, lamport) index.
func (s *PostgresStore) Stats(ctx context.Context) (gossip.StoreStats, error) {
	var eventCount int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM peer_gossip`).Scan(&eventCount); err != nil {
		return gossip.StoreStats{}, fmt.Errorf("gossipfeed: stats count: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT originator, max(lamport) FROM peer_gossip GROUP BY originator`)
	if err != nil {
		return gossip.StoreStats{}, fmt.Errorf("gossipfeed: stats heads: %w", err)
	}
	defer rows.Close()

	heads := make(map[string]uint64)
	for rows.Next() {
		var originator string
		var lamport int64
		if err := rows.Scan(&originator, &lamport); err != nil {
			return gossip.StoreStats{}, fmt.Errorf("gossipfeed: stats scan: %w", err)
		}
		heads[originator] = uint64(lamport)
	}
	if err := rows.Err(); err != nil {
		return gossip.StoreStats{}, err
	}
	return gossip.StoreStats{
		EventCount:      int(eventCount),
		OriginatorCount: len(heads),
		Heads:           heads,
	}, nil
}

// IterSince implements gossip.Store: cursor-paginated feed primitive,
// ascending (originator, lamport), half-open on cursor.Lamport.
func (s *PostgresStore) IterSince(ctx context.Context, cursor gossip.IterCursor, limit int) ([]gossip.SignedEvent, gossip.IterCursor, error) {
	if limit <= 0 {
		return nil, cursor, fmt.Errorf("%w: limit must be positive, got %d", gossip.ErrInvalidConfig, limit)
	}
	q := `SELECT payload, lamport FROM peer_gossip WHERE lamport > $1`
	args := []any{int64(cursor.Lamport)}
	if cursor.Originator != "" {
		args = append(args, cursor.Originator)
		q += fmt.Sprintf(" AND originator = $%d", len(args))
	}
	if cursor.Kind != "" {
		args = append(args, string(cursor.Kind))
		q += fmt.Sprintf(" AND kind = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY originator, lamport LIMIT $%d", len(args))

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, cursor, fmt.Errorf("gossipfeed: itersince query: %w", err)
	}
	defer rows.Close()

	var out []gossip.SignedEvent
	var lastLamport int64
	for rows.Next() {
		var payload []byte
		var lamport int64
		if err := rows.Scan(&payload, &lamport); err != nil {
			return nil, cursor, fmt.Errorf("gossipfeed: itersince scan: %w", err)
		}
		ev, err := unmarshalEvent(payload)
		if err != nil {
			return nil, cursor, err
		}
		out = append(out, ev)
		lastLamport = lamport
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, err
	}
	next := cursor
	if len(out) > 0 {
		next.Lamport = uint64(lastLamport)
	}
	return out, next, nil
}

// LatestSTH implements gossip.Store.
func (s *PostgresStore) LatestSTH(ctx context.Context, originator string) (gossip.SignedEvent, bool, error) {
	if originator == "" {
		return gossip.SignedEvent{}, false, fmt.Errorf("%w: originator empty", gossip.ErrInvalidConfig)
	}
	var payload []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT payload FROM peer_gossip WHERE originator = $1 AND kind = $2 ORDER BY lamport DESC LIMIT 1`,
		originator, string(gossip.KindCosignedTreeHead)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return gossip.SignedEvent{}, false, nil
	}
	if err != nil {
		return gossip.SignedEvent{}, false, fmt.Errorf("gossipfeed: latest sth: %w", err)
	}
	ev, err := unmarshalEvent(payload)
	if err != nil {
		return gossip.SignedEvent{}, false, err
	}
	return ev, true, nil
}

// Prune deletes events older than the retention cutoff (D8). Returns the
// number of rows removed. Called on a schedule by the monitoring
// scheduler; old findings re-hydrate via stateless catch-up if needed.
func (s *PostgresStore) Prune(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx,
		fmt.Sprintf(`DELETE FROM peer_gossip WHERE inserted_at < now() - interval '%d days'`, retentionDays))
	if err != nil {
		return 0, fmt.Errorf("gossipfeed: prune: %w", err)
	}
	return res.RowsAffected()
}

// Close implements gossip.Store; closes the owned pool.
func (s *PostgresStore) Close(ctx context.Context) error {
	return s.db.Close()
}

func unmarshalEvent(payload []byte) (gossip.SignedEvent, error) {
	var ev gossip.SignedEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return gossip.SignedEvent{}, fmt.Errorf("gossipfeed: unmarshal event: %w", err)
	}
	return ev, nil
}

func decodeEventID(h string) ([32]byte, error) {
	var id [32]byte
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("gossipfeed: corrupt event_id %q", h)
	}
	copy(id[:], raw)
	return id, nil
}

func eventHasBinding(ev gossip.SignedEvent, target [32]byte) bool {
	want := hex.EncodeToString(target[:])
	for _, b := range ev.Bindings {
		if b == want {
			return true
		}
	}
	return false
}
