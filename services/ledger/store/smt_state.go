/*
FILE PATH: store/smt_state.go

PostgresLeafStore — the Postgres-backed implementation of the v0.3.0 SDK's
smt.LeafStore interface.

# DE-POLLUTION: PG HOLDS LEAVES, NOT THE NODE DAG

	smt_leaves is the irreducible SMT state: root = f(smt_leaves). The ~2N
	Jellyfish node DAG that used to live in PG (jellyfish_nodes, dropped in
	migration 0013) is now content-addressed tiles in the object store, with an
	in-memory tail for un-tiled nodes (store/tailed_node_store.go). The builder
	computes over the TailedNodeStore; the reconciler emits durable tiles. So the
	node-store implementation moved off PG entirely — only the leaf store and the
	LogPosition (de)serialization helpers remain here.

# KEY ARCHITECTURAL DECISIONS

  - PostgresLeafStore: every interface method takes ctx (Tier 1.3 of
    the v0.2.0 SDK migration, preserved in v0.3.0). SetTx remains for
    atomic builder commits; SetBatchTx is the builder's per-batch path.

  - LogPosition serialization: length-prefixed DID + uint64, matching
    the SDK's canonical serialization.

# INVARIANTS

  - After builder atomic commit, smt_leaves is consistent with
    smt_root_state.current_root: every leaf reachable from the committed root
    is present in smt_leaves (and the root is derivable from the leaf set).
*/
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// 1) PostgresLeafStore — implements sdk smt.LeafStore
// ─────────────────────────────────────────────────────────────────────────────

// PostgresLeafStore persists SMT leaves in Postgres.
// Supports transactional writes for atomic builder commits via SetTx.
type PostgresLeafStore struct {
	db *pgxpool.Pool
}

// NewPostgresLeafStore creates a leaf store. Per-call ctx is supplied
// via the SDK's smt.LeafStore interface methods.
func NewPostgresLeafStore(db *pgxpool.Pool) *PostgresLeafStore {
	return &PostgresLeafStore{db: db}
}

// Get reads a leaf by key. Returns nil if not found.
func (s *PostgresLeafStore) Get(ctx context.Context, key [32]byte) (*types.SMTLeaf, error) {
	var originTipBytes, authorityTipBytes []byte
	err := s.db.QueryRow(ctx,
		"SELECT origin_tip, authority_tip FROM smt_leaves WHERE leaf_key = $1",
		key[:],
	).Scan(&originTipBytes, &authorityTipBytes)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store/smt: get leaf: %w", err)
	}

	originTip, err := DeserializeLogPosition(originTipBytes)
	if err != nil {
		return nil, fmt.Errorf("store/smt: decode origin_tip: %w", err)
	}
	authorityTip, err := DeserializeLogPosition(authorityTipBytes)
	if err != nil {
		return nil, fmt.Errorf("store/smt: decode authority_tip: %w", err)
	}

	return &types.SMTLeaf{Key: key, OriginTip: originTip, AuthorityTip: authorityTip}, nil
}

// ListAll returns every leaf in smt_leaves — the full committed leaf set.
// Tail recovery replays these to rebuild the in-memory node tail on boot, since
// root = f(smt_leaves). At very large N this should stream/paginate; today it
// materializes (recovery is a rare boot path).
func (s *PostgresLeafStore) ListAll(ctx context.Context) ([]types.SMTLeaf, error) {
	rows, err := s.db.Query(ctx, "SELECT leaf_key, origin_tip, authority_tip FROM smt_leaves")
	if err != nil {
		return nil, fmt.Errorf("store/smt: list leaves: %w", err)
	}
	defer rows.Close()

	var out []types.SMTLeaf
	for rows.Next() {
		var keyBytes, originTipBytes, authorityTipBytes []byte
		if err := rows.Scan(&keyBytes, &originTipBytes, &authorityTipBytes); err != nil {
			return nil, fmt.Errorf("store/smt: scan leaf: %w", err)
		}
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("store/smt: list leaves: bad leaf_key length %d", len(keyBytes))
		}
		originTip, err := DeserializeLogPosition(originTipBytes)
		if err != nil {
			return nil, fmt.Errorf("store/smt: decode origin_tip: %w", err)
		}
		authorityTip, err := DeserializeLogPosition(authorityTipBytes)
		if err != nil {
			return nil, fmt.Errorf("store/smt: decode authority_tip: %w", err)
		}
		var key [32]byte
		copy(key[:], keyBytes)
		out = append(out, types.SMTLeaf{Key: key, OriginTip: originTip, AuthorityTip: authorityTip})
	}
	return out, rows.Err()
}

// Set writes a leaf using the connection pool (non-transactional).
// Used during non-critical paths. Builder uses SetTx for atomic commits.
func (s *PostgresLeafStore) Set(ctx context.Context, key [32]byte, leaf types.SMTLeaf) error {
	originBytes := SerializeLogPosition(leaf.OriginTip)
	authBytes := SerializeLogPosition(leaf.AuthorityTip)

	_, err := s.db.Exec(ctx, `
		INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (leaf_key) DO UPDATE SET
			origin_tip = EXCLUDED.origin_tip,
			authority_tip = EXCLUDED.authority_tip,
			updated_at = NOW()`,
		key[:], originBytes, authBytes,
	)
	if err != nil {
		return fmt.Errorf("store/smt: set leaf: %w", err)
	}
	return nil
}

// SetTx writes a leaf within a transaction (for atomic builder commit).
//
// Prefer SetBatchTx for any path that writes more than one leaf — the
// builder's per-batch commit must use the batched form to collapse N
// network round-trips into 1. SetTx remains for unit tests and the
// rebuild tool that legitimately write a single row.
func (s *PostgresLeafStore) SetTx(ctx context.Context, tx pgx.Tx, key [32]byte, leaf types.SMTLeaf) error {
	originBytes := SerializeLogPosition(leaf.OriginTip)
	authBytes := SerializeLogPosition(leaf.AuthorityTip)

	_, err := tx.Exec(ctx, `
		INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (leaf_key) DO UPDATE SET
			origin_tip = EXCLUDED.origin_tip,
			authority_tip = EXCLUDED.authority_tip,
			updated_at = NOW()`,
		key[:], originBytes, authBytes,
	)
	if err != nil {
		return fmt.Errorf("store/smt: set leaf tx: %w", err)
	}
	return nil
}

// SetBatchTx writes N leaves inside the supplied transaction in a
// single round-trip. THIS is the method the builder's atomic commit
// uses; per-row SetTx in a Go for-loop pays N synchronous network
// hops to Postgres and is the N+1-query write path the 10K soak
// telemetry surfaced as the per-batch latency floor (~2.5s of
// commit time at BatchSize=500 ≈ 1500 RTTs × 1.5ms).
//
// The implementation uses PostgreSQL's parallel `unnest($1::bytea[],
// $2::bytea[], $3::bytea[])` form so the server plans ONE INSERT,
// executes ONE statement, and round-trips ONE OK packet. ON CONFLICT
// DO UPDATE preserves the per-row idempotency the builder's retry
// semantics rely on; identical leaves rewritten are no-ops at the
// row level (the same (origin_tip, authority_tip) goes back in).
//
// Empty input is a no-op — callers don't need to guard.
//
// Returns the number of rows affected by the INSERT (per PG semantics
// for INSERT … ON CONFLICT DO UPDATE: every input row counts as 1
// affected, whether it inserted or updated). The caller can compare
// against len(leaves) — a mismatch is pathological (would require an
// in-batch leaf_key collision, which sha256(LogDID||seq) makes
// near-impossible across distinct seqs) and is THE smoking gun for
// "leaves silently collapsed via ON CONFLICT".
func (s *PostgresLeafStore) SetBatchTx(ctx context.Context, tx pgx.Tx, leaves []types.SMTLeaf) (int64, error) {
	if len(leaves) == 0 {
		return 0, nil
	}
	keys := make([][]byte, len(leaves))
	origins := make([][]byte, len(leaves))
	auths := make([][]byte, len(leaves))
	for i := range leaves {
		// Copy the [32]byte key array onto the heap so the slice
		// header we hand to pgx outlives this loop iteration. (Go's
		// GC keeps the underlying array alive via the slice in
		// keys[i], but only because the slice's backing array is a
		// fresh allocation per iteration — which `leaves[i].Key` is
		// since it's a value field on the struct.)
		k := leaves[i].Key
		keys[i] = k[:]
		origins[i] = SerializeLogPosition(leaves[i].OriginTip)
		auths[i] = SerializeLogPosition(leaves[i].AuthorityTip)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
		SELECT leaf_key, origin_tip, authority_tip, NOW()
		FROM unnest($1::bytea[], $2::bytea[], $3::bytea[])
			AS t(leaf_key, origin_tip, authority_tip)
		ON CONFLICT (leaf_key) DO UPDATE SET
			origin_tip = EXCLUDED.origin_tip,
			authority_tip = EXCLUDED.authority_tip,
			updated_at = NOW()`,
		keys, origins, auths,
	)
	if err != nil {
		return 0, fmt.Errorf("store/smt: set batch tx (n=%d): %w", len(leaves), err)
	}
	return tag.RowsAffected(), nil
}

// SetBatch writes multiple leaves using Postgres batching.
// This satisfies the sdk smt.LeafStore interface.
func (s *PostgresLeafStore) SetBatch(ctx context.Context, leaves []types.SMTLeaf) error {
	if len(leaves) == 0 {
		return nil
	}

	batch := &pgx.Batch{}

	for _, leaf := range leaves {
		originBytes := SerializeLogPosition(leaf.OriginTip)
		authBytes := SerializeLogPosition(leaf.AuthorityTip)

		batch.Queue(`
			INSERT INTO smt_leaves (leaf_key, origin_tip, authority_tip, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (leaf_key) DO UPDATE SET
				origin_tip = EXCLUDED.origin_tip,
				authority_tip = EXCLUDED.authority_tip,
				updated_at = NOW()`,
			leaf.Key[:], originBytes, authBytes,
		)
	}

	br := s.db.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()

	if _, err := br.Exec(); err != nil {
		return fmt.Errorf("store/smt: set batch: %w", err)
	}
	return nil
}

// Delete removes a leaf.
func (s *PostgresLeafStore) Delete(ctx context.Context, key [32]byte) error {
	_, err := s.db.Exec(ctx, "DELETE FROM smt_leaves WHERE leaf_key = $1", key[:])
	if err != nil {
		return fmt.Errorf("store/smt: delete leaf: %w", err)
	}
	return nil
}

// Count returns the total number of SMT leaves.
func (s *PostgresLeafStore) Count(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRow(ctx, "SELECT COUNT(*) FROM smt_leaves").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store/smt: count leaves: %w", err)
	}
	return count, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) LogPosition serialization for BYTEA columns
// ─────────────────────────────────────────────────────────────────────────────

// SerializeLogPosition encodes a LogPosition as length-prefixed DID + uint64.
func SerializeLogPosition(pos types.LogPosition) []byte {
	did := []byte(pos.LogDID)
	buf := make([]byte, 2+len(did)+8)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(did)))
	copy(buf[2:2+len(did)], did)
	binary.BigEndian.PutUint64(buf[2+len(did):], pos.Sequence)
	return buf
}

// DeserializeLogPosition decodes a BYTEA into a LogPosition.
func DeserializeLogPosition(data []byte) (types.LogPosition, error) {
	if len(data) < 10 {
		return types.LogPosition{}, fmt.Errorf("LogPosition bytes too short: %d", len(data))
	}
	didLen := binary.BigEndian.Uint16(data[0:2])
	if int(2+didLen+8) > len(data) {
		return types.LogPosition{}, fmt.Errorf("LogPosition truncated: didLen=%d, total=%d", didLen, len(data))
	}
	did := string(data[2 : 2+didLen])
	seq := binary.BigEndian.Uint64(data[2+didLen:])
	return types.LogPosition{LogDID: did, Sequence: seq}, nil
}
