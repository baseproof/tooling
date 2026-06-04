/*
FILE PATH:

	reservation/postgres.go

DESCRIPTION:

	PostgresStore — the production reservation.Store. It is held to the exact same
	contract as the in-memory fake by reservationtest.StoreConformance (run
	against a real database in CI), so the lifecycle logic proven against the fake
	holds here too.

KEY ARCHITECTURAL DECISIONS:
  - Reservations are keyed by artifact_cid (the content address known at
    submission time), not by an entry sequence (assigned asynchronously later).
  - Create uses INSERT ... ON CONFLICT DO NOTHING + RowsAffected to surface
    ErrDuplicate without coupling to a driver error code.
  - SetStatus is the atomic CAS: UPDATE ... WHERE artifact_cid=$ AND status=$from.
    One row updated => won; zero rows => distinguish absent (ErrNotFound) from
    a lost race / illegal move (ErrConflict). This is what makes concurrent
    FINISH/REAP safe at the database, mirroring the fake's mutex CAS.
*/
package reservation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore persists reservations in the artifact_reservations table.
type PostgresStore struct {
	db *pgxpool.Pool
}

// NewPostgresStore creates a Postgres-backed reservation store.
func NewPostgresStore(db *pgxpool.Pool) *PostgresStore { return &PostgresStore{db: db} }

var _ Store = (*PostgresStore)(nil)

func (s *PostgresStore) Create(ctx context.Context, r Reservation) error {
	tag, err := s.db.Exec(ctx, `
		INSERT INTO artifact_reservations
			(artifact_cid, content_digest, mime_type, max_size, owner, status, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (artifact_cid) DO NOTHING`,
		r.ArtifactCID, r.ContentDigest, r.MIMEType,
		r.MaxSize, r.Owner, string(r.Status), r.ExpiresAt, r.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("reservation/pg: create: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDuplicate
	}
	return nil
}

func (s *PostgresStore) Get(ctx context.Context, artifactCID string) (Reservation, error) {
	var r Reservation
	var maxSize int64
	var status string
	err := s.db.QueryRow(ctx, `
		SELECT artifact_cid, content_digest, mime_type, max_size, owner, status, expires_at, created_at
		FROM artifact_reservations WHERE artifact_cid = $1`, artifactCID,
	).Scan(&r.ArtifactCID, &r.ContentDigest, &r.MIMEType, &maxSize, &r.Owner, &status, &r.ExpiresAt, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Reservation{}, ErrNotFound
	}
	if err != nil {
		return Reservation{}, fmt.Errorf("reservation/pg: get %s: %w", artifactCID, err)
	}
	r.MaxSize = maxSize
	r.Status = Status(status)
	return r, nil
}

func (s *PostgresStore) SetStatus(ctx context.Context, artifactCID string, from, to Status) error {
	if !CanTransition(from, to) {
		return ErrConflict
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE artifact_reservations SET status = $1 WHERE artifact_cid = $2 AND status = $3`,
		string(to), artifactCID, string(from))
	if err != nil {
		return fmt.Errorf("reservation/pg: set status %s: %w", artifactCID, err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Zero rows: distinguish "absent" from "wrong from" (lost CAS).
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM artifact_reservations WHERE artifact_cid = $1)`, artifactCID,
	).Scan(&exists); err != nil {
		return fmt.Errorf("reservation/pg: set status %s existence: %w", artifactCID, err)
	}
	if !exists {
		return ErrNotFound
	}
	return ErrConflict
}

func (s *PostgresStore) ListExpirable(ctx context.Context, now time.Time, limit int) ([]Reservation, error) {
	rows, err := s.db.Query(ctx, `
		SELECT artifact_cid, content_digest, mime_type, max_size, owner, status, expires_at, created_at
		FROM artifact_reservations
		WHERE status IN ('pending_upload','uploaded') AND expires_at <= $1
		ORDER BY expires_at ASC
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("reservation/pg: list expirable: %w", err)
	}
	defer rows.Close()

	var out []Reservation
	for rows.Next() {
		var r Reservation
		var maxSize int64
		var status string
		if err := rows.Scan(&r.ArtifactCID, &r.ContentDigest, &r.MIMEType,
			&maxSize, &r.Owner, &status, &r.ExpiresAt, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("reservation/pg: scan: %w", err)
		}
		r.MaxSize = maxSize
		r.Status = Status(status)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reservation/pg: rows: %w", err)
	}
	return out, nil
}
