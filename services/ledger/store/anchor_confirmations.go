/*
FILE PATH: store/anchor_confirmations.go

AnchorConfirmationStore — the durable record of "our anchor LANDED in that
parent log" (migration 0021), written by the publisher's read-back and served
by GET /v1/network/anchors.

INSERT-ONLY BY LAW. verified_at is the FIRST successful observation and is
never refreshed: RecordFirstSeen writes with ON CONFLICT DO NOTHING and
returns the STORED time, the table sits in the H4 append-only guard list, and
F2 grants deny mutation at the DB role. This is the persistence half of the
lazy-fresh defense — the SDK's freshness floor is min(AnchoredAt, VerifiedAt),
and a refreshable VerifiedAt would let one stale anchor read fresh forever.
*/
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AnchorConfirmation is one confirmed landing of THIS log's cosigned head in
// a parent log.
type AnchorConfirmation struct {
	// ParentLogDID is the parent log the anchor entry was admitted on.
	ParentLogDID string
	// TreeHeadRef is the 64-hex network-bound digest of OUR anchored head
	// (the anchor payload's tree_head_ref) — the row's identity together
	// with ParentLogDID.
	TreeHeadRef string
	// ParentNetworkID is the parent's constitutional identity (the WHICH)
	// when known — always filled by the 4d derivation chain; nil in the
	// env-config era.
	ParentNetworkID []byte
	// ParentSeq is the anchor entry's sequence on the PARENT log.
	ParentSeq uint64
	// AnchoredTreeSize is OUR tree size at the anchored head.
	AnchoredTreeSize uint64
	// AnchoredAt is the payload's self-reported claim (zero when absent).
	AnchoredAt time.Time
	// VerifiedAt is the FIRST successful read-back observation. Immutable.
	VerifiedAt time.Time
}

// AnchorConfirmationStore persists confirmations.
type AnchorConfirmationStore struct{ db *pgxpool.Pool }

// NewAnchorConfirmationStore wires the store.
func NewAnchorConfirmationStore(db *pgxpool.Pool) *AnchorConfirmationStore {
	return &AnchorConfirmationStore{db: db}
}

// RecordFirstSeen inserts the confirmation if (and only if) this
// (parent, head) pair has never been recorded, and returns the DURABLE
// verified_at — the stored first observation, never c.VerifiedAt when a row
// already exists. Re-observation is a no-op by construction.
func (s *AnchorConfirmationStore) RecordFirstSeen(ctx context.Context, c AnchorConfirmation) (time.Time, error) {
	if c.ParentLogDID == "" || c.TreeHeadRef == "" {
		return time.Time{}, fmt.Errorf("store/anchor_confirmations: parent_log_did and tree_head_ref required")
	}
	if c.VerifiedAt.IsZero() {
		return time.Time{}, fmt.Errorf("store/anchor_confirmations: zero verified_at (the observation clock is the caller's)")
	}
	var anchoredAt any
	if !c.AnchoredAt.IsZero() {
		anchoredAt = c.AnchoredAt
	}
	if _, err := s.db.Exec(ctx, `
		INSERT INTO anchor_confirmations (
			parent_log_did, tree_head_ref, parent_network_id,
			parent_seq, anchored_tree_size, anchored_at, verified_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (parent_log_did, tree_head_ref) DO NOTHING`,
		c.ParentLogDID, c.TreeHeadRef, c.ParentNetworkID,
		int64(c.ParentSeq), int64(c.AnchoredTreeSize), anchoredAt, c.VerifiedAt,
	); err != nil {
		return time.Time{}, fmt.Errorf("store/anchor_confirmations: insert: %w", err)
	}
	var stored time.Time
	if err := s.db.QueryRow(ctx, `
		SELECT verified_at FROM anchor_confirmations
		WHERE parent_log_did = $1 AND tree_head_ref = $2`,
		c.ParentLogDID, c.TreeHeadRef,
	).Scan(&stored); err != nil {
		return time.Time{}, fmt.Errorf("store/anchor_confirmations: read back: %w", err)
	}
	return stored.UTC(), nil
}

// LatestPerParent returns, for every parent this log has confirmed anchors
// in, the confirmation with the freshest verified_at — the rows
// GET /v1/network/anchors serves as the anchor chain. Empty result is a
// valid answer (a log that has never anchored anywhere).
func (s *AnchorConfirmationStore) LatestPerParent(ctx context.Context) ([]AnchorConfirmation, error) {
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT ON (parent_log_did)
			parent_log_did, tree_head_ref, parent_network_id,
			parent_seq, anchored_tree_size, anchored_at, verified_at
		FROM anchor_confirmations
		ORDER BY parent_log_did, verified_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store/anchor_confirmations: latest: %w", err)
	}
	defer rows.Close()
	var out []AnchorConfirmation
	for rows.Next() {
		var c AnchorConfirmation
		var parentSeq, treeSize int64
		var anchoredAt *time.Time
		if err := rows.Scan(&c.ParentLogDID, &c.TreeHeadRef, &c.ParentNetworkID,
			&parentSeq, &treeSize, &anchoredAt, &c.VerifiedAt); err != nil {
			return nil, fmt.Errorf("store/anchor_confirmations: scan: %w", err)
		}
		c.ParentSeq = uint64(parentSeq)
		c.AnchoredTreeSize = uint64(treeSize)
		if anchoredAt != nil {
			c.AnchoredAt = anchoredAt.UTC()
		}
		c.VerifiedAt = c.VerifiedAt.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}
