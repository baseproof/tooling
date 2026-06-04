/*
FILE PATH: store/tile_frontier.go

PgTileFrontier — the durable Tile Clock (see migration 0012).

The reconciler advances this watermark ONLY after the tiles for `root` are
durably PUT-ack'd; the published horizon is gated on it. A crash/restart reads
it back and re-emits the exact gap to the committed root — deterministic resume,
no stranded tiles, no permanent holes.

SMTCommitCursor adapts SMTRootStateStore to the reconciler's CommitCursorReader:
the commit cursor (committed_through_seq + current_root) the builder advances in
the atomic commit tx.
*/
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PgTileFrontier reads/advances the singleton tile_frontier row.
type PgTileFrontier struct {
	db *pgxpool.Pool
}

// NewPgTileFrontier constructs the durable frontier store.
func NewPgTileFrontier(db *pgxpool.Pool) *PgTileFrontier {
	return &PgTileFrontier{db: db}
}

// ReadFrontier returns the highest seq whose SMT tiles are confirmed durable,
// and the root at that seq. Errors if the singleton row is missing (migration
// 0012 didn't run — not a normal first-boot case).
func (s *PgTileFrontier) ReadFrontier(ctx context.Context) (uint64, [32]byte, error) {
	var rootBytes []byte
	var seq int64
	err := s.db.QueryRow(ctx,
		`SELECT frontier_root, frontier_seq FROM tile_frontier WHERE id = 1`,
	).Scan(&rootBytes, &seq)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("store/tile-frontier: read: %w", err)
	}
	if len(rootBytes) != 32 {
		return 0, [32]byte{}, fmt.Errorf("store/tile-frontier: bad root length %d (want 32)", len(rootBytes))
	}
	var root [32]byte
	copy(root[:], rootBytes)
	return uint64(seq), root, nil
}

// AdvanceFrontier persists the frontier forward to (seq, root). It MUST be
// called ONLY after the tiles for root are durably PUT-ack'd. Monotonic: the
// WHERE guard makes a stale/out-of-order advance a no-op (frontier never
// regresses), while allowing an equal-seq re-advance to refresh the root for
// the genesis→first-batch transition (committed_through_seq can be 0 for the
// first committed entry).
func (s *PgTileFrontier) AdvanceFrontier(ctx context.Context, seq uint64, root [32]byte) error {
	_, err := s.db.Exec(ctx,
		`UPDATE tile_frontier
		 SET frontier_root = $2, frontier_seq = $1, updated_at = NOW()
		 WHERE id = 1 AND frontier_seq <= $1`,
		int64(seq), root[:],
	)
	if err != nil {
		return fmt.Errorf("store/tile-frontier: advance to %d: %w", seq, err)
	}
	return nil
}

// SMTCommitCursor adapts SMTRootStateStore to the reconciler's commit-cursor
// reader: it reports the durable commit cursor (committed_through_seq) and the
// SMT root at that seq.
type SMTCommitCursor struct {
	rs *SMTRootStateStore
}

// NewSMTCommitCursor wraps an SMTRootStateStore as a commit-cursor reader.
func NewSMTCommitCursor(rs *SMTRootStateStore) *SMTCommitCursor {
	return &SMTCommitCursor{rs: rs}
}

// ReadCommit returns (committed_through_seq, current_root).
func (c *SMTCommitCursor) ReadCommit(ctx context.Context) (uint64, [32]byte, error) {
	st, err := c.rs.Read(ctx)
	if err != nil {
		return 0, [32]byte{}, err
	}
	return st.CommittedThroughSeq, st.CurrentRoot, nil
}
