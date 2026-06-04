package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/core/smt"
)

// commitRootTx runs fn inside a committed transaction (helper for the CAS test).
func commitRootTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("tx fn: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestSMTRootState_CAS validates the compare-and-swap guard on smt_root_state:
// a write lands only when the row still holds the (priorRoot, priorSeq) the
// caller read, and any stale prior is rejected with ErrRootCASMismatch — the
// defense that stops a deposed/duplicate builder from clobbering a newer root
// with this batch's older one.
func TestSMTRootState_CAS(t *testing.T) {
	pool := requireDB(t)
	// Register the pool close as a Cleanup, NOT a defer: t.Cleanup callbacks run
	// AFTER the test function (and its defers) return, in last-added-first order.
	// A `defer pool.Close()` would close the pool BEFORE the baseline-restore
	// Cleanup below runs, and that restore's pool.Begin would then hit "closed
	// pool". Registering Close first means it runs LAST — after the restore.
	t.Cleanup(pool.Close)
	ctx := context.Background()
	rs := NewSMTRootStateStore(pool)

	// Restore the migration-seeded empty-tree baseline at the end so this
	// singleton-row mutation doesn't contaminate sibling store tests.
	t.Cleanup(func() {
		commitRootTx(t, ctx, pool, func(tx pgx.Tx) error {
			return rs.SetTx(ctx, tx, smt.EmptyHash, 0)
		})
	})

	// Establish a known baseline (the row is a migration-seeded singleton).
	base := [32]byte{0x11, 0x22, 0x33}
	const baseSeq = uint64(41)
	commitRootTx(t, ctx, pool, func(tx pgx.Tx) error { return rs.SetTx(ctx, tx, base, baseSeq) })

	// CAS with the matching prior advances the row.
	next := [32]byte{0xAA, 0xBB, 0xCC}
	const nextSeq = uint64(42)
	commitRootTx(t, ctx, pool, func(tx pgx.Tx) error {
		return rs.SetTxCAS(ctx, tx, next, nextSeq, base, baseSeq)
	})
	got, err := rs.Read(ctx)
	if err != nil {
		t.Fatalf("read after CAS: %v", err)
	}
	if got.CurrentRoot != next || got.CommittedThroughSeq != nextSeq {
		t.Fatalf("after CAS = (%x, %d), want (%x, %d)", got.CurrentRoot[:4], got.CommittedThroughSeq, next[:4], nextSeq)
	}

	// CAS with a stale prior must be rejected; a stale root, a stale seq, or both
	// independently fail (each predicate is load-bearing).
	for _, tc := range []struct {
		name      string
		priorRoot [32]byte
		priorSeq  uint64
	}{
		{"stale root+seq", base, baseSeq},
		{"stale root only", base, nextSeq},
		{"stale seq only", next, baseSeq},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clobber := [32]byte{0xDE, 0xAD}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if casErr := rs.SetTxCAS(ctx, tx, clobber, 999, tc.priorRoot, tc.priorSeq); !errors.Is(casErr, ErrRootCASMismatch) {
				t.Fatalf("SetTxCAS stale prior: err = %v, want ErrRootCASMismatch", casErr)
			}
		})
	}

	// The row still holds the post-CAS state — no rejected write leaked through.
	got, err = rs.Read(ctx)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if got.CurrentRoot != next || got.CommittedThroughSeq != nextSeq {
		t.Fatalf("final = (%x, %d), want unchanged (%x, %d)", got.CurrentRoot[:4], got.CommittedThroughSeq, next[:4], nextSeq)
	}
}
