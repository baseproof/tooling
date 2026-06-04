package store

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/baseproof/baseproof/types"
)

// These tests pin the persistence-boundary contract behind the builder's
// coalesceLeafMutations fix: SetBatchTx persists leaves via ONE
// `INSERT … ON CONFLICT (leaf_key) DO UPDATE` statement, which Postgres rejects if
// the statement presents the same conflict key twice. The builder coalesces its
// ordered per-entry mutation log to one row per key before calling this; these
// tests cover both the happy path (coalesced → commits, last write wins) and the
// not-happy path (raw duplicate keys → the exact SQLSTATE 21000 that wedged the
// builder), plus the legitimate cross-batch upsert that must NOT regress.
//
// PG-gated via requireDB (BASEPROOF_TEST_DSN).

func dedupLeaf(b byte, originSeq, authSeq uint64) types.SMTLeaf {
	var k [32]byte
	k[0] = b
	return types.SMTLeaf{
		Key:          k,
		OriginTip:    types.LogPosition{LogDID: "did:web:dedup.test", Sequence: originSeq},
		AuthorityTip: types.LogPosition{LogDID: "did:web:dedup.test", Sequence: authSeq},
	}
}

// TestSetBatchTx_DuplicateKeysInOneBatch_Rejected — NOT-HAPPY / hazard proof.
// A root and a same-batch amendment of it produce TWO writes to the same leaf_key
// in the SDK's ordered mutation log. Fed RAW (un-coalesced) to SetBatchTx, the
// single ON CONFLICT statement carries the key twice and Postgres rejects it with
// SQLSTATE 21000 — the precise failure that stalled the builder at 30K. This test
// fails (regression!) if SetBatchTx ever silently accepts in-batch duplicates,
// which would mean the builder's coalescing had been removed without a replacement.
func TestSetBatchTx_DuplicateKeysInOneBatch_Rejected(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `TRUNCATE smt_leaves`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	ls := NewPostgresLeafStore(pool)

	dup := []types.SMTLeaf{
		dedupLeaf(0xA1, 1, 1), // root: leaf 0xA1 created
		dedupLeaf(0xA1, 5, 1), // amendment of 0xA1 in the SAME batch (origin tip advances)
	}
	err := WithSerializableTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		_, e := ls.SetBatchTx(ctx, tx, dup)
		return e
	})
	if err == nil {
		t.Fatal("SetBatchTx accepted a batch with a duplicate leaf_key — the ON CONFLICT hazard " +
			"is not reproduced; callers (the builder) MUST coalesce to one row per key first")
	}
	if !strings.Contains(err.Error(), "affect row a second time") {
		t.Fatalf("want the duplicate-conflict-key error (SQLSTATE 21000, 'cannot affect row a second time'), got: %v", err)
	}
}

// TestSetBatchTx_CoalescedBatch_PersistsLastWrite — HAPPY path. The coalesced shape
// (one row per key, carrying the amended/last-write state) commits, persists the
// final state, and reports RowsAffected == len(input) — the invariant the builder's
// post-commit collapse check relies on.
func TestSetBatchTx_CoalescedBatch_PersistsLastWrite(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `TRUNCATE smt_leaves`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	ls := NewPostgresLeafStore(pool)

	// What coalesceLeafMutations([root 0xB1, amend 0xB1→5, root 0xB2]) yields: 0xB1 at
	// its LAST write (origin 5), 0xB2 once.
	batch := []types.SMTLeaf{dedupLeaf(0xB1, 5, 1), dedupLeaf(0xB2, 2, 2)}
	var affected int64
	if err := WithSerializableTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		affected, e = ls.SetBatchTx(ctx, tx, batch)
		return e
	}); err != nil {
		t.Fatalf("SetBatchTx(coalesced): %v", err)
	}
	if affected != 2 {
		t.Fatalf("RowsAffected = %d, want 2 (== len(batch)); a mismatch breaks the builder's collapse check", affected)
	}
	got, err := ls.Get(ctx, dedupLeaf(0xB1, 0, 0).Key)
	if err != nil || got == nil {
		t.Fatalf("Get 0xB1: leaf=%v err=%v", got, err)
	}
	if got.OriginTip.Sequence != 5 {
		t.Fatalf("0xB1 origin tip = %d, want 5 (the last write the committed root reflects)", got.OriginTip.Sequence)
	}
	if got.AuthorityTip.Sequence != 1 {
		t.Fatalf("0xB1 authority tip = %d, want 1", got.AuthorityTip.Sequence)
	}
}

// TestSetBatchTx_CrossBatchUpsert_NotRegressed — NO-REGRESSION of the legitimate
// path. ON CONFLICT (leaf_key) exists to let a LATER batch update a leaf a PRIOR
// batch created (an amendment that lands in a different builder cycle than its
// root). That must keep working: the second batch updates the same key to its new
// state. (This is the across-statement case PG allows — distinct from the
// within-statement duplicate the first test rejects.)
func TestSetBatchTx_CrossBatchUpsert_NotRegressed(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `TRUNCATE smt_leaves`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	ls := NewPostgresLeafStore(pool)

	put := func(l types.SMTLeaf) {
		t.Helper()
		if err := WithSerializableTx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
			_, e := ls.SetBatchTx(ctx, tx, []types.SMTLeaf{l})
			return e
		}); err != nil {
			t.Fatalf("SetBatchTx: %v", err)
		}
	}
	put(dedupLeaf(0xC1, 1, 1)) // batch 1: create
	put(dedupLeaf(0xC1, 9, 1)) // batch 2: amend the same key (separate cycle)

	got, err := ls.Get(ctx, dedupLeaf(0xC1, 0, 0).Key)
	if err != nil || got == nil {
		t.Fatalf("Get 0xC1: leaf=%v err=%v", got, err)
	}
	if got.OriginTip.Sequence != 9 {
		t.Fatalf("0xC1 origin tip = %d, want 9 (cross-batch ON CONFLICT update)", got.OriginTip.Sequence)
	}
}
