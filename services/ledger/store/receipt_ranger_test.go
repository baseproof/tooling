package store

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// TestEntryIndexReceiptRanger_MetadataOnly proves the checkpoint loop's
// ReceiptRoot is a function of entry_index METADATA alone — the ranger is
// constructed with ONLY a *pgxpool.Pool (no byte reader, no WAL), so it cannot
// depend on the Badger WAL byte-availability state machine. It also pins the
// dense-over-existing-seqs semantics (gaps skipped) the builder's per-batch
// Step 6c had.
func TestEntryIndexReceiptRanger_MetadataOnly(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `TRUNCATE entry_index CASCADE`); err != nil {
		t.Fatalf("truncate entry_index: %v", err)
	}

	const logDID = "did:web:ranger.test"
	es := NewEntryStore(pool)

	// Insert entries at seqs {0,1,2,4,5} — a GAP at 3 (a tombstone/ghost would
	// produce the same hole). No web3_receipts ⇒ each entry's receipt hash is the
	// empty-set sentinel.
	present := []uint64{0, 1, 2, 4, 5}
	rows := make([]EntryRow, 0, len(present))
	for _, s := range present {
		var h [32]byte
		binary.BigEndian.PutUint64(h[:8], s+1) // unique canonical_hash
		rows = append(rows, EntryRow{
			SequenceNumber: s,
			CanonicalHash:  h,
			LogTime:        time.Unix(int64(s), 0).UTC(),
			SignerDID:      "did:web:signer",
			Status:         StatusLive,
		})
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := es.InsertBatch(ctx, tx, rows); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("InsertBatch: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Constructed with ONLY a pool — there is no byte reader to consult, so this
	// cannot stall on a shipped+pruned WAL entry.
	r := NewEntryIndexReceiptRanger(pool, logDID)

	empty, err := types.EntryReceiptHash(nil)
	if err != nil {
		t.Fatalf("EntryReceiptHash(nil): %v", err)
	}
	want := func(seqs ...uint64) [32]byte {
		c := make([]smt.ReceiptCommitment, 0, len(seqs))
		for _, s := range seqs {
			c = append(c, smt.ReceiptCommitment{
				Position:    types.LogPosition{LogDID: logDID, Sequence: s},
				ReceiptHash: empty,
			})
		}
		return smt.ReceiptRoot(c)
	}
	check := func(name string, from, to uint64, w [32]byte) {
		got, err := r.ReceiptRoot(ctx, from, to)
		if err != nil {
			t.Fatalf("%s: ReceiptRoot(%d,%d): %v", name, from, to, err)
		}
		if got != w {
			t.Fatalf("%s: ReceiptRoot(%d,%d) = %x, want %x", name, from, to, got[:6], w[:6])
		}
	}

	check("full range (gap at 3 skipped)", 0, 5, want(0, 1, 2, 4, 5))
	check("sub-range", 1, 2, want(1, 2))
	check("gap-spanning sub-range skips 3", 2, 4, want(2, 4))
	check("empty range (no rows)", 100, 100, [32]byte{})
	check("inverted range", 9, 8, [32]byte{})

	// Every present seq's receipt inclusion proof reconstructs the SAME checkpoint
	// ReceiptRoot the cosigned head commits — the third cosigned-root leg the v2
	// receipt_proof binds to. A target in the gap (seq 3) has no receipt to prove.
	root := want(0, 1, 2, 4, 5)
	for _, s := range present {
		p, err := r.ReceiptInclusionProof(ctx, 0, 5, s)
		if err != nil {
			t.Fatalf("ReceiptInclusionProof(0,5,%d): %v", s, err)
		}
		if err := smt.VerifyReceiptInclusion(p, root); err != nil {
			t.Fatalf("seq %d: inclusion proof does not reconstruct the checkpoint ReceiptRoot: %v", s, err)
		}
	}
	if _, err := r.ReceiptInclusionProof(ctx, 0, 5, 3); err == nil {
		t.Fatal("seq 3 (a gap) must have no receipt inclusion proof")
	}
}
