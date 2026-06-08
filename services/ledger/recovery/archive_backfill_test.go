/*
FILE PATH: recovery/archive_backfill_test.go

G1 acceptance — the operator can backfill cold archives for PRE-ARCHIVE history.

Models a network that ran before the forward archivers shipped: its cosigned heads are
in Postgres (tree_heads) but the object store has NO per-size checkpoint archives, NO
size index, and NO receipts for the historical range — only the latest published horizon.
In that state a cold receipt proof for an old seq resolves to the WRONG covering
checkpoint (the only one indexed). After `recovery.ArchiveBackfill`, every historical
checkpoint is regenerated from the PG ladder and the cold resolver — reading the object
store alone — finds the CORRECT covering checkpoint, the earliest history, and the
archived heads. That is precisely the precondition a bounded Postgres depends on.

Skips when BASEPROOF_TEST_DSN is unset (store.IsolatedDB).
*/
package recovery

import (
	"context"
	"testing"

	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store"
)

const archiveBackfillTestLogDID = "did:example:archive-backfill-test"

func TestArchiveBackfill_RegeneratesColdArchivesForHistory(t *testing.T) {
	ctx := context.Background()
	pool := store.IsolatedDB(t)
	heads := store.NewTreeHeadStore(pool)
	obj := newMemObjStore()
	const minSigs = 1

	// ── A cosigned ladder in Postgres at sizes 10, 25, 40 — but the object store holds
	//    NONE of their per-size archives (the pre-archive state). One sig each so the
	//    ladder (CosignedSizeAtOrAbove, minSigs=1) returns them.
	for _, size := range []uint64{10, 25, 40} {
		var rootHash, smtRoot, receiptRoot [32]byte
		rootHash[0], smtRoot[0], receiptRoot[0] = byte(size), byte(size), byte(size)
		if err := heads.InsertHead(ctx, size, rootHash, smtRoot, receiptRoot, 0); err != nil {
			t.Fatalf("InsertHead(%d): %v", size, err)
		}
		if err := heads.InsertSig(ctx, size, 0, "witness:test", 1, []byte(`{"sig":"x"}`)); err != nil {
			t.Fatalf("InsertSig(%d): %v", size, err)
		}
	}

	// The live (now archive-capable) writer has published its CURRENT head (size 40), so
	// the horizon exists and 40 is archived+indexed — but the historical 10/25 are not.
	if err := store.NewS3CheckpointPublisher(obj).PublishCosignedCheckpoint(ctx, sizedHead(40)); err != nil {
		t.Fatalf("publish latest horizon: %v", err)
	}

	resolver := store.NewS3ReceiptHeadResolver(store.NewS3CheckpointSizeIndex(obj), store.NewS3HorizonReader(obj))

	// ── BEFORE: an entry at seq 14 (covered by checkpoint 25) resolves to the WRONG
	//    covering checkpoint — 40, the only one indexed — and checkpoints/25 is absent.
	if got, ok, err := resolver.CosignedSizeAtOrAbove(ctx, 15, minSigs); err != nil || !ok || got != 40 {
		t.Fatalf("pre-backfill AtOrAbove(15) = (%d,%v,%v); want (40,true,nil) — only the latest checkpoint is archived", got, ok, err)
	}
	if has, _ := obj.HeadObject(ctx, "checkpoints/25"); has {
		t.Fatal("pre-backfill: checkpoints/25 must be ABSENT (historical archive missing)")
	}

	// ── Run the operator backfill (the G1 entrypoint).
	rep, err := ArchiveBackfill(ctx, ArchiveBackfillDeps{
		Pool: pool, ObjectStore: obj, LogDID: archiveBackfillTestLogDID, MinSigs: minSigs,
	})
	if err != nil {
		t.Fatalf("ArchiveBackfill: %v", err)
	}
	if rep.Checkpoints != 3 || rep.CheckpointErrs != 0 {
		t.Fatalf("backfill report = %+v; want 3 checkpoints, 0 checkpoint errors", rep)
	}

	// ── AFTER: history is regenerated. Reading the OBJECT STORE ALONE, the cold resolver
	//    now finds the CORRECT covering checkpoint for the old seq, the earliest history,
	//    the receipt-range start, and the archived head — none of which existed before.
	if got, ok, err := resolver.CosignedSizeAtOrAbove(ctx, 15, minSigs); err != nil || !ok || got != 25 {
		t.Fatalf("post-backfill AtOrAbove(15) = (%d,%v,%v); want (25,true,nil) — covering checkpoint regenerated", got, ok, err)
	}
	if got, ok, err := resolver.CosignedSizeAtOrAbove(ctx, 1, minSigs); err != nil || !ok || got != 10 {
		t.Fatalf("post-backfill AtOrAbove(1) = (%d,%v,%v); want (10,true,nil) — earliest history reachable", got, ok, err)
	}
	if got, ok, err := resolver.CosignedSizeBelow(ctx, 25, minSigs); err != nil || !ok || got != 10 {
		t.Fatalf("post-backfill Below(25) = (%d,%v,%v); want (10,true,nil) — receipt-range start", got, ok, err)
	}
	head, err := resolver.GetBySize(ctx, 10)
	if err != nil || head == nil || head.TreeSize != 10 {
		t.Fatalf("post-backfill GetBySize(10) = (%+v, %v); want a head with TreeSize 10", head, err)
	}
	for _, key := range []string{"checkpoints/10", "checkpoints/25", "receipts/10", "receipts/25"} {
		if has, _ := obj.HeadObject(ctx, key); !has {
			t.Errorf("post-backfill: %s must be present (regenerated from the ladder)", key)
		}
	}

	// ── Idempotent: a second run re-archives identical bytes — no ladder error, same walk.
	rep2, err := ArchiveBackfill(ctx, ArchiveBackfillDeps{
		Pool: pool, ObjectStore: obj, LogDID: archiveBackfillTestLogDID, MinSigs: minSigs,
	})
	if err != nil || rep2.Checkpoints != 3 {
		t.Fatalf("re-run must be idempotent: report=%+v err=%v", rep2, err)
	}
}

// sizedHead is a minimal cosigned head at a given tree size (the published-horizon stand-in).
func sizedHead(n uint64) sdktypes.CosignedTreeHead {
	var rootHash, smtRoot, receiptRoot [32]byte
	rootHash[0], smtRoot[0], receiptRoot[0] = byte(n), byte(n), byte(n)
	return sdktypes.CosignedTreeHead{TreeHead: sdktypes.TreeHead{
		TreeSize: n, RootHash: rootHash, SMTRoot: smtRoot, ReceiptRoot: receiptRoot,
	}}
}
