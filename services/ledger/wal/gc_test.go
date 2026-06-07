package wal

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
)

func newGCCommitter(t *testing.T, retentionBuffer uint64) *Committer {
	t.Helper()
	db, err := OpenInMemory(nil)
	if err != nil {
		t.Fatalf("OpenInMemory: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewCommitter(db, CommitterConfig{
		QueueSize:       256,
		BatchMaxEntries: 16,
		DisableSync:     true,
		RetentionBuffer: retentionBuffer,
	})
}

// seqEntry builds a unique entry for seq and submits + sequences it. ship=true also
// marks it shipped (the GC-eligible state).
func seqEntry(t *testing.T, c *Committer, ctx context.Context, seq uint64, ship bool) [32]byte {
	t.Helper()
	wire := make([]byte, 16)
	binary.BigEndian.PutUint64(wire, seq)
	binary.BigEndian.PutUint64(wire[8:], seq*2654435761)
	hash := sha256.Sum256(wire)
	if err := c.Submit(ctx, hash, wire, time.Now().UnixMicro(), nil); err != nil {
		t.Fatalf("Submit seq=%d: %v", seq, err)
	}
	if err := c.Sequence(ctx, hash, seq); err != nil {
		t.Fatalf("Sequence seq=%d: %v", seq, err)
	}
	if ship {
		if err := c.MarkShipped(ctx, hash); err != nil {
			t.Fatalf("MarkShipped seq=%d: %v", seq, err)
		}
	}
	return hash
}

func keyExists(c *Committer, key []byte) bool {
	exists := false
	_ = c.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		exists = err == nil
		return nil
	})
	return exists
}

func liveAt(c *Committer, hash [32]byte, seq uint64) bool {
	return keyExists(c, entryKey(hash)) || keyExists(c, metaKey(hash)) || keyExists(c, seqIndexKey(seq))
}

// TestGCBelowRetention_DeletesShippedBelowCutoff is the core: with HWM=N and buffer B,
// every shipped seq in [1, N-B] has its entry:/meta:/seq_index: removed, and the most
// recent B shipped entries are retained intact.
func TestGCBelowRetention_DeletesShippedBelowCutoff(t *testing.T) {
	ctx := context.Background()
	c := newGCCommitter(t, 3)
	const N = 10
	hashes := map[uint64][32]byte{}
	for s := uint64(1); s <= N; s++ {
		hashes[s] = seqEntry(t, c, ctx, s, true)
	}
	if err := c.AdvanceHWM(ctx, N); err != nil {
		t.Fatalf("AdvanceHWM: %v", err)
	}

	reclaimed, err := c.GCBelowRetention(ctx)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if reclaimed != 7 { // cutoff = 10-3 = 7 → seqs 1..7
		t.Fatalf("reclaimed = %d, want 7", reclaimed)
	}
	for s := uint64(1); s <= N; s++ {
		wantLive := s > 7 // 8,9,10 retained by the buffer
		if got := liveAt(c, hashes[s], s); got != wantLive {
			t.Fatalf("seq=%d live=%v, want %v", s, got, wantLive)
		}
	}
	// A retained entry is still fully readable.
	if !keyExists(c, entryKey(hashes[10])) || !keyExists(c, metaKey(hashes[10])) || !keyExists(c, seqIndexKey(10)) {
		t.Fatal("retained seq 10 missing a record after GC")
	}
}

// TestGCBelowRetention_FailClosedOnUnshipped is the SAFETY gate: even with a wrong
// (too-high) HWM, the GC must NOT delete a seq that is not StateShipped.
func TestGCBelowRetention_FailClosedOnUnshipped(t *testing.T) {
	ctx := context.Background()
	c := newGCCommitter(t, 3)
	hashes := map[uint64][32]byte{}
	for s := uint64(1); s <= 10; s++ {
		hashes[s] = seqEntry(t, c, ctx, s, s != 2) // seq 2 sequenced-only (NOT shipped)
	}
	// Force a wrong HWM (seq 2 is not shipped) to exercise the defensive guard.
	if err := c.AdvanceHWM(ctx, 10); err != nil {
		t.Fatalf("AdvanceHWM: %v", err)
	}

	reclaimed, err := c.GCBelowRetention(ctx)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if reclaimed != 6 { // cutoff 7; shipped 1,3,4,5,6,7 deleted; seq 2 skipped
		t.Fatalf("reclaimed = %d, want 6", reclaimed)
	}
	if !liveAt(c, hashes[2], 2) {
		t.Fatal("FAIL-CLOSED VIOLATED: GC deleted un-shipped seq 2")
	}
}

// TestGCBelowRetention_Disabled: a zero RetentionBuffer never deletes.
func TestGCBelowRetention_Disabled(t *testing.T) {
	ctx := context.Background()
	c := newGCCommitter(t, 0)
	for s := uint64(1); s <= 5; s++ {
		seqEntry(t, c, ctx, s, true)
	}
	_ = c.AdvanceHWM(ctx, 5)
	if reclaimed, err := c.GCBelowRetention(ctx); err != nil || reclaimed != 0 {
		t.Fatalf("disabled GC: reclaimed=%d err=%v, want 0/nil", reclaimed, err)
	}
}

// TestGCBelowRetention_BelowBuffer: nothing aged past the buffer yet → no-op.
func TestGCBelowRetention_BelowBuffer(t *testing.T) {
	ctx := context.Background()
	c := newGCCommitter(t, 100)
	for s := uint64(1); s <= 5; s++ {
		seqEntry(t, c, ctx, s, true)
	}
	_ = c.AdvanceHWM(ctx, 5)
	if reclaimed, err := c.GCBelowRetention(ctx); err != nil || reclaimed != 0 {
		t.Fatalf("below-buffer GC: reclaimed=%d err=%v, want 0/nil", reclaimed, err)
	}
}

// TestGCBelowRetention_Idempotent: a second GC over the same state deletes nothing.
func TestGCBelowRetention_Idempotent(t *testing.T) {
	ctx := context.Background()
	c := newGCCommitter(t, 2)
	for s := uint64(1); s <= 8; s++ {
		seqEntry(t, c, ctx, s, true)
	}
	_ = c.AdvanceHWM(ctx, 8)
	first, err := c.GCBelowRetention(ctx)
	if err != nil || first != 6 { // cutoff 6 → seqs 1..6
		t.Fatalf("first GC: %d err=%v, want 6", first, err)
	}
	second, err := c.GCBelowRetention(ctx)
	if err != nil || second != 0 {
		t.Fatalf("second GC: %d err=%v, want 0 (idempotent)", second, err)
	}
}

// TestDiskBytes returns a non-negative size and never panics.
func TestDiskBytes(t *testing.T) {
	c := newGCCommitter(t, 0)
	if c.DiskBytes() < 0 {
		t.Fatal("DiskBytes negative")
	}
}
