/*
FILE PATH: wal/gc.go

WAL retention GC (Phase 2, 2.1) — the ONLY deletion site in the WAL keyspace.

Once an entry is durably shipped to the byte store, its WAL copy is dead weight.
GCBelowRetention removes entry:/meta:/seq_index: for every SHIPPED entry whose seq is
below HWM-RetentionBuffer (the high-water mark of contiguously-shipped seqs, minus a
safety buffer of the most-recent shipped entries), then reclaims the freed value-log
space. Without it the WAL grows with TOTAL lifetime entries (10B) and exhausts disk;
with it the WAL is bounded to (un-shipped backlog + RetentionBuffer).

SAFETY — this is the only path that deletes committed bytes, so it fails CLOSED:
  - cutoff = HWM - RetentionBuffer; only seqs <= cutoff are eligible. Every seq <= HWM
    is contiguously shipped by construction (the Shipper advances HWM only through a
    contiguous Shipped run), and the buffer leaves the most-recent shipped entries for
    late readers / boot reconciliation.
  - a per-entry check skips any seq whose Meta.State != StateShipped, so a wrong HWM
    can NEVER make the GC delete un-shipped or manual-retry bytes.
  - bounded batches keep each Badger txn small; idempotent + safe to call repeatedly,
    and concurrently with the single HWM-advancing goroutine.

Tessera's dedup keyspace (tessera_dedup:) is deliberately left intact — deleting it
would let a re-submission of a reclaimed entry be admitted as a duplicate.
*/
package wal

import (
	"context"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
)

// gcBatchMax bounds the seqs deleted per Badger txn (txn size + bounded work/call).
const gcBatchMax = 1000

// gcVLogPasses bounds value-log GC rewrites per call; the rest reclaim next call.
const gcVLogPasses = 8

// GCBelowRetention deletes WAL records for shipped entries below HWM-RetentionBuffer
// and reclaims freed value-log space. Returns the number of entries removed. A zero
// RetentionBuffer disables it (returns 0) — the WAL retains everything.
func (c *Committer) GCBelowRetention(ctx context.Context) (int, error) {
	if c.cfg.RetentionBuffer == 0 {
		return 0, nil // GC disabled — retain the whole WAL
	}
	hwm, err := c.HWM(ctx)
	if err != nil {
		return 0, err
	}
	if hwm <= c.cfg.RetentionBuffer {
		return 0, nil // nothing has aged past the buffer yet
	}
	cutoff := hwm - c.cfg.RetentionBuffer // delete shipped seqs in [1, cutoff]

	reclaimed := 0
	// INCREMENTAL: resume from the last reclaim cursor, not 0. Everything below
	// gcResumeSeq is already shipped-and-deleted, so re-walking it each cycle only
	// re-skips tombstones across the LSM — O(history) work that tapers throughput.
	// Resuming makes each pass scan only the newly-aged [gcResumeSeq, cutoff] range,
	// i.e. ~O(RetentionBuffer) regardless of total history. (Seek tolerates a
	// gcResumeSeq whose own key was already deleted — it lands on the next live key.)
	fromSeq := c.gcResumeSeq
	for {
		if err := ctx.Err(); err != nil {
			return reclaimed, err
		}
		batch, nextSeq, cErr := c.collectGCBatch(fromSeq, cutoff)
		if cErr != nil {
			return reclaimed, cErr
		}
		if len(batch) == 0 {
			break
		}
		if dErr := c.deleteGCBatch(batch); dErr != nil {
			return reclaimed, dErr
		}
		reclaimed += len(batch)
		fromSeq = nextSeq
	}
	// The full [gcResumeSeq, cutoff] range is now processed (all shipped seqs ≤
	// cutoff deleted); advance the cursor so the next pass starts above it. Only on
	// a clean completion — an early ctx/error return above leaves the cursor put,
	// so the next pass safely (idempotently) redoes the bounded partial range.
	c.gcResumeSeq = cutoff

	// Reclaim freed space: RunValueLogGC rewrites one log file when >= ratio of it is
	// stale, returning ErrNoRewrite when there is nothing left. Bounded passes.
	if reclaimed > 0 {
		for i := 0; i < gcVLogPasses; i++ {
			if vErr := c.db.RunValueLogGC(0.5); vErr != nil {
				break // ErrNoRewrite (nothing to reclaim) or another stop condition
			}
		}
	}
	return reclaimed, nil
}

// RetentionBuffer returns the configured GC margin in sequences (0 ⇒ GC disabled).
// The scheduler reads it to gate + size the work-driven trigger (GCDue).
func (c *Committer) RetentionBuffer() uint64 { return c.cfg.RetentionBuffer }

// GCDue reports whether retention GC should run now: the contiguously-SHIPPED
// high-water mark has advanced at least one RetentionBuffer past the last reclaim
// point. This is the WORK-DRIVEN trigger that replaces a wall-clock interval —
// GC cadence then tracks shipping throughput (high write rate ⇒ frequent small
// reclaims; an idle log stops triggering and simply holds its ~RetentionBuffer
// margin), so the WAL footprint stays bounded at ≈ unshipped-backlog +
// O(RetentionBuffer) at any scale, with nothing tuned to load. A zero buffer
// disables GC. Pure + side-effect-free so the scheduling decision is unit-tested
// without standing up a WAL.
func GCDue(shippedHWM, lastReclaimedHWM, retentionBuffer uint64) bool {
	if retentionBuffer == 0 {
		return false
	}
	return shippedHWM >= lastReclaimedHWM+retentionBuffer
}

// gcVictim is one (seq, hash) pair eligible for deletion.
type gcVictim struct {
	seq  uint64
	hash [32]byte
}

// collectGCBatch scans seq_index ascending from fromSeq up to cutoff, returning the
// next batch of SHIPPED victims (skipping any non-shipped seq — the fail-closed guard)
// and the seq to resume from. Read-only.
func (c *Committer) collectGCBatch(fromSeq, cutoff uint64) ([]gcVictim, uint64, error) {
	var batch []gcVictim
	nextSeq := fromSeq
	err := c.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte{prefixSeqIndex}
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(seqIndexKey(fromSeq)); it.Valid() && len(batch) < gcBatchMax; it.Next() {
			seq := seqFromIndexKey(it.Item().KeyCopy(nil))
			if seq > cutoff {
				break // ascending → nothing more in range
			}
			nextSeq = seq + 1
			var hash [32]byte
			if vErr := it.Item().Value(func(val []byte) error {
				if len(val) != 32 {
					return fmt.Errorf("wal/gc: bad seq_index value len=%d at seq=%d", len(val), seq)
				}
				copy(hash[:], val)
				return nil
			}); vErr != nil {
				return vErr
			}
			var meta Meta
			if mErr := readMeta(txn, hash, &meta); mErr != nil {
				if errors.Is(mErr, badger.ErrKeyNotFound) {
					continue // meta already gone (partial prior GC) — nothing to reclaim
				}
				return mErr
			}
			if meta.State != StateShipped {
				continue // FAIL-CLOSED: never delete un-shipped / manual bytes
			}
			batch = append(batch, gcVictim{seq: seq, hash: hash})
		}
		return nil
	})
	return batch, nextSeq, err
}

// deleteGCBatch removes entry:/meta:/seq_index: for each victim in one txn.
func (c *Committer) deleteGCBatch(batch []gcVictim) error {
	return c.db.Update(func(txn *badger.Txn) error {
		for _, v := range batch {
			if e := txn.Delete(seqIndexKey(v.seq)); e != nil {
				return e
			}
			if e := txn.Delete(entryKey(v.hash)); e != nil {
				return e
			}
			if e := txn.Delete(metaKey(v.hash)); e != nil {
				return e
			}
		}
		return nil
	})
}

// DiskBytes reports the WAL's on-disk size (LSM + value-log) — the
// baseproof_wal_disk_bytes gauge backing the 2.1 "disk flat post-ship" SLO.
func (c *Committer) DiskBytes() int64 {
	lsm, vlog := c.db.Size()
	return lsm + vlog
}
