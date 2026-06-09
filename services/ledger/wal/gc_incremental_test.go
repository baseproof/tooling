package wal

import (
	"context"
	"testing"
)

// TestGCBelowRetention_IncrementalResume proves the GC resumes from its cursor
// instead of re-walking seq_index from 0 each cycle: a second pass reclaims ONLY
// the newly-aged range and advances the cursor, never re-touching the already-
// deleted prefix. (Helpers newGCCommitter/seqEntry live in gc_test.go.)
func TestGCBelowRetention_IncrementalResume(t *testing.T) {
	ctx := context.Background()
	c := newGCCommitter(t, 2) // RetentionBuffer = 2

	// Cycle 1: seqs 1..8, HWM 8 → cutoff 6 → reclaim 1..6; cursor advances to 6.
	for s := uint64(1); s <= 8; s++ {
		seqEntry(t, c, ctx, s, true)
	}
	_ = c.AdvanceHWM(ctx, 8)
	if n, err := c.GCBelowRetention(ctx); err != nil || n != 6 {
		t.Fatalf("cycle 1: reclaimed %d err=%v, want 6", n, err)
	}
	if c.gcResumeSeq != 6 {
		t.Fatalf("cursor = %d after cycle 1, want 6", c.gcResumeSeq)
	}

	// Cycle 2: add seqs 9..16, HWM 16 → cutoff 14. The newly-aged range is [7, 14]
	// (7,8 were within the old buffer, now aged; 9..14 new). The prune resumes from
	// the cursor (6) — seqs 1..6 are gone and are NOT re-scanned — so it reclaims
	// exactly 8 (seqs 7..14) and the cursor advances to 14.
	for s := uint64(9); s <= 16; s++ {
		seqEntry(t, c, ctx, s, true)
	}
	_ = c.AdvanceHWM(ctx, 16)
	if n, err := c.GCBelowRetention(ctx); err != nil || n != 8 {
		t.Fatalf("cycle 2: reclaimed %d err=%v, want 8 (seqs 7..14)", n, err)
	}
	if c.gcResumeSeq != 14 {
		t.Fatalf("cursor = %d after cycle 2, want 14", c.gcResumeSeq)
	}

	// Cycle 3 with no new entries past the buffer: nothing to reclaim, cursor put.
	if n, err := c.GCBelowRetention(ctx); err != nil || n != 0 {
		t.Fatalf("cycle 3: reclaimed %d err=%v, want 0", n, err)
	}
	if c.gcResumeSeq != 14 {
		t.Fatalf("cursor = %d after cycle 3, want 14 (unchanged)", c.gcResumeSeq)
	}
}
