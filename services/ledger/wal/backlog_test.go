package wal

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
)

// Backlog = highest sequenced seq − HWM (the shipper's true queue depth).
func TestCommitter_Backlog(t *testing.T) {
	c, _ := openTestCommitter(t)
	ctx := context.Background()

	if got := c.Backlog(); got != 0 {
		t.Fatalf("empty WAL backlog = %d, want 0", got)
	}

	// Sequence seqs 0..4.
	for i := uint64(0); i < 5; i++ {
		wire := []byte(fmt.Sprintf("backlog-entry-%d", i))
		h := sha256.Sum256(wire)
		if err := c.Submit(ctx, h, wire, int64(i+1), nil); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
		if err := c.Sequence(ctx, h, i); err != nil {
			t.Fatalf("sequence %d: %v", i, err)
		}
	}

	// Nothing shipped (HWM=0): highest=4 − 0 = 4.
	if got := c.Backlog(); got != 4 {
		t.Fatalf("backlog after sequencing 0..4 = %d, want 4", got)
	}
	// Ship through HWM=2: 4 − 2 = 2.
	if err := c.AdvanceHWM(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if got := c.Backlog(); got != 2 {
		t.Fatalf("backlog at HWM=2 = %d, want 2", got)
	}
	// Caught up (HWM=4): 0.
	if err := c.AdvanceHWM(ctx, 4); err != nil {
		t.Fatal(err)
	}
	if got := c.Backlog(); got != 0 {
		t.Fatalf("backlog at HWM=4 = %d, want 0", got)
	}
}
