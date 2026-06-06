package builder

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/core/smt"

	"github.com/baseproof/tooling/services/ledger/store"
)

// After a working cycle publishes, committed == published ⇒ horizon lag 0.
func TestCheckpoint_HorizonLag_ZeroAfterPublish(t *testing.T) {
	commit := &fakeCommit{seq: 9, root: rootN(0x55)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	loop := newLoop(commit, frontier, newFakeTiles(), &fakeWitness{}, &fakePublisher{})

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	if got := loop.HorizonLag(); got != 0 {
		t.Fatalf("horizon lag after publish = %d, want 0", got)
	}
}

// A HOLD (witness outage) advances committed but not published ⇒ lag > 0,
// equal to the committed tree_size since nothing has ever published.
func TestCheckpoint_HorizonLag_HoldShowsLag(t *testing.T) {
	commit := &fakeCommit{seq: 9, root: rootN(0x55)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	loop := newLoop(commit, frontier, newFakeTiles(), &fakeWitness{err: errors.New("witness down")}, &fakePublisher{})

	// Holds (witness down) — nothing published.
	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	want := int64(store.TreeSizeForCommittedSeq(9)) // committed − published(0)
	if got := loop.HorizonLag(); got != want {
		t.Fatalf("horizon lag during hold = %d, want %d", got, want)
	}
	if want <= 0 {
		t.Fatalf("test precondition: committed tree_size should be > 0, got %d", want)
	}
}
