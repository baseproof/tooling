package store

import (
	"context"
	"errors"
	"testing"
)

// fakeLadder yields a scripted ascending set of cosigned sizes.
type fakeLadder struct {
	sizes []uint64
	err   error
}

func (f fakeLadder) CosignedSizeAtOrAbove(_ context.Context, minSize uint64, _ int) (uint64, bool, error) {
	if f.err != nil {
		return 0, false, f.err
	}
	for _, s := range f.sizes {
		if s >= minSize {
			return s, true, nil
		}
	}
	return 0, false, nil
}

// TestArchiveBackfill_WalksLadderWithCorrectRanges: the job visits every checkpoint
// ascending and archives each head + the receipt delta [prevSize, size-1], then the
// rotation index once.
func TestArchiveBackfill_WalksLadderWithCorrectRanges(t *testing.T) {
	var cps []uint64
	type rng struct{ cover, from, to uint64 }
	var rcs []rng
	rotations := 0

	j := NewArchiveBackfillJob(
		fakeLadder{sizes: []uint64{10, 25, 40}}, 1,
		func(_ context.Context, size uint64) error { cps = append(cps, size); return nil },
		func(_ context.Context, cover, from, to uint64) error { rcs = append(rcs, rng{cover, from, to}); return nil },
		func(_ context.Context) error { rotations++; return nil },
		nil)

	rep, err := j.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.Checkpoints != 3 {
		t.Fatalf("walked %d checkpoints, want 3", rep.Checkpoints)
	}
	if len(cps) != 3 || cps[0] != 10 || cps[1] != 25 || cps[2] != 40 {
		t.Fatalf("checkpoint archive sizes = %v, want [10 25 40]", cps)
	}
	want := []rng{{10, 0, 9}, {25, 10, 24}, {40, 25, 39}}
	if len(rcs) != 3 {
		t.Fatalf("receipt ops = %d, want 3", len(rcs))
	}
	for i, w := range want {
		if rcs[i] != w {
			t.Fatalf("receipt op[%d] = %+v, want %+v", i, rcs[i], w)
		}
	}
	if rotations != 1 {
		t.Fatalf("rotation archived %d times, want exactly 1", rotations)
	}
}

// TestArchiveBackfill_BestEffortPerItem: a per-item archive error is counted and the
// walk continues (history is not abandoned on one bad checkpoint).
func TestArchiveBackfill_BestEffortPerItem(t *testing.T) {
	j := NewArchiveBackfillJob(
		fakeLadder{sizes: []uint64{10, 25, 40}}, 1,
		func(_ context.Context, size uint64) error {
			if size == 25 {
				return errors.New("object store hiccup")
			}
			return nil
		},
		func(_ context.Context, _, _, _ uint64) error { return errors.New("receipts down") },
		func(_ context.Context) error { return errors.New("rotation down") },
		nil)

	rep, err := j.Run(context.Background())
	if err != nil {
		t.Fatalf("best-effort errors must not abort the run: %v", err)
	}
	if rep.Checkpoints != 3 {
		t.Fatalf("walk must continue past errors: visited %d, want 3", rep.Checkpoints)
	}
	if rep.CheckpointErrs != 1 || rep.ReceiptErrs != 3 || !rep.RotationErr {
		t.Fatalf("report = %+v, want 1 checkpoint err, 3 receipt errs, rotation err", rep)
	}
}

// TestArchiveBackfill_LadderErrorAborts: a PG enumeration fault aborts with an error
// (distinct from per-item best-effort).
func TestArchiveBackfill_LadderErrorAborts(t *testing.T) {
	j := NewArchiveBackfillJob(fakeLadder{err: errors.New("pg down")}, 1, nil, nil, nil, nil)
	if _, err := j.Run(context.Background()); err == nil {
		t.Fatal("a ladder enumeration error must abort the run")
	}
}

// TestArchiveBackfill_EmptyLadder: a log with no cosigned checkpoints yet archives
// nothing but the rotation index (and does not error).
func TestArchiveBackfill_EmptyLadder(t *testing.T) {
	rotations := 0
	j := NewArchiveBackfillJob(fakeLadder{sizes: nil}, 1, nil, nil,
		func(_ context.Context) error { rotations++; return nil }, nil)
	rep, err := j.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Checkpoints != 0 || rotations != 1 {
		t.Fatalf("empty ladder: checkpoints=%d rotations=%d, want 0 and 1", rep.Checkpoints, rotations)
	}
}
