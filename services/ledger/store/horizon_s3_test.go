package store

import (
	"context"
	"errors"
	"os"
	"testing"

	sdktypes "github.com/baseproof/baseproof/types"
)

func s3Head(n uint64) sdktypes.CosignedTreeHead {
	return sdktypes.CosignedTreeHead{TreeHead: sdktypes.TreeHead{TreeSize: n, SMTRoot: [32]byte{byte(n)}}}
}

// TestS3Checkpoint_DualWriteAndReadAt is the S3-path +/- for 1.1a: the publisher
// writes BOTH the latest checkpoint and a per-size archive at checkpoints/<N>,
// and S3HorizonReader.ReadCheckpointAt reads exactly that — a publisher→reader
// round-trip at the agreed key, PG-free. An un-archived size is os.ErrNotExist
// (a genuine not-found, never a fabricated head).
func TestS3Checkpoint_DualWriteAndReadAt(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	pub := NewS3CheckpointPublisher(obj)
	reader := NewS3HorizonReader(obj)
	ctx := context.Background()

	sizes := []uint64{7, 13, 21}
	for _, n := range sizes {
		if err := pub.PublishCosignedCheckpoint(ctx, s3Head(n)); err != nil {
			t.Fatalf("publish %d: %v", n, err)
		}
	}

	if _, ok := obj.m["cosigned-checkpoint"]; !ok {
		t.Fatal("latest cosigned-checkpoint not written")
	}
	// The archive retains EVERY size (the latest is overwritten, the archive is not).
	for _, n := range sizes {
		head, raw, err := reader.ReadCheckpointAt(ctx, n)
		if err != nil {
			t.Fatalf("ReadCheckpointAt(%d): %v", n, err)
		}
		if head.TreeSize != n {
			t.Errorf("ReadCheckpointAt(%d): TreeSize = %d", n, head.TreeSize)
		}
		if len(raw) == 0 {
			t.Errorf("ReadCheckpointAt(%d): empty raw", n)
		}
	}

	if _, _, err := reader.ReadCheckpointAt(ctx, 999); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadCheckpointAt(999): err = %v, want os.ErrNotExist", err)
	}
}

// TestS3Checkpoint_ArchiveKeyScheme pins the S3 archive key to checkpoints/<N>,
// matching the POSIX writer (tessera) and the api reader.
func TestS3Checkpoint_ArchiveKeyScheme(t *testing.T) {
	if got := checkpointArchiveKey(12345); got != "checkpoints/12345" {
		t.Fatalf("checkpointArchiveKey = %q, want checkpoints/12345", got)
	}
}
