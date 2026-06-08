package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/bytestore"
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

// Publish populates the checkpoint-size index so the PG-off resolver can enumerate.
func TestS3Checkpoint_PublishPopulatesSizeIndex(t *testing.T) {
	obj := &fakeObjStore{m: map[string][]byte{}}
	pub := NewS3CheckpointPublisher(obj)
	ctx := context.Background()
	for _, n := range []uint64{7, 13, 21} {
		if err := pub.PublishCosignedCheckpoint(ctx, s3Head(n)); err != nil {
			t.Fatalf("publish %d: %v", n, err)
		}
	}
	got, ok, err := NewS3CheckpointSizeIndex(obj).AtOrAbove(ctx, 8, 21)
	if err != nil {
		t.Fatalf("AtOrAbove: %v", err)
	}
	if !ok || got != 13 {
		t.Fatalf("index AtOrAbove(8) = (%d,%v), want (13,true)", got, ok)
	}
}

// Fail-closed: when the size index can't be written, the publisher does NOT advance
// the horizon — a reader never sees a head whose covering checkpoint it can't resolve.
func TestS3Checkpoint_IndexFailureWithholdsHorizon(t *testing.T) {
	obj := &prefixFailObjStore{m: map[string][]byte{}, failPrefix: "checkpoint-index/"}
	pub := NewS3CheckpointPublisher(obj)
	if err := pub.PublishCosignedCheckpoint(context.Background(), s3Head(7)); err == nil {
		t.Fatal("publish must fail when the index write fails")
	}
	if _, ok := obj.m[cosignedCheckpointKey]; ok {
		t.Fatal("horizon was advanced despite a failed index write — not fail-closed")
	}
}

// prefixFailObjStore fails PutObject for keys under failPrefix (to prove fail-closed
// ordering), and otherwise behaves like the in-memory fake.
type prefixFailObjStore struct {
	m          map[string][]byte
	failPrefix string
}

func (f *prefixFailObjStore) PutObject(_ context.Context, key string, data []byte) error {
	if strings.HasPrefix(key, f.failPrefix) {
		return errors.New("forced put failure")
	}
	f.m[key] = append([]byte(nil), data...)
	return nil
}

func (f *prefixFailObjStore) GetObject(_ context.Context, key string) ([]byte, error) {
	b, ok := f.m[key]
	if !ok {
		return nil, bytestore.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

func (f *prefixFailObjStore) HeadObject(_ context.Context, key string) (bool, error) {
	_, ok := f.m[key]
	return ok, nil
}
