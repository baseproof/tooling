package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/baseproof/baseproof/core/smt"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// fakeObjStore is an in-memory objectPutGetter so the S3 tile store is testable
// with no live S3/SeaweedFS. It returns bytestore.ErrNotFound on a miss, exactly
// as *bytestore.S3.GetObject does.
type fakeObjStore struct{ m map[string][]byte }

func (f *fakeObjStore) PutObject(_ context.Context, key string, data []byte) error {
	f.m[key] = append([]byte(nil), data...)
	return nil
}

func (f *fakeObjStore) GetObject(_ context.Context, key string) ([]byte, error) {
	b, ok := f.m[key]
	if !ok {
		return nil, bytestore.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

func (f *fakeObjStore) HeadObject(_ context.Context, key string) (bool, error) {
	_, ok := f.m[key]
	return ok, nil
}

func TestS3SMTTileStore_RoundTripKeyAndMiss(t *testing.T) {
	f := &fakeObjStore{m: map[string][]byte{}}
	ts := NewS3SMTTileStore(f)

	var id [32]byte
	id[0], id[1], id[31] = 0xab, 0xcd, 0xff
	want := []byte("encoded-tile-bytes")

	if err := ts.Put(context.Background(), id, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Keyed by the content-address fan-out path — the SAME key PosixSMTTileStore
	// uses, so the two backends share one namespace and a CDN fronts S3 verbatim.
	if _, ok := f.m[smt.TilePath(id)]; !ok {
		t.Fatalf("Put did not key by smt.TilePath; got keys=%v", keysOf(f.m))
	}

	got, err := ts.Fetch(context.Background(), id)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("Fetch = %q, want %q", got, want)
	}

	// A miss MUST surface as os.ErrNotExist (the smt.TiledNodeStore contract:
	// a clean absent node, not a backing-store error).
	var miss [32]byte
	miss[0] = 0x01
	if _, err := ts.Fetch(context.Background(), miss); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Fetch(miss) err = %v, want os.ErrNotExist", err)
	}

	// Exists is the exact `known` predicate: true for a present tile, false for a
	// miss (never a false positive — that would strand a needed tile).
	if ok, err := ts.Exists(context.Background(), id); err != nil || !ok {
		t.Fatalf("Exists(present) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := ts.Exists(context.Background(), miss); err != nil || ok {
		t.Fatalf("Exists(miss) = (%v, %v), want (false, nil)", ok, err)
	}
}

func keysOf(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
