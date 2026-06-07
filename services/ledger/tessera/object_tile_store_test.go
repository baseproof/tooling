/*
FILE PATH: tessera/object_tile_store_test.go

Self-contained tests for ObjectTileBackend and the shared in-memory
fakeObjectStore (reused by tile_shipper_test.go). No live S3/SeaweedFS: the fake
returns bytestore.ErrNotFound on a miss exactly as *bytestore.S3.GetObject does,
so the os.ErrNotExist mapping the partial→full fallback depends on is exercised
for real.
*/
package tessera

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// fakeObjectStore is an in-memory ObjectStore. The mutex makes it safe for the
// proof builder's concurrent tile reads in the end-to-end shipper test.
type fakeObjectStore struct {
	mu        sync.Mutex
	m         map[string][]byte
	puts      int    // total PutObject calls — lets a test assert minimal/idempotent shipping
	putErr    error  // when non-nil, every PutObject fails (exercises fail-closed)
	putErrKey string // when set, PutObject fails only for this key (e.g. the cursor)
	getErr    error  // when non-nil, GetObject returns this (a non-ErrNotFound fault)
}

func newFakeObjectStore() *fakeObjectStore { return &fakeObjectStore{m: map[string][]byte{}} }

func (f *fakeObjectStore) PutObject(_ context.Context, key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	if f.putErrKey != "" && key == f.putErrKey {
		return fmt.Errorf("put %q rejected", key)
	}
	f.m[key] = append([]byte(nil), data...)
	f.puts++
	return nil
}

func (f *fakeObjectStore) GetObject(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	b, ok := f.m[key]
	if !ok {
		return nil, bytestore.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

func (f *fakeObjectStore) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ks := make([]string, 0, len(f.m))
	for k := range f.m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (f *fakeObjectStore) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.m[key]
	return ok
}

func TestObjectTileBackend_RoundTrip(t *testing.T) {
	f := newFakeObjectStore()
	b := NewObjectTileBackend(f)
	ctx := context.Background()

	const path = "tile/0/x001/067"
	want := []byte("hash-tile-bytes")
	// Keyed by the bare tlog-tiles path (tesseraTileKey identity) — the SAME key
	// the shipper writes, so the two never drift.
	if err := f.PutObject(ctx, tesseraTileKey(path), want); err != nil {
		t.Fatalf("seed PutObject: %v", err)
	}

	got, err := b.ReadTileByPath(ctx, path)
	if err != nil {
		t.Fatalf("ReadTileByPath: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("ReadTileByPath = %q, want %q", got, want)
	}
}

func TestObjectTileBackend_MissMapsToErrNotExist(t *testing.T) {
	b := NewObjectTileBackend(newFakeObjectStore())
	// A miss MUST surface as os.ErrNotExist — the sentinel TileReader.Fetch uses to
	// fall back partial→full and the proof builder treats as "not yet integrated".
	// Anything else would turn a clean frontier miss into a hard proof failure.
	_, err := b.ReadTileByPath(context.Background(), "tile/0/x000/000")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("miss err = %v, want os.ErrNotExist", err)
	}
}

func TestObjectTileBackend_EmptyPathRejected(t *testing.T) {
	b := NewObjectTileBackend(newFakeObjectStore())
	if _, err := b.ReadTileByPath(context.Background(), ""); err == nil {
		t.Fatal("ReadTileByPath(\"\") = nil err, want non-nil")
	}
}

func TestObjectTileBackend_PropagatesBackingError(t *testing.T) {
	// A real backing-store fault (NOT a miss) must surface as an error, and must
	// NOT be mislabeled os.ErrNotExist — that would let the proof builder treat a
	// transient S3 outage as a clean "tile absent" and emit a wrong/short proof.
	backing := errors.New("s3 timeout")
	f := newFakeObjectStore()
	f.getErr = backing
	b := NewObjectTileBackend(f)

	_, err := b.ReadTileByPath(context.Background(), "tile/0/x000/000")
	if err == nil {
		t.Fatal("ReadTileByPath on a backing fault = nil err, want error")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backing fault %v mislabeled as os.ErrNotExist", err)
	}
	if !errors.Is(err, backing) {
		t.Fatalf("err = %v, want it to wrap the backing error", err)
	}
}
