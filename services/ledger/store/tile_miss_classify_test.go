package store

import (
	"context"
	"os"
	"testing"
)

// fakeTileStore is a controllable SMTTileStore for pinning each ClassifyTileMiss
// verdict deterministically (no real object store needed).
type fakeTileStore struct {
	exists     bool
	fetchBytes []byte
	fetchErr   error
}

func (f fakeTileStore) Put(_ context.Context, _ [32]byte, _ []byte) error { return nil }
func (f fakeTileStore) Fetch(_ context.Context, _ [32]byte) ([]byte, error) {
	return f.fetchBytes, f.fetchErr
}
func (f fakeTileStore) Exists(_ context.Context, _ [32]byte) (bool, error) { return f.exists, nil }

var _ SMTTileStore = fakeTileStore{}

func TestClassifyTileMiss(t *testing.T) {
	var h [32]byte
	cases := []struct {
		name string
		ts   fakeTileStore
		want string
	}{
		{
			// HEAD false → X is not a tile top → band interior reached by a
			// compressed pointer (the leaf-loss top-skip).
			name: "interior top-skip (HEAD false, GET miss)",
			ts:   fakeTileStore{exists: false, fetchErr: os.ErrNotExist},
			want: MissInteriorTopSkip,
		},
		{
			// HEAD true but GET fails → durable top per HEAD, unreadable by GET:
			// object-store HEAD-vs-GET inconsistency.
			name: "stranded top (HEAD true, GET fail)",
			ts:   fakeTileStore{exists: true, fetchErr: os.ErrNotExist},
			want: MissStrandedTop,
		},
		{
			// HEAD true and GET ok → present now; the miss was transient.
			name: "resolves now (HEAD true, GET ok)",
			ts:   fakeTileStore{exists: true, fetchBytes: []byte("tile-bytes")},
			want: MissResolvesNow,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := ClassifyTileMiss(context.Background(), c.ts, h)
			if v.Kind != c.want {
				t.Fatalf("Kind = %q, want %q (verdict=%+v)", v.Kind, c.want, v)
			}
			if v.IsTileTopHEAD != c.ts.exists {
				t.Errorf("IsTileTopHEAD = %v, want %v", v.IsTileTopHEAD, c.ts.exists)
			}
			// A GET failure must be reported as the signal, not swallowed.
			if c.ts.fetchErr != nil && v.GetErr == "" {
				t.Error("GetErr empty despite a fetch error")
			}
			if c.ts.fetchErr == nil && v.GetBytes != len(c.ts.fetchBytes) {
				t.Errorf("GetBytes = %d, want %d", v.GetBytes, len(c.ts.fetchBytes))
			}
		})
	}
}
