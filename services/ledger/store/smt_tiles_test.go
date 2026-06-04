package store

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// buildTileTree builds an in-memory SMT with n leaves and returns it + its root
// + the keys, mirroring the SDK's own tile tests.
func buildTileTree(t *testing.T, n int) (*smt.Tree, [32]byte, [][32]byte) {
	t.Helper()
	ctx := context.Background()
	tr := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	keys := make([][32]byte, n)
	for i := 0; i < n; i++ {
		k := smt.DeriveKey(types.LogPosition{LogDID: "did:web:court.example", Sequence: uint64(i + 1)})
		keys[i] = k
		if err := tr.SetLeaf(ctx, k, types.SMTLeaf{Key: k, OriginTip: types.LogPosition{LogDID: "did:web:court.example", Sequence: uint64(i + 1)}}); err != nil {
			t.Fatal(err)
		}
	}
	root, _ := tr.Root(ctx)
	return tr, root, keys
}

// servesByteIdenticalProofs is the cutover-correctness assertion: proofs served
// from the tile store are byte-identical to proofs served directly from the SMT
// node store, and verify against the root.
func servesByteIdenticalProofs(t *testing.T, ts SMTTileStore) {
	t.Helper()
	ctx := context.Background()
	tr, root, keys := buildTileTree(t, 200)

	tiles, err := smt.BuildTiles(tr.Nodes(), root, smt.TileHeight)
	if err != nil {
		t.Fatalf("BuildTiles: %v", err)
	}
	if err := EmitTiles(ctx, ts, tiles); err != nil {
		t.Fatalf("EmitTiles: %v", err)
	}

	tiled := smt.NewTiledNodeStore(ctx, ts, smt.NewTileCache(1<<16))
	for _, k := range keys {
		want, err := smt.GenerateProofAt(tr.Nodes(), root, k)
		if err != nil {
			t.Fatalf("direct proof %x: %v", k[:6], err)
		}
		got, err := smt.GenerateProofAt(tiled, root, k)
		if err != nil {
			t.Fatalf("tile proof %x: %v", k[:6], err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("tile proof != direct proof for key %x", k[:6])
		}
		if err := smt.VerifyMembershipProof(got, root); err != nil {
			t.Fatalf("tile proof must verify: %v", err)
		}
	}
}

func TestMemSMTTileStore_ServesByteIdenticalProofs(t *testing.T) {
	servesByteIdenticalProofs(t, NewMemSMTTileStore())
}

func TestPosixSMTTileStore_ServesByteIdenticalProofs(t *testing.T) {
	servesByteIdenticalProofs(t, NewPosixSMTTileStore(t.TempDir()))
}

func TestSMTTileStore_FetchMiss(t *testing.T) {
	ctx := context.Background()
	var id [32]byte
	id[0] = 0xaa
	for _, ts := range []SMTTileStore{NewMemSMTTileStore(), NewPosixSMTTileStore(t.TempDir())} {
		if _, err := ts.Fetch(ctx, id); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%T: miss = %v, want os.ErrNotExist", ts, err)
		}
	}
}

func TestMemSMTTileStore_Len(t *testing.T) {
	ctx := context.Background()
	ts := NewMemSMTTileStore()
	if ts.Len() != 0 {
		t.Fatal("empty store len != 0")
	}
	_ = ts.Put(ctx, [32]byte{1}, []byte("a"))
	_ = ts.Put(ctx, [32]byte{2}, []byte("b"))
	_ = ts.Put(ctx, [32]byte{1}, []byte("a")) // re-put same id
	if ts.Len() != 2 {
		t.Errorf("len = %d, want 2", ts.Len())
	}
}

func TestGenerateSMTProof_SourceModes(t *testing.T) {
	ctx := context.Background()
	tr, root, keys := buildTileTree(t, 64)
	k := keys[0]

	// Populate a tile store from the tree.
	tiles, err := smt.BuildTiles(tr.Nodes(), root, smt.TileHeight)
	if err != nil {
		t.Fatal(err)
	}
	ts := NewMemSMTTileStore()
	if err := EmitTiles(ctx, ts, tiles); err != nil {
		t.Fatal(err)
	}
	cache := smt.NewTileCache(1 << 12)

	want, _ := smt.GenerateProofAt(tr.Nodes(), root, k)

	// pg
	p, mm, err := GenerateSMTProof(ctx, SMTProofSourcePG, tr.Nodes(), nil, nil, root, k)
	if err != nil || mm || !reflect.DeepEqual(p, want) {
		t.Errorf("pg: mm=%v err=%v eq=%v", mm, err, reflect.DeepEqual(p, want))
	}
	// tiles
	p, mm, err = GenerateSMTProof(ctx, SMTProofSourceTiles, nil, ts, cache, root, k)
	if err != nil || mm || !reflect.DeepEqual(p, want) {
		t.Errorf("tiles: mm=%v err=%v eq=%v", mm, err, reflect.DeepEqual(p, want))
	}
	// shadow (consistent) → no mismatch, serves pg
	p, mm, err = GenerateSMTProof(ctx, SMTProofSourceShadow, tr.Nodes(), ts, cache, root, k)
	if err != nil || mm || !reflect.DeepEqual(p, want) {
		t.Errorf("shadow ok: mm=%v err=%v", mm, err)
	}
	// shadow with an EMPTY tile store → mismatch (tile path fails), still serves pg
	p, mm, err = GenerateSMTProof(ctx, SMTProofSourceShadow, tr.Nodes(), NewMemSMTTileStore(), smt.NewTileCache(16), root, k)
	if err != nil || !mm || !reflect.DeepEqual(p, want) {
		t.Errorf("shadow mismatch: mm=%v err=%v (want mm=true, pg served)", mm, err)
	}
}

func TestParseSMTProofSource(t *testing.T) {
	for in, want := range map[string]SMTProofSource{
		"pg": SMTProofSourcePG, "tiles": SMTProofSourceTiles, "shadow": SMTProofSourceShadow,
		"": SMTProofSourcePG, "garbage": SMTProofSourcePG, " TILES ": SMTProofSourceTiles,
	} {
		if got := ParseSMTProofSource(in); got != want {
			t.Errorf("ParseSMTProofSource(%q) = %q, want %q", in, got, want)
		}
	}
}
