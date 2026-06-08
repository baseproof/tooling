package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// Builds a real SMT in the SDK's in-memory stores, emits its tiles, and proves
// a membership proof RESOLVES against only the emitted tiles — the core
// integrity guarantee (published ⇒ tiles present ⇒ proof resolves). Then checks
// idempotent re-emit (Exists prunes) and the empty-root no-op.
func TestBuildTilesEmitter_EmitsResolvableTilesThenPrunes(t *testing.T) {
	ctx := context.Background()
	nodes := smt.NewInMemoryNodeStore()
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), nodes)

	for i := byte(1); i <= 8; i++ {
		var key [32]byte
		key[0], key[31] = i, i
		leaf := types.SMTLeaf{
			Key:          key,
			OriginTip:    types.LogPosition{LogDID: "did:test", Sequence: uint64(i)},
			AuthorityTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i)},
		}
		if err := tree.SetLeaf(ctx, key, leaf); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, err)
		}
	}
	root, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if root == smt.EmptyHash {
		t.Fatal("root empty after inserts")
	}

	tiles := NewMemSMTTileStore()
	em := NewBuildTilesEmitter(nodes, tiles)

	if _, err := em.EmitDurable(ctx, smt.EmptyHash, root, 8); err != nil {
		t.Fatalf("EmitDurable: %v", err)
	}
	emitted := tiles.Len()
	if emitted == 0 {
		t.Fatal("no tiles emitted for a non-empty root")
	}

	// THE integrity check: a proof at root, served ONLY from the emitted tiles,
	// must resolve — i.e. the emitted set is complete for root.
	ts := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1024))
	var key1 [32]byte
	key1[0], key1[31] = 1, 1
	proof, perr := smt.GenerateProofAt(ts, root, key1)
	if perr != nil {
		t.Fatalf("proof against emitted tiles did not resolve: %v", perr)
	}
	if proof.TerminalKind != types.SMTTerminalLeaf || proof.TerminalLeaf == nil || proof.TerminalLeaf.Key != key1 {
		t.Fatalf("expected a membership proof for key1, got terminal kind %d", proof.TerminalKind)
	}

	// Idempotent re-emit: Exists prunes the whole set, no new tiles.
	if _, err := em.EmitDurable(ctx, smt.EmptyHash, root, 8); err != nil {
		t.Fatalf("second EmitDurable: %v", err)
	}
	if tiles.Len() != emitted {
		t.Fatalf("re-emit changed tile count %d → %d (Exists did not prune)", emitted, tiles.Len())
	}

	// Empty root → no-op.
	empty := NewMemSMTTileStore()
	if _, err := NewBuildTilesEmitter(nodes, empty).EmitDurable(ctx, smt.EmptyHash, smt.EmptyHash, 0); err != nil {
		t.Fatalf("EmitDurable(empty): %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("empty-root emit wrote %d tiles, want 0", empty.Len())
	}
}

// key3band places branch points in tile bands 0, 1 AND 2 (TileHeight=8) — branching
// in the top bits of bytes 0/1/2 — so the tree is ≥3 tile bands deep. That is the
// case where the dirty source is load-bearing: a band-2 tile is reachable ONLY by
// recursing a dirty band-1 tile, so a wrong/empty dirty set strands it.
func key3band(i int) [32]byte {
	var k [32]byte
	k[0] = byte((i & 0x03) << 6)
	k[1] = byte(((i >> 2) & 0x03) << 6)
	k[2] = byte(((i >> 4) & 0x03) << 6)
	return k
}

// TestBuildTilesEmitter_IncrementalEqualsFull is the 2.2 correctness gate: over a
// *TailedNodeStore the emitter takes the INCREMENTAL path (BuildDirtyTiles, walking
// only the un-tiled tail), and the resulting DURABLE tile set serves byte-identical
// proofs to the FULL BuildTiles(newRoot) — the SDK's equivalence contract. The keys
// force a ≥3-band tree (asserted), so the dirty-source + boundary recursion are
// actually exercised: an empty/wrong dirty set strands a band-2 tile and FAILS here.
func TestBuildTilesEmitter_IncrementalEqualsFull(t *testing.T) {
	ctx := context.Background()
	tailed := NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), tailed)

	insert := func(from, to int) [32]byte {
		for i := from; i < to; i++ {
			k := key3band(i)
			if err := tree.SetLeaf(ctx, k, types.SMTLeaf{
				Key:       k,
				OriginTip: types.LogPosition{LogDID: "did:test", Sequence: uint64(i + 1)},
			}); err != nil {
				t.Fatalf("SetLeaf %d: %v", i, err)
			}
		}
		root, err := tree.Root(ctx)
		if err != nil {
			t.Fatalf("Root: %v", err)
		}
		return root
	}

	tiles := NewMemSMTTileStore()
	em := NewBuildTilesEmitter(tailed, tiles) // *TailedNodeStore → incremental path

	// Batch 1 → emit (the band structure for the first half).
	root1 := insert(0, 32)
	if _, err := em.EmitDurable(ctx, smt.EmptyHash, root1, 32); err != nil {
		t.Fatalf("emit root1: %v", err)
	}
	afterFirst := tiles.Len()

	// Batch 2 → emit. Adds band-2 branches UNDER existing band-1 tiles (those tiles go
	// dirty; their new band-2 children emit only via the dirty recursion).
	root2 := insert(32, 64)
	if _, err := em.EmitDurable(ctx, root1, root2, 64); err != nil {
		t.Fatalf("emit root2: %v", err)
	}
	if tiles.Len() <= afterFirst {
		t.Fatalf("incremental emit added no tiles (len %d→%d)", afterFirst, tiles.Len())
	}

	// EQUIVALENCE + DEPTH: the FULL build of root2 is ≥3 tiles, and every one is
	// durably present byte-identical after the two incremental emits.
	oracle, err := smt.BuildTiles(tailed, root2, smt.TileHeight)
	if err != nil {
		t.Fatalf("oracle BuildTiles(root2): %v", err)
	}
	if len(oracle) < 3 {
		t.Fatalf("tree only %d tiles — not exercising 3-band dirty recursion (afterFirst=%d)", len(oracle), afterFirst)
	}
	for id, tile := range oracle {
		got, ferr := tiles.Fetch(ctx, id)
		if ferr != nil {
			t.Fatalf("oracle tile %x stranded (not durable after incremental emit): %v", id[:6], ferr)
		}
		want, encErr := smt.EncodeTile(tile)
		if encErr != nil {
			t.Fatalf("encode oracle tile %x: %v", id[:6], encErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("oracle tile %x bytes differ from incrementally-emitted", id[:6])
		}
	}

	// Proofs across both batches resolve + verify against ONLY the durable tiles.
	ts := smt.NewTiledNodeStore(ctx, tiles, smt.NewTileCache(1<<16))
	for _, i := range []int{0, 31, 32, 63} {
		k := key3band(i)
		proof, perr := smt.GenerateProofAt(ts, root2, k)
		if perr != nil {
			t.Fatalf("proof key#%d did not resolve from durable tiles: %v", i, perr)
		}
		if vErr := smt.VerifyMembershipProof(proof, root2); vErr != nil {
			t.Fatalf("proof key#%d must verify against root: %v", i, vErr)
		}
	}
}
