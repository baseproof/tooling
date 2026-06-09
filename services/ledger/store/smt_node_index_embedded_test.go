/*
FILE PATH: store/smt_node_index_embedded_test.go

Exceptional, self-contained coverage of the durable SMT node→tile-top index
(PGNodeIndex / migration 0018) against a REAL Postgres — embedded-postgres, no
external DSN, no CI service, no Docker. embeddedpg.Start boots a real engine and
applies the production migrations, so this exercises the actual SQL (the unnest
bulk upsert, the ON CONFLICT semantics, the bytea round-trip) and the END-TO-END
fix: a band-INTERIOR node, unfetchable from the top-keyed tile store, RESOLVES
through the PG index attached to a TiledNodeStore — the leaf-loss fix, proven
against the real backend instead of an in-memory fake.

Skips (never fails) where a real PG cannot be brought up (running as root, or no
network for the one-time binary download), matching the repo's other embedded-PG
tests. package store_test (external) so it can import internal/embeddedpg, which
imports store.
*/
package store_test

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/store"
)

// distinct from dbintegration_test's 54331 so a parallel `go test ./...` run
// never collides on the embedded-PG port.
const nodeIndexPGPort = 54332

func TestPGNodeIndex_Embedded(t *testing.T) {
	pool := embeddedpg.Start(t, nodeIndexPGPort) // t.Skip if no real PG here
	ctx := context.Background()
	truncate := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, "TRUNCATE smt_node_index"); err != nil {
			t.Fatalf("truncate smt_node_index: %v", err)
		}
	}
	// hb builds a [32]byte from a prefix — distinct content per test, no collisions.
	hb := func(b ...byte) [32]byte {
		var x [32]byte
		copy(x[:], b)
		return x
	}

	t.Run("put_lookup_round_trip_and_bytea_fidelity", func(t *testing.T) {
		truncate(t)
		idx := store.NewPGNodeIndex(ctx, pool)
		// High bit (0x80), 0xFF, 0x7F, low bytes, and a trailing marker — a byte
		// pattern that catches any sign/encoding/truncation bug in the bytea path.
		node := hb(0xFF, 0x00, 0x80, 0x7F, 0x01, 0xFE)
		var top [32]byte
		for i := range top {
			top[i] = byte(0xA0 + i%8)
		}
		if err := idx.PutNodes(ctx, []store.NodeIndexEntry{{Node: node, Top: top}}); err != nil {
			t.Fatalf("PutNodes: %v", err)
		}
		got, ok, err := idx.OwningTile(node)
		if err != nil || !ok {
			t.Fatalf("OwningTile: ok=%v err=%v", ok, err)
		}
		if got != top {
			t.Fatalf("top round-trip mismatch:\n got  %x\n want %x", got, top)
		}
	})

	t.Run("unknown_node_is_clean_miss_not_error", func(t *testing.T) {
		truncate(t)
		idx := store.NewPGNodeIndex(ctx, pool)
		got, ok, err := idx.OwningTile(hb(0xDE, 0xAD, 0xBE, 0xEF))
		if err != nil {
			t.Fatalf("miss must be a clean (false,nil), got err=%v", err)
		}
		if ok {
			t.Fatalf("unknown node returned ok=true (top=%x)", got)
		}
	})

	t.Run("idempotent_reput_and_first_writer_wins_on_conflict", func(t *testing.T) {
		truncate(t)
		idx := store.NewPGNodeIndex(ctx, pool)
		node := hb(0x11, 0x22)
		topA, topB := hb(0xA1), hb(0xB2)
		put := func(top [32]byte) {
			if err := idx.PutNodes(ctx, []store.NodeIndexEntry{{Node: node, Top: top}}); err != nil {
				t.Fatalf("put: %v", err)
			}
		}
		put(topA)
		put(topA) // re-assert the same immutable mapping: a no-op, never an error
		put(topB) // conflict: ON CONFLICT DO NOTHING keeps the original mapping
		got, ok, err := idx.OwningTile(node)
		if err != nil || !ok {
			t.Fatalf("lookup: ok=%v err=%v", ok, err)
		}
		if got != topA {
			t.Fatalf("ON CONFLICT DO NOTHING violated: got %x, want first-writer topA %x", got, topA)
		}
	})

	t.Run("bulk_put_exceeds_one_chunk", func(t *testing.T) {
		truncate(t)
		idx := store.NewPGNodeIndex(ctx, pool)
		// > nodeIndexPutChunk (5000): exercises the chunk loop AND a multi-thousand
		// unnest($1::bytea[],$2::bytea[]) array bind in one statement.
		const n = 6001
		entries := make([]store.NodeIndexEntry, n)
		for i := 0; i < n; i++ {
			var node, top [32]byte
			node[0], node[1], node[2], node[31] = byte(i), byte(i>>8), byte(i>>16), 0x01
			top[0], top[1], top[31] = byte(i), byte(i>>8), 0x02
			entries[i] = store.NodeIndexEntry{Node: node, Top: top}
		}
		if err := idx.PutNodes(ctx, entries); err != nil {
			t.Fatalf("bulk PutNodes(%d): %v", n, err)
		}
		// Spot-check the two chunk boundaries + the ends.
		for _, i := range []int{0, 4999, 5000, 5001, n - 1} {
			got, ok, err := idx.OwningTile(entries[i].Node)
			if err != nil || !ok {
				t.Fatalf("entry %d: ok=%v err=%v", i, ok, err)
			}
			if got != entries[i].Top {
				t.Fatalf("entry %d top mismatch", i)
			}
		}
	})

	t.Run("end_to_end_index_resolves_tile_interior", func(t *testing.T) {
		truncate(t)
		_, tiles, interiors := buildTreeTiles(t, 2000)
		if len(interiors) == 0 {
			t.Fatal("harness produced no interior nodes; cannot exercise the fix")
		}
		t.Logf("tiles=%d  interior (top-unfetchable) nodes=%d", len(tiles), len(interiors))

		mem := store.NewMemSMTTileStore()
		for top, tile := range tiles {
			enc, err := smt.EncodeTile(tile)
			if err != nil {
				t.Fatalf("encode tile: %v", err)
			}
			if err := mem.Put(ctx, top, enc); err != nil {
				t.Fatalf("put tile: %v", err)
			}
		}

		// Populate the PG index exactly as BuildTilesEmitter does: every interior
		// (node that is not its tile's top) → that tile's top.
		idx := store.NewPGNodeIndex(ctx, pool)
		var entries []store.NodeIndexEntry
		for top, tile := range tiles {
			for i := range tile.Nodes {
				if nh := smt.HashNode(tile.Nodes[i]); nh != top {
					entries = append(entries, store.NodeIndexEntry{Node: nh, Top: top})
				}
			}
		}
		if err := idx.PutNodes(ctx, entries); err != nil {
			t.Fatalf("PutNodes(%d): %v", len(entries), err)
		}

		withIdx := smt.NewTiledNodeStore(ctx, mem, nil)
		withIdx.SetNodeIndex(idx)
		for _, x := range sampleHashes(interiors, 256) {
			// CONTROL: a fresh top-keyed store cannot address an interior by hash.
			bare := smt.NewTiledNodeStore(ctx, mem, nil)
			if n, _ := bare.Get(x); n != nil {
				t.Fatalf("control: interior %x resolved WITHOUT the index", x[:6])
			}
			// WITH the PG index: Get fetches the interior's owning tile and resolves it.
			n, err := withIdx.Get(x)
			if err != nil {
				t.Fatalf("withIdx.Get(%x): %v", x[:6], err)
			}
			if n == nil {
				t.Fatalf("interior %x STILL unresolvable with the PG index", x[:6])
			}
			if smt.HashNode(n) != x {
				t.Fatalf("PG index served a node hashing to a DIFFERENT key for %x", x[:6])
			}
		}
	})

	t.Run("backfill_rebuilds_index_from_tiles_alone", func(t *testing.T) {
		truncate(t)
		_, tiles, interiors := buildTreeTiles(t, 1500)
		if len(interiors) == 0 {
			t.Fatal("no interiors produced")
		}
		mem := store.NewMemSMTTileStore()
		for top, tile := range tiles {
			enc, err := smt.EncodeTile(tile)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if err := mem.Put(ctx, top, enc); err != nil {
				t.Fatalf("put: %v", err)
			}
		}

		// Index starts EMPTY (truncated) — the DB-loss recovery scenario. Backfill
		// rebuilds it from the durable tile set alone, no entry replay.
		idx := store.NewPGNodeIndex(ctx, pool)
		nTiles, nNodes, err := store.BackfillNodeIndex(ctx, mem, idx, 0)
		if err != nil {
			t.Fatalf("BackfillNodeIndex: %v", err)
		}
		if nTiles == 0 || nNodes == 0 {
			t.Fatalf("backfill scanned nothing: tiles=%d nodes=%d", nTiles, nNodes)
		}
		t.Logf("backfill: tiles=%d interiors_indexed=%d", nTiles, nNodes)

		tns := smt.NewTiledNodeStore(ctx, mem, nil)
		tns.SetNodeIndex(idx)
		for _, x := range sampleHashes(interiors, 256) {
			n, err := tns.Get(x)
			if err != nil || n == nil {
				t.Fatalf("post-backfill interior %x unresolved (resolved=%v err=%v)", x[:6], n != nil, err)
			}
		}

		// Idempotent: re-running the backfill is safe (ON CONFLICT DO NOTHING).
		if _, _, err := store.BackfillNodeIndex(ctx, mem, idx, 0); err != nil {
			t.Fatalf("backfill re-run: %v", err)
		}
	})
}

// buildTreeTiles builds an in-memory SMT over n distinct leaves, tiles it via the
// SDK, and returns the root, the tile set, and the INTERIOR node hashes — nodes
// that live inside a tile but are never themselves a tile top, so the top-keyed
// tile store cannot address them (exactly the band-interiors a compressed pointer
// strands).
func buildTreeTiles(t *testing.T, n int) ([32]byte, map[[32]byte]smt.SMTTile, [][32]byte) {
	t.Helper()
	ctx := context.Background()
	// One node store backs the tree AND feeds BuildTiles, so the tile set is
	// exactly the committed tree's nodes.
	nodes := smt.NewInMemoryNodeStore()
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), nodes)

	batch := make([]types.SMTLeaf, n)
	for i := 0; i < n; i++ {
		pos := types.LogPosition{LogDID: "did:baseproof:nodeindextest", Sequence: uint64(i + 1)}
		key := smt.DeriveKey(pos)
		batch[i] = types.SMTLeaf{Key: key, OriginTip: pos, AuthorityTip: pos}
	}
	if err := tree.SetLeaves(ctx, batch); err != nil {
		t.Fatalf("SetLeaves: %v", err)
	}
	root, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	tiles, err := smt.BuildTiles(nodes, root, smt.TileHeight)
	if err != nil {
		t.Fatalf("BuildTiles: %v", err)
	}

	isTop := make(map[[32]byte]bool, len(tiles))
	for top := range tiles {
		isTop[top] = true
	}
	seen := make(map[[32]byte]bool)
	var interiors [][32]byte
	for top, tile := range tiles {
		for i := range tile.Nodes {
			nh := smt.HashNode(tile.Nodes[i])
			if nh == top || isTop[nh] || seen[nh] {
				continue
			}
			seen[nh] = true
			interiors = append(interiors, nh)
		}
	}
	return root, tiles, interiors
}

// sampleHashes returns up to max entries — bounds the per-node PG round-trips so
// the integration test stays fast while still covering a broad interior sample.
func sampleHashes(in [][32]byte, max int) [][32]byte {
	if len(in) <= max {
		return in
	}
	step := len(in) / max
	out := make([][32]byte, 0, max)
	for i := 0; i < len(in) && len(out) < max; i += step {
		out = append(out, in[i])
	}
	return out
}
