/*
FILE PATH: store/tile_emitter.go

BuildTilesEmitter — makes every SMT tile reachable from a committed root durable in
an SMTTileStore. Satisfies the reconciler's TileEmitter.

Two paths behind one interface, selected by the node substrate:

  - Incremental (production): when the substrate exposes its un-tiled tail
    (*TailedNodeStore via Tail()), smt.BuildDirtyTiles walks ONLY the tiles the
    checkpoint changed — work ∝ the delta, not the whole tree. The tail is the dirty
    set (committed-but-not-tiled); the tile store's Exists is the EXACT `known` oracle
    (an Exists error → not-known → re-emit, NEVER skip — a false positive would strand
    a needed tile). This is the 10B-regime path: a full walk per checkpoint, on the
    EmitDurable→cosign horizon-critical path, is catastrophic.

  - Full (fallback / oracle): a plain NodeStore (first-tiling of a backfilled tree,
    tests) falls back to smt.BuildTiles — the full-subtree walk BuildDirtyTiles is
    validated against; their durable union serves byte-identical proofs.

Both paths Put only tiles the store does not already hold (Exists prunes), so
EmitDurable returning nil means the committed root's tiles are durable — the gate the
reconciler requires before advancing the frontier.
*/
package store

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/core/smt"
)

// BuildTilesEmitter emits tiles from a NodeStore into an SMTTileStore.
type BuildTilesEmitter struct {
	nodes smt.NodeStore
	tiles SMTTileStore
}

// tailSnapshotter is the optional capability a NodeStore exposes to drive incremental
// tiling: its un-tiled tail is the dirty set BuildDirtyTiles recurses over. The
// production substrate (*TailedNodeStore) implements it; a plain NodeStore does not.
type tailSnapshotter interface {
	Tail() map[[32]byte]smt.Node
}

// NewBuildTilesEmitter wires the emitter. nodes is the substrate the committed root's
// nodes are read from (the *TailedNodeStore in-memory tail + tile read-through in
// production; the Jellyfish node DAG no longer lives in PG); tiles is the durable
// object-store tile sink the reconciler folds that tail into.
func NewBuildTilesEmitter(nodes smt.NodeStore, tiles SMTTileStore) *BuildTilesEmitter {
	return &BuildTilesEmitter{nodes: nodes, tiles: tiles}
}

// EmitDurable ensures every tile reachable from committedRoot is durably present,
// and returns the content hashes of every node now durable in those tiles. The
// reconciler evicts exactly that set from the in-memory tail (PruneTiled), bounding
// the tail to the un-tiled gap — WITHOUT this signal the tail accumulates every
// committed node (O(history)) and the writer OOMs. A nil/empty return (EmptyHash, or
// an error) prunes nothing. Returning a non-nil error means NO tiles became durable
// this call; the set is then nil so the caller evicts nothing (fail-closed).
//
// fromRoot is the prior durably-tiled root (the frontier root; EmptyHash at genesis).
// The incremental emitter warms the same-position prior tile from it so a re-emitted
// tile's unchanged interiors resolve AFTER the tail is pruned — without it the emit
// faults "interior node missing from node store" (the pruned-tail tiling stall). It
// is only a warm anchor: the durable tile SET produced is identical regardless.
func (e *BuildTilesEmitter) EmitDurable(ctx context.Context, fromRoot [32]byte, committedRoot [32]byte, _ uint64) (map[[32]byte]struct{}, error) {
	if committedRoot == smt.EmptyHash {
		return nil, nil // empty tree → no tiles, nothing durable
	}
	tileSet, err := e.buildTiles(ctx, fromRoot, committedRoot)
	if err != nil {
		return nil, err
	}
	for id, tile := range tileSet {
		// Content-addressed: an already-present tile carries identical bytes, so skip
		// it (bounds PUTs to the missing set). The incremental path already excluded
		// known tiles; this also guards the full-build path + a concurrent re-emit.
		if ok, eerr := e.tiles.Exists(ctx, id); eerr == nil && ok {
			continue
		}
		enc, encErr := smt.EncodeTile(tile)
		if encErr != nil {
			return nil, fmt.Errorf("store/tile-emitter: encode tile %x: %w", id[:6], encErr)
		}
		if perr := e.tiles.Put(ctx, id, enc); perr != nil {
			return nil, fmt.Errorf("store/tile-emitter: put tile %x: %w", id[:6], perr)
		}
	}
	// Every node in every tile of tileSet is now durable (just-PUT, or already
	// present and skipped above). Hash them so the reconciler can evict exactly these
	// from the tail — a strictly fail-closed prune signal (evict iff durable). Empty
	// for a no-tile committedRoot.
	durable := make(map[[32]byte]struct{})
	for _, tile := range tileSet {
		for i := range tile.Nodes {
			durable[smt.HashNode(tile.Nodes[i])] = struct{}{}
		}
	}
	return durable, nil
}

// buildTiles selects the incremental dirty-set walk when the node substrate exposes
// its un-tiled tail (production: *TailedNodeStore — work ∝ the checkpoint delta), else
// the full-subtree walk (the correctness oracle BuildDirtyTiles is validated against).
// fromRoot anchors the incremental walk's prior-tile warming; the full walk ignores it.
func (e *BuildTilesEmitter) buildTiles(ctx context.Context, fromRoot, committedRoot [32]byte) (map[[32]byte]smt.SMTTile, error) {
	tailed, ok := e.nodes.(tailSnapshotter)
	if !ok {
		tiles, err := smt.BuildTiles(e.nodes, committedRoot, smt.TileHeight)
		if err != nil {
			return nil, fmt.Errorf("store/tile-emitter: build tiles at %x: %w", committedRoot[:8], err)
		}
		return tiles, nil
	}
	// known reports EXACT tile-root durability. The SDK requires exactness: a false
	// negative re-emits harmlessly, a false positive strands a needed tile — so an
	// Exists error maps to NOT-known (re-emit), never to known.
	known := func(top [32]byte) bool {
		present, eerr := e.tiles.Exists(ctx, top)
		return eerr == nil && present
	}
	// Read the dirty walk through a FRESH, UNBOUNDED per-emit read-through — NOT the
	// long-lived proof-serving store. BuildDirtyTiles re-reads a dirty band's CLEAN
	// interiors (warmed from the same-position prior tile) AFTER loading the deeper
	// boundary tiles below them; a BOUNDED read-through (the memory-capped store) can
	// evict such an interior mid-band-walk, faulting "interior node missing from node
	// store" once a pass exceeds the cap (the pruned-tail tiling stall — proven in
	// baseproof tile_pruned_cap_test.go: a smaller cap strands at a smaller tree).
	// This store holds the whole pass working set and is discarded on return, so it
	// holds NO O(history) memory — the cap stays on the long-lived proof path.
	emitNodes := &tailReadThrough{
		tail:  tailed.Tail(),
		tiled: smt.NewTiledNodeStoreCapped(ctx, e.tiles, nil, 0),
	}
	tiles, err := smt.BuildDirtyTiles(emitNodes, emitNodes.tail, committedRoot, fromRoot, smt.TileHeight, known)
	if err != nil {
		return nil, fmt.Errorf("store/tile-emitter: build dirty tiles at %x: %w", committedRoot[:8], err)
	}
	return tiles, nil
}

// tailReadThrough is a per-emit NodeStore view: the committed-but-not-tiled tail
// (a snapshot) first, then an UNBOUNDED durable tile read-through. BuildDirtyTiles
// needs its full pass working set resident — a bounded read-through evicts a
// band's interiors mid-walk and strands them — so this store does not cap; being
// per-emit (discarded after each EmitDurable) it never accumulates O(history).
type tailReadThrough struct {
	tail  map[[32]byte]smt.Node
	tiled smt.NodeStore
}

func (v *tailReadThrough) Get(h [32]byte) (smt.Node, error) {
	if h == smt.EmptyHash {
		return nil, nil
	}
	if n, ok := v.tail[h]; ok {
		return n, nil
	}
	return v.tiled.Get(h)
}

// Put is unused: BuildDirtyTiles only reads. Return the content hash without
// storing (NodeStore requires the method).
func (v *tailReadThrough) Put(n smt.Node) ([32]byte, error) { return smt.HashNode(n), nil }
