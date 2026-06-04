/*
FILE PATH: store/tile_emitter.go

BuildTilesEmitter — makes every SMT tile reachable from a committed root durable
in an SMTTileStore. Satisfies the reconciler's TileEmitter.

First cut: smt.BuildTiles(committedRoot) — the full-subtree, idempotent,
content-addressed regeneration path the SDK blesses for "initial backfill /
periodic regeneration" — Put-ing only tiles the store does not already hold
(Exists prunes, bounding PUTs to the missing set). A Put returns only on a
backend ack, so EmitDurable returning nil means the committed root's tiles are
durable — the gate the reconciler requires before advancing the frontier.

The incremental successor (BuildDirtyTiles over the fromRoot→committedRoot delta,
work ∝ the gap, not the whole tree) drops in behind the same interface for the
10B regime; fromRoot is carried for it and ignored here.
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

// NewBuildTilesEmitter wires the emitter. nodes is the substrate the committed
// root's nodes are read from (the TailedNodeStore in-memory tail today; the
// Jellyfish node DAG no longer lives in PG); tiles is the durable object-store
// tile sink the reconciler folds that tail into.
func NewBuildTilesEmitter(nodes smt.NodeStore, tiles SMTTileStore) *BuildTilesEmitter {
	return &BuildTilesEmitter{nodes: nodes, tiles: tiles}
}

// EmitDurable ensures every tile reachable from committedRoot is durably present.
func (e *BuildTilesEmitter) EmitDurable(ctx context.Context, _ [32]byte, committedRoot [32]byte, _ uint64) error {
	if committedRoot == smt.EmptyHash {
		return nil // empty tree → no tiles
	}
	tileSet, err := smt.BuildTiles(e.nodes, committedRoot, smt.TileHeight)
	if err != nil {
		return fmt.Errorf("store/tile-emitter: build tiles at %x: %w", committedRoot[:8], err)
	}
	for id, tile := range tileSet {
		// Content-addressed: an already-present tile carries identical bytes, so
		// skip it (bounds PUTs to the missing set — the incremental property even
		// the full-build path keeps).
		if ok, eerr := e.tiles.Exists(ctx, id); eerr == nil && ok {
			continue
		}
		enc, encErr := smt.EncodeTile(tile)
		if encErr != nil {
			return fmt.Errorf("store/tile-emitter: encode tile %x: %w", id[:6], encErr)
		}
		if perr := e.tiles.Put(ctx, id, enc); perr != nil {
			return fmt.Errorf("store/tile-emitter: put tile %x: %w", id[:6], perr)
		}
	}
	return nil
}
