package store

import "context"

// TileMissVerdict classifies WHY a node X resolved from neither the in-memory
// tail nor a fetchable tile — the exact point the SDK insert faults
// "missing node X (referenced by ancestor)" → PathD → leaf loss.
//
// It is the tooling-layer half of the leaf-loss instrumentation, paired with the
// SDK trace: the SDK gives the fault LOCATION (smt.TiledNodeStore.Get MISS →
// jellyfishInsert.missingNode) and the node IDENTITY (the typed
// smt.MissingNodeError carrying X and its ancestor Z); this gives the live
// object-store HEAD/GET VERDICT for X. First-class and reusable — the builder
// read-through, the emitter, and recovery all classify a miss the same way,
// rather than each carrying a bespoke probe.
type TileMissVerdict struct {
	Kind          string // one of the Miss* constants
	IsTileTopHEAD bool   // Exists(X): X is addressable as a durable tile TOP
	GetBytes      int    // Fetch(X) byte count (0 on miss)
	GetErr        string // Fetch(X) error rendered, "" on success
}

const (
	// MissStrandedTop — HEAD says X IS a durable tile top, but GET could not read
	// it. An object-store HEAD-vs-GET inconsistency: BuildDirtyTiles' `known`
	// (Exists) oracle trusted a top that is not actually fetchable, stranding it.
	// A write/serve-path gap, NOT the compression top-skip.
	MissStrandedTop = "STRANDED_TOP_HEAD_GET"

	// MissInteriorTopSkip — HEAD says X is NOT a tile top, so X is a band INTERIOR
	// a compressed pointer reached without ever requesting its band top; the
	// top-keyed store cannot address it. This is the compression top-skip. The SDK
	// NodeIndex (OwningTile) resolves it by mapping X to its owning tile; absent
	// that index, this is the leaf-loss source.
	MissInteriorTopSkip = "INTERIOR_TOP_SKIP"

	// MissResolvesNow — HEAD true AND GET ok on the probe: X is present now and the
	// miss was transient (timing / eventual consistency between commit and serve),
	// not a durable gap.
	MissResolvesNow = "RESOLVES_NOW"
)

// ClassifyTileMiss interrogates the live tile store for X with one HEAD (Exists)
// and one GET (Fetch) and returns the verdict. It never returns an error: a
// HEAD/GET failure is itself the signal. Callers should cap how often they invoke
// it (a soak can miss thousands of times) — the verdict from the first samples is
// sufficient to classify the fault.
func ClassifyTileMiss(ctx context.Context, tiles SMTTileStore, hash [32]byte) TileMissVerdict {
	isTop, _ := tiles.Exists(ctx, hash) // HEAD
	gb, gerr := tiles.Fetch(ctx, hash)  // GET
	v := TileMissVerdict{IsTileTopHEAD: isTop, GetBytes: len(gb)}
	if gerr != nil {
		v.GetErr = gerr.Error()
	}
	switch {
	case isTop && gerr == nil:
		v.Kind = MissResolvesNow
	case isTop && gerr != nil:
		v.Kind = MissStrandedTop
	default: // !isTop → not addressable as a tile top
		v.Kind = MissInteriorTopSkip
	}
	return v
}
