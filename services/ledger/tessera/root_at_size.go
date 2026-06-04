/*
FILE PATH:

	tessera/root_at_size.go

DESCRIPTION:

	TesseraAdapter.RootAtSize — the CT-aligned size-bound Merkle-root
	primitive. Derives the RFC 6962 root at an arbitrary historical
	treeSize from immutable tiles, via the c2sp.org/tlog-tiles
	compact-range recipe.

	Why this exists: the builder's cosign payload binds
	(tree_size, root_hash, smt_root, receipt_root) into a single
	witness-signed object. Under sequencer pressure, the builder's
	prior approach (sample Tessera's latest published Head, blindly
	overwrite SMTRoot with this batch's local root) signed
	inconsistent tuples — the Merkle half described the full
	submitted log while the SMT half described only this batch's
	slice. The CT discipline (RFC 6962) keeps every field in the
	signed checkpoint a deterministic function of one size; this
	primitive is what makes that achievable for the builder.

	Mechanics (the standard tlog-tiles recipe):
	  1. Durability gate: treeSize must be <= the integrated tile
	     range. If not, return ErrTilesNotDurable so callers can
	     skip the cosign cycle cleanly.
	  2. client.FetchRangeNodes(ctx, treeSize, tileFetch) returns
	     the O(log treeSize) nodes covering the compact range
	     [0, treeSize), read from tiles with the required
	     partial-tile fallback semantics (handled by TileReader.Fetch).
	  3. compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	     reconstructs the canonical Merkle shape over those nodes.
	  4. Range.GetRootHash(nil) yields the root — a pure function
	     of tile bytes a light client can independently verify.

	treeSize == 0 returns the RFC 6962 empty-tree root
	(SHA-256 of the empty string), matching the upstream convention.

	This method is additive in PR-1: it ships the surface and tests
	but is not yet called by builder/loop.go Step 6. PR-2 wires the
	call into Step 6 behind a tile_frontier durability gate and a
	feature flag.
*/
package tessera

import (
	"context"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
)

// ErrTilesNotDurable signals that RootAtSize was asked for a treeSize
// that the integrated tile substrate does not yet cover — i.e., leaves
// at that size exist in WAL or in-flight but not as tile bytes the
// recipe below can read deterministically. Callers MUST treat this as
// a transient skip signal, never a fatal error: by the next cycle the
// tile reconciler typically catches up, and a retry resolves cleanly.
var ErrTilesNotDurable = errors.New("tessera: tiles do not cover requested tree size")

// IntegratedSize is the inclusive upper bound on tree sizes whose RFC 6962 root
// is derivable from durable tiles right now. It delegates to the backend's
// integrated size (the durable Merkle leaf count, advanced by the sequencer as it
// integrates appended leaves — every entry, including commentary). The checkpoint
// loop reads it both as the Merkle-durability gate for RootAtSize and as the
// genesis disambiguator (0 = empty log vs 1 = a single committed entry, which
// smt_root_state alone cannot distinguish). Safe for log-internal processes only
// — per the AppenderBackend contract, external consumers must anchor on Head().
func (a *TesseraAdapter) IntegratedSize(ctx context.Context) (uint64, error) {
	return a.backend.IntegratedSize(ctx)
}

// RootAtSize returns the RFC 6962 Merkle root at exactly treeSize,
// recomputed from tiles. See the file header for the full rationale.
func (a *TesseraAdapter) RootAtSize(ctx context.Context, treeSize uint64) ([32]byte, error) {
	if treeSize == 0 {
		// RFC 6962 §2.1: the empty tree root is the hash of the
		// empty string. The compact-range library returns nil for
		// an empty range; we surface the canonical value instead so
		// callers (and tests) don't need to special-case this.
		var out [32]byte
		copy(out[:], rfc6962.DefaultHasher.EmptyRoot())
		return out, nil
	}

	// Durability gate. IntegratedSize is the inclusive upper bound
	// on tree sizes whose tiles are present. Past that, FetchRangeNodes
	// would fail with os.ErrNotExist at the first missing tile — we
	// surface the typed sentinel up front so callers don't have to
	// match a wrapped storage error.
	integrated, err := a.backend.IntegratedSize(ctx)
	if err != nil {
		return [32]byte{}, fmt.Errorf("tessera/RootAtSize: IntegratedSize: %w", err)
	}
	if treeSize > integrated {
		return [32]byte{}, fmt.Errorf("%w: requested=%d, integrated=%d",
			ErrTilesNotDurable, treeSize, integrated)
	}

	// tlog-tiles compact-range recipe — pure function of tile bytes.
	// TileReader.Fetch implements the required partial-tile fallback
	// (tessera/tile_reader.go:126); passing it directly satisfies
	// client.TileFetcherFunc's documented contract.
	nodes, err := client.FetchRangeNodes(ctx, treeSize, a.tileReader.Fetch)
	if err != nil {
		return [32]byte{}, fmt.Errorf("tessera/RootAtSize: FetchRangeNodes(%d): %w", treeSize, err)
	}
	rf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	r, err := rf.NewRange(0, treeSize, nodes)
	if err != nil {
		return [32]byte{}, fmt.Errorf("tessera/RootAtSize: NewRange(0,%d): %w", treeSize, err)
	}
	rootBytes, err := r.GetRootHash(nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("tessera/RootAtSize: GetRootHash: %w", err)
	}
	var out [32]byte
	copy(out[:], rootBytes)
	return out, nil
}
