/*
FILE PATH: tessera/tile_shipper.go

Tessera tile shipper — the WRITER-side other half of object_tile_store.go.

Our stack runs tessera embedded with the POSIX storage driver (the only driver
that does not bring its own coordination DB — we sequence on Postgres, not
Spanner/MySQL), so log tiles land on the writer's local disk. The horizontally-
scalable read front (cmd/ledger-reader) cannot reach that disk, so the writer
ships every immutable tlog-tiles object — hash tiles (inclusion proofs) and entry
bundles (the /raw seq→hash fallback) — to the shared object store, keyed by the
bare c2sp path. This mirrors how SMT tiles (store.S3SMTTileStore.Put) and the
cosigned horizon (store.S3CheckpointPublisher) already reach S3.

Scale (15y / 10B entries / 500 TPS): shipping is INCREMENTAL via a durable size
cursor. Each cosigned-checkpoint publish ships only the tiles whose content
changed since the last — the frontier tile at each of the ~5 hash-tile levels
plus any newly-completed tiles — a handful of objects, never a tree walk. A
restart resumes from the persisted cursor, so it never re-ships the whole tree.

Correctness invariant (ShippingPublisher): tiles ship BEFORE the cosigned head is
published, so a horizon a reader can fetch from S3 implies every tile backing a
proof at that size is already in S3. The POSIX driver writes the exact partial
width the reader will request at each committed size and never deletes narrower
partials (storage/posix writeTile), so the precise path
TilePath(L, i, PartialTileSize(L, i, N)) is always on disk when we ship size N.
*/
package tessera

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/baseproof/baseproof/types"
	"github.com/transparency-dev/tessera/api/layout"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// tileShipCursorKey is the object key holding the highest tree size fully shipped
// — the resume point a restarted writer reads so it ships only the delta, not the
// whole tree. Namespaced per-log by the *bytestore.S3 adapter, like every other
// logical key. Not a tile path, so a tlog-tiles CDN never serves it.
const tileShipCursorKey = "tessera-tile-ship-cursor"

// tileRef identifies one tlog-tiles object to ship: a hash tile (entry=false) or
// an entry bundle (entry=true), at the given tile level/index and partial width
// (0 = a full, immutable tile).
type tileRef struct {
	entry bool
	level uint64
	index uint64
	width uint8
}

// path renders the c2sp tlog-tiles path for the tile — the exact path the read
// front requests (layout.TilePath / layout.EntriesPath) and the object key.
func (r tileRef) path() string {
	if r.entry {
		return layout.EntriesPath(r.index, r.width)
	}
	return layout.TilePath(r.level, r.index, r.width)
}

// tilesToShip enumerates the tlog-tiles objects whose content depends on a leaf
// in (lastSize, newSize] — the minimal delta to let the object store serve every
// inclusion proof and entry-bundle lookup at tree size newSize, given everything
// through lastSize is already shipped.
//
// Per hash-tile level (and once for the entry-bundle row) it re-ships the
// frontier tile that was still partial at lastSize (it has since grown) plus
// every tile newly touched up to newSize, each at the EXACT width the reader will
// request at newSize (layout.PartialTileSize) — which is the width the POSIX
// driver wrote when it integrated to newSize. Tiles fully populated at lastSize
// are immutable and were shipped once, so they are skipped. A level unchanged
// between the two sizes (and therefore every higher level) is skipped entirely.
func tilesToShip(lastSize, newSize uint64) []tileRef {
	if newSize <= lastSize {
		return nil
	}
	var refs []tileRef

	// Hash tiles: one row per tile level, until a level holds no nodes.
	for level := uint64(0); ; level++ {
		newAtLevel := newSize >> (level * layout.TileHeight)
		if newAtLevel == 0 {
			break // no nodes at this tile level (or any higher) for newSize.
		}
		lastAtLevel := lastSize >> (level * layout.TileHeight)
		if newAtLevel == lastAtLevel {
			break // this level — and every higher one — is unchanged; already shipped.
		}
		// First index not fully shipped at lastSize; last index with content at newSize.
		startIdx := lastAtLevel / layout.TileWidth
		endIdx := (newAtLevel - 1) / layout.TileWidth
		for idx := startIdx; idx <= endIdx; idx++ {
			refs = append(refs, tileRef{
				level: level,
				index: idx,
				width: layout.PartialTileSize(level, idx, newSize),
			})
		}
	}

	// Entry bundles share level-0's index range and width (EntryBundleWidth == 256).
	startIdx := lastSize / layout.TileWidth
	endIdx := (newSize - 1) / layout.TileWidth
	for idx := startIdx; idx <= endIdx; idx++ {
		refs = append(refs, tileRef{
			entry: true,
			index: idx,
			width: layout.PartialTileSize(0, idx, newSize),
		})
	}
	return refs
}

// TileShipper ships tessera tiles from the writer's local tile source (a
// *POSIXTileBackend, satisfying TileBackend) to a shared ObjectStore, tracking a
// durable size cursor so each call ships only the delta.
type TileShipper struct {
	src    TileBackend // read the tiles the writer's embedded tessera wrote
	obj    ObjectStore // write tiles + cursor to the shared object store
	logger *slog.Logger

	mu     sync.Mutex
	cursor uint64 // highest tree size fully shipped (and persisted)
}

// NewTileShipper builds a shipper and resumes from the durable cursor so a
// restart re-ships only the delta, never a whole-tree cold walk.
//
// The cursor read is fail-safe by design, which matters for EVERY new network as
// it grows:
//   - absent (bytestore.ErrNotFound) ⇒ cursor 0. This is the fresh-log case: the
//     tree is also empty here, so shipping is incremental from leaf 1 and the
//     cursor keeps pace with the head forever — a new network can never trigger a
//     bulk ship under normal operation.
//   - present ⇒ resume at the stored size.
//   - a TRANSIENT object-store fault or a CORRUPT cursor ⇒ ERROR (boot fails).
//     Treating either as "no cursor" would silently reset to 0 and bulk re-ship
//     the entire tree on the next publish — a self-inflicted outage if an
//     established writer restarts during an S3 blip. Failing boot lets the
//     supervisor retry against the real cursor instead.
func NewTileShipper(ctx context.Context, src TileBackend, obj ObjectStore, logger *slog.Logger) (*TileShipper, error) {
	s := &TileShipper{src: src, obj: obj, logger: logger}
	raw, err := obj.GetObject(ctx, tileShipCursorKey)
	switch {
	case err == nil:
		v, perr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if perr != nil {
			return nil, fmt.Errorf("tessera/ship: corrupt ship cursor %q: %w", raw, perr)
		}
		s.cursor = v
	case errors.Is(err, bytestore.ErrNotFound):
		s.cursor = 0 // fresh log — incremental from leaf 1.
	default:
		return nil, fmt.Errorf("tessera/ship: read ship cursor (refusing to reset to 0 and bulk re-ship): %w", err)
	}
	return s, nil
}

// ShipUpTo ships every tile the object store needs to serve proofs and entry
// lookups at tree size `size`, then advances and persists the cursor. Monotonic
// and idempotent: a size at or below the cursor is a no-op. Fail-closed — on any
// tile read/put error it returns WITHOUT advancing the cursor, so the caller (the
// publish path) never advances the horizon past tiles that are not yet durable in
// the object store; the CheckpointLoop retries on its next tick.
func (s *TileShipper) ShipUpTo(ctx context.Context, size uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size <= s.cursor {
		return nil
	}
	refs := tilesToShip(s.cursor, size)
	for _, r := range refs {
		path := r.path()
		data, err := s.src.ReadTileByPath(ctx, path)
		if err != nil {
			return fmt.Errorf("tessera/ship: read tile %q for size %d: %w", path, size, err)
		}
		if err := s.obj.PutObject(ctx, tesseraTileKey(path), data); err != nil {
			return fmt.Errorf("tessera/ship: put tile %q: %w", path, err)
		}
	}
	// Persist the cursor only AFTER the tiles are durable. A crash between the tile
	// puts and this put just re-ships the same (idempotent) delta on the next call.
	if err := s.obj.PutObject(ctx, tileShipCursorKey, []byte(strconv.FormatUint(size, 10))); err != nil {
		return fmt.Errorf("tessera/ship: persist cursor %d: %w", size, err)
	}
	s.cursor = size
	if s.logger != nil {
		s.logger.Debug("tessera tiles shipped to object store", "to_size", size, "tiles", len(refs))
	}
	return nil
}

// shipped reports the current cursor (highest size shipped). For tests + metrics.
func (s *TileShipper) shipped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cursor
}

// checkpointPublisher is the builder.CheckpointPublisher surface, named here so
// ShippingPublisher implements + wraps it structurally without importing builder
// (which would invert the dependency: builder already wires this package).
type checkpointPublisher interface {
	PublishCosignedCheckpoint(ctx context.Context, head types.CosignedTreeHead) error
}

// ShippingPublisher ships tessera tiles up to head.TreeSize to the object store
// BEFORE delegating the cosigned-checkpoint publish. The ordering is the read
// front's correctness invariant: a horizon a reader can fetch from S3 implies the
// tiles backing every proof at that size are already in S3. Fail-closed — a ship
// error blocks the publish, so the horizon never advances past non-durable tiles.
type ShippingPublisher struct {
	inner   checkpointPublisher
	shipper *TileShipper
}

var _ checkpointPublisher = (*ShippingPublisher)(nil)

// NewShippingPublisher wraps inner (the real cosigned-checkpoint publisher) so
// every publish first ships the tiles backing proofs at the published size.
func NewShippingPublisher(inner checkpointPublisher, shipper *TileShipper) *ShippingPublisher {
	return &ShippingPublisher{inner: inner, shipper: shipper}
}

// PublishCosignedCheckpoint ships tiles up to head.TreeSize, then publishes.
func (p *ShippingPublisher) PublishCosignedCheckpoint(ctx context.Context, head types.CosignedTreeHead) error {
	if err := p.shipper.ShipUpTo(ctx, head.TreeSize); err != nil {
		return fmt.Errorf("tessera/ship: tiles for size %d not shipped, withholding horizon: %w", head.TreeSize, err)
	}
	return p.inner.PublishCosignedCheckpoint(ctx, head)
}
