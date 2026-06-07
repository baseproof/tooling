/*
FILE PATH: tessera/object_tile_store.go

Object-store (S3 / GCS) tlog-tiles backend — the PG-free, horizontally-scalable
read path for tessera log tiles.

A read-front pod (cmd/ledger-reader) reconstructs RFC 6962 inclusion proofs and
entry-bundle seq→hash lookups from the SAME shared object store the writer ships
tiles to (tile_shipper.go), with NO shared filesystem and NO writer affinity.
This is the tessera analogue of store.S3SMTTileStore / store.NewS3HorizonReader:
log tiles, SMT nodes, and the cosigned horizon all served from one object store,
so a reader pod needs only the bucket (and Postgres only for value lookups).

The object key is the bare c2sp tlog-tiles path ("tile/0/x001/067",
"tile/entries/067"); the *bytestore.S3 adapter prepends the per-log namespace, so
logs sharing a bucket never collide and a standard tlog-tiles CDN can front the
objects unchanged. (SMT tiles live under "smt/tile/...", entry bytes under
"entries/...", the horizon under "cosigned-checkpoint"/"checkpoints/..." — no
overlap with the "tile/..." namespace.)
*/
package tessera

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// ObjectStore is the minimal key→bytes surface the object tile backend (read)
// and the tile shipper (write) need. *bytestore.S3 satisfies it; tests inject an
// in-memory fake. Depending on the interface — not *bytestore.S3 — keeps the tile
// substrate swappable (S3, GCS, a CDN-backed store) with no code change here.
type ObjectStore interface {
	// PutObject writes data at key. Idempotent for the immutable tiles shipped
	// here (identical bytes per key; last-writer-wins on a re-ship).
	PutObject(ctx context.Context, key string, data []byte) error
	// GetObject reads the bytes at key, returning bytestore.ErrNotFound on a miss.
	GetObject(ctx context.Context, key string) ([]byte, error)
}

// tesseraTileKey maps a c2sp tlog-tiles path to its object-store key. Identity:
// the bare path IS the canonical tlog-tiles location, and the *bytestore.S3
// adapter namespaces it per-log. One chokepoint so the shipper (Put) and the
// backend (Get) can never drift to different keys.
func tesseraTileKey(path string) string { return path }

// ObjectTileBackend reads tlog-tiles tiles from an ObjectStore. It satisfies
// TileBackend, so NewTileReader / the proof adapter / SeqHashFromEntryTile serve
// inclusion proofs and entry-bundle lookups from S3/GCS exactly as they do over
// POSIXTileBackend — the read front needs no shared filesystem.
type ObjectTileBackend struct{ obj ObjectStore }

var _ TileBackend = (*ObjectTileBackend)(nil)

// NewObjectTileBackend roots a tile backend on an object store (production: a
// *bytestore.S3 pointed at the shared bucket the writer ships tiles to).
func NewObjectTileBackend(obj ObjectStore) *ObjectTileBackend {
	return &ObjectTileBackend{obj: obj}
}

// ReadTileByPath fetches the tile at the c2sp path, mapping the object store's
// not-found (bytestore.ErrNotFound) to os.ErrNotExist — the exact sentinel
// TileReader.Fetch uses for its partial→full fallback and the proof builder
// treats as "not yet integrated" rather than a hard backing-store fault. Matches
// POSIXTileBackend.ReadTileByPath's contract.
func (b *ObjectTileBackend) ReadTileByPath(ctx context.Context, path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("tessera/object: ReadTileByPath requires non-empty path")
	}
	data, err := b.obj.GetObject(ctx, tesseraTileKey(path))
	if errors.Is(err, bytestore.ErrNotFound) {
		return nil, fmt.Errorf("tessera/object: tile %q: %w", path, os.ErrNotExist)
	}
	if err != nil {
		return nil, fmt.Errorf("tessera/object: read tile %q: %w", path, err)
	}
	return data, nil
}
