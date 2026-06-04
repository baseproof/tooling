/*
FILE PATH: store/smt_tiles_s3.go

S3SMTTileStore — the object-store implementation of SMTTileStore.

Content-addressed SMT tiles keyed by smt.TilePath(id) (the SAME c2sp-style
fan-out PosixSMTTileStore uses), served from any S3-compatible object store —
SeaweedFS in this deployment, MinIO / R2 / AWS S3 elsewhere. It is a drop-in
peer of PosixSMTTileStore: the builder's post-commit emit and the proof
handler's as-of read both speak the SMTTileStore interface, so swapping the
local filesystem for shared object storage touches only the wiring, never the
logic.

WHY THIS EXISTS (zero-trust / transparency)

	The proof-serving substrate must not live on a single node's local disk: an
	auditor, a CDN edge, or a horizontally-scaled read replica has to fetch the
	exact content-addressed tiles independently and verify them by hash against
	the witness-cosigned root. A shared, content-addressed object store is that
	substrate. PosixSMTTileStore is fine for single-node dev; S3SMTTileStore is
	the network-scale, transparent default.

	The store depends on a key-addressed object CONTRACT (objectPutGetter), not a
	concrete backend — *bytestore.S3 satisfies it today; any future backend drops
	in without touching this file or any caller.
*/
package store

import (
	"context"
	"errors"
	"os"

	"github.com/baseproof/baseproof/core/smt"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// objectPutGetter is the minimal key-addressed object surface an
// S3SMTTileStore needs. *bytestore.S3 satisfies it; tests inject a fake.
// Depending on the interface (not *bytestore.S3) is the point — the tile
// substrate is swappable without code changes.
type objectPutGetter interface {
	// PutObject writes data at key. Idempotent for content-addressed callers.
	PutObject(ctx context.Context, key string, data []byte) error
	// GetObject reads the bytes at key, returning bytestore.ErrNotFound on a miss.
	GetObject(ctx context.Context, key string) ([]byte, error)
	// HeadObject reports existence at key without transferring the body.
	HeadObject(ctx context.Context, key string) (bool, error)
}

// S3SMTTileStore serves content-addressed SMT tiles from an object store.
type S3SMTTileStore struct{ obj objectPutGetter }

// Compile-time proof it satisfies both the ledger interface and the SDK fetcher.
var (
	_ SMTTileStore    = (*S3SMTTileStore)(nil)
	_ smt.TileFetcher = (*S3SMTTileStore)(nil)
)

// NewS3SMTTileStore roots a tile store on any key-addressed object store
// (production: a *bytestore.S3 pointed at the SeaweedFS bucket).
func NewS3SMTTileStore(obj objectPutGetter) *S3SMTTileStore {
	return &S3SMTTileStore{obj: obj}
}

// Put writes the encoded tile at smt.TilePath(id) — the same content-address
// fan-out PosixSMTTileStore uses, so tiles emitted to POSIX and to S3 share one
// namespace and a CDN can front the object store unchanged.
func (s *S3SMTTileStore) Put(ctx context.Context, id [32]byte, encoded []byte) error {
	return s.obj.PutObject(ctx, smt.TilePath(id), encoded)
}

// Fetch reads the tile at smt.TilePath(id), mapping the object store's
// not-found (bytestore.ErrNotFound) to os.ErrNotExist so smt.TiledNodeStore
// classifies a clean miss (ErrUnknownRoot / ErrNodeMissing) rather than a hard
// backing-store fault — preserving the SMTTileStore contract byte-for-byte.
func (s *S3SMTTileStore) Fetch(ctx context.Context, id [32]byte) ([]byte, error) {
	b, err := s.obj.GetObject(ctx, smt.TilePath(id))
	if errors.Is(err, bytestore.ErrNotFound) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Exists reports whether the tile for id is durably present via an object-store
// HEAD (no body transfer) — the exact `known` predicate for BuildDirtyTiles.
func (s *S3SMTTileStore) Exists(ctx context.Context, id [32]byte) (bool, error) {
	return s.obj.HeadObject(ctx, smt.TilePath(id))
}
