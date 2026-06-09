/*
FILE PATH: store/smt_tiles.go

DESCRIPTION:

	The content-addressed SMT tile store — the A4 cutover substrate. The builder
	emits tiles here post-commit (A4a); the SMT proof handlers serve from here
	(A4c) by wrapping it in an smt.TiledNodeStore for smt.GenerateProofAt.

	This is the de-pollution substrate: the SMT node DAG lives in immutable,
	content-addressed tiles (object store / filesystem / CDN), NOT in Postgres.
	(The old jellyfish_nodes projection is dropped in migration 0013.) Tiles are
	keyed by their top node's hash, so they are immutable, dedup across roots, and
	need no invalidation — a cache with content-addressing is always coherent.

	PROOF SOURCE (SMTProofSource, below): "tiles" serves proofs directly from the
	tile store (stateless readers, e.g. ledger-reader); "pg" serves from the live
	in-process node store (now the TailedNodeStore — tail + tile read-through, no
	longer a PG table); "shadow" computes from BOTH and compares (the byte-
	identical evidence used to validate the cutover). See SMTProofSource below.

	Backends share one interface so GCS/S3 (A4b) drop in without touching the
	builder or handlers; this file ships the in-memory (tests/shadow) and POSIX
	(dev/single-node) backends.
*/
package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// SMTProofSource selects where SMT proofs are served from. "tiles" serves
// directly from the content-addressed tile store (stateless readers). "pg"
// serves from the live in-process node store (the TailedNodeStore: in-memory
// tail + tile read-through) — the name is kept for config compat
// (LEDGER_SMT_PROOF_SOURCE), as the node DAG no longer lives in PG. "shadow"
// computes from BOTH and compares (the byte-identical cutover evidence) while
// serving the pg result.
type SMTProofSource string

const (
	SMTProofSourcePG     SMTProofSource = "pg"
	SMTProofSourceTiles  SMTProofSource = "tiles"
	SMTProofSourceShadow SMTProofSource = "shadow"
)

// ParseSMTProofSource maps an env/config string to a source, defaulting to the
// safe pg path on anything unrecognised.
func ParseSMTProofSource(s string) SMTProofSource {
	switch SMTProofSource(strings.ToLower(strings.TrimSpace(s))) {
	case SMTProofSourceTiles:
		return SMTProofSourceTiles
	case SMTProofSourceShadow:
		return SMTProofSourceShadow
	default:
		return SMTProofSourcePG
	}
}

// GenerateSMTProof serves an SMT proof at root per the source mode:
//   - pg:     from nodes (the live in-process NodeStore — now the TailedNodeStore)
//   - tiles:  from the content-addressed tile store (the de-polluted node substrate)
//   - shadow: compute BOTH, return mismatch=true if they differ (the cutover
//     evidence), but SERVE the pg result (safe while shadowing)
//
// tiles/cache may be nil only for pg mode. The returned mismatch is meaningful
// only in shadow mode (false otherwise).
func GenerateSMTProof(
	ctx context.Context,
	mode SMTProofSource,
	nodes smt.NodeStore,
	tiles SMTTileStore,
	cache *smt.TileCache,
	root, key [32]byte,
) (proof *types.SMTProof, mismatch bool, err error) {
	switch mode {
	case SMTProofSourceTiles:
		ts := smt.NewTiledNodeStore(ctx, tiles, cache)
		p, perr := smt.GenerateProofAt(ts, root, key)
		return p, false, perr
	case SMTProofSourceShadow:
		pgProof, perr := smt.GenerateProofAt(nodes, root, key)
		if perr != nil {
			return nil, false, perr
		}
		ts := smt.NewTiledNodeStore(ctx, tiles, cache)
		tileProof, terr := smt.GenerateProofAt(ts, root, key)
		// A tile error or a divergence is a shadow mismatch; serve pg.
		mm := terr != nil || !reflect.DeepEqual(pgProof, tileProof)
		return pgProof, mm, nil
	default: // pg
		p, perr := smt.GenerateProofAt(nodes, root, key)
		return p, false, perr
	}
}

// SMTTileStore persists and serves content-addressed SMT tiles. Fetch satisfies
// smt.TileFetcher (returns os.ErrNotExist on a miss, which smt.TiledNodeStore
// treats as a clean absent-node). Put is content-addressed and idempotent: the
// same id always carries the same bytes (re-Put is a no-op-equivalent overwrite).
type SMTTileStore interface {
	Put(ctx context.Context, id [32]byte, encoded []byte) error
	Fetch(ctx context.Context, id [32]byte) ([]byte, error)
	// Exists reports whether the tile for id is durably present. It is the EXACT
	// existence oracle the reconciler hands smt.BuildDirtyTiles as `known` (the
	// SDK requires exactness: a false negative re-emits harmlessly, a false
	// positive strands a needed tile). A backing-store error surfaces so the
	// caller can treat it as "not known" (re-emit) rather than wrongly skip.
	Exists(ctx context.Context, id [32]byte) (bool, error)
}

// SMTTileLister enumerates the id (top hash) of every durable tile. It is the
// optional capability the node-index backfill needs to rebuild the index from the
// durable tile set (the DB-loss / fresh-index recovery path) — O(tiles), reading
// the checkpoint-attested tiles rather than replaying entry history. fn returning
// an error aborts the scan. All three tile stores implement it.
type SMTTileLister interface {
	ListTiles(ctx context.Context, fn func(id [32]byte) error) error
}

// Compile-time proof the store is usable as an smt.TileFetcher + lister.
var (
	_ smt.TileFetcher = (*MemSMTTileStore)(nil)
	_ smt.TileFetcher = (*PosixSMTTileStore)(nil)
	_ SMTTileLister   = (*MemSMTTileStore)(nil)
	_ SMTTileLister   = (*PosixSMTTileStore)(nil)
)

// tileIDFromKey parses a tile's 32-byte id from the trailing 64-hex segment of an
// object key or filesystem path (smt.TilePath's …/<aa>/<bb>/<64-hex> layout).
// ok=false for any key whose last segment is not a 32-byte hex hash (so unrelated
// objects under the prefix are skipped, not misread).
func tileIDFromKey(key string) ([32]byte, bool) {
	key = filepath.ToSlash(key)
	last := key[strings.LastIndex(key, "/")+1:]
	if len(last) != 64 {
		return [32]byte{}, false
	}
	raw, err := hex.DecodeString(last)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	var id [32]byte
	copy(id[:], raw)
	return id, true
}

// TilesCoverRoot reports whether the SMT structure rooted at `root` is ACTUALLY
// readable from the tile store — the true "tiles durable" signal. The
// tile_frontier watermark is only a CLAIM of this; a crash between AdvanceFrontier
// and a durable tile write can make the claim false (issue #189). Gates that
// decide "is there anything to recover / re-emit?" should consult this rather
// than trusting frontier_root == committed_root. EmptyHash is trivially covered.
func TilesCoverRoot(ctx context.Context, tiles SMTTileStore, cache *smt.TileCache, root [32]byte) bool {
	if root == smt.EmptyHash {
		return true
	}
	n, err := smt.NewTiledNodeStore(ctx, tiles, cache).Get(root)
	return err == nil && n != nil
}

// EmitTiles encodes and persists a tile set produced by smt.BuildTiles /
// BuildDirtyTiles. Returns the first error; the post-commit caller logs and
// continues (durable PG + Tessera state is already committed, so a tile-write
// failure is recoverable by a later backfill, never a data-loss).
func EmitTiles(ctx context.Context, ts SMTTileStore, tiles map[[32]byte]smt.SMTTile) error {
	for id, tile := range tiles {
		enc, err := smt.EncodeTile(tile)
		if err != nil {
			return fmt.Errorf("store/smt_tiles: encode tile %x: %w", id[:6], err)
		}
		if err := ts.Put(ctx, id, enc); err != nil {
			return fmt.Errorf("store/smt_tiles: put tile %x: %w", id[:6], err)
		}
	}
	return nil
}

// MemSMTTileStore is an in-memory tile store for tests and the shadow-compare
// path (no object store needed to gather byte-identical evidence).
type MemSMTTileStore struct {
	mu sync.RWMutex
	m  map[[32]byte][]byte
}

// NewMemSMTTileStore constructs an empty in-memory tile store.
func NewMemSMTTileStore() *MemSMTTileStore {
	return &MemSMTTileStore{m: make(map[[32]byte][]byte)}
}

// Put stores a copy of encoded under id.
func (s *MemSMTTileStore) Put(_ context.Context, id [32]byte, encoded []byte) error {
	s.mu.Lock()
	s.m[id] = append([]byte(nil), encoded...)
	s.mu.Unlock()
	return nil
}

// Fetch returns the bytes for id, or os.ErrNotExist.
func (s *MemSMTTileStore) Fetch(_ context.Context, id [32]byte) ([]byte, error) {
	s.mu.RLock()
	b, ok := s.m[id]
	s.mu.RUnlock()
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

// Exists reports whether a tile for id is held.
func (s *MemSMTTileStore) Exists(_ context.Context, id [32]byte) (bool, error) {
	s.mu.RLock()
	_, ok := s.m[id]
	s.mu.RUnlock()
	return ok, nil
}

// Len reports the number of distinct tiles held (metrics/tests).
func (s *MemSMTTileStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// ListTiles calls fn for each resident tile id. Ids are snapshotted under the
// lock and fn is invoked OUTSIDE it (fn may be slow, e.g. a PG write).
func (s *MemSMTTileStore) ListTiles(_ context.Context, fn func(id [32]byte) error) error {
	s.mu.RLock()
	ids := make([][32]byte, 0, len(s.m))
	for id := range s.m {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	for _, id := range ids {
		if err := fn(id); err != nil {
			return err
		}
	}
	return nil
}

// PosixSMTTileStore is a filesystem tile store using the canonical
// smt.TilePath fan-out (smt/tile/<aa>/<bb>/<hash>) under root. Suitable for
// dev/single-node and as the local mirror a CDN/object-store fronts.
type PosixSMTTileStore struct {
	root string
}

// NewPosixSMTTileStore roots a tile store at dir.
func NewPosixSMTTileStore(dir string) *PosixSMTTileStore {
	return &PosixSMTTileStore{root: dir}
}

// Put writes encoded to <root>/<TilePath(id)> CRASH-DURABLY: write to a temp
// file, fsync it, rename into place, then fsync the parent directory. Only then
// return nil. Tiles are content-addressed + immutable, so the only correctness
// requirement is that "Put returned ⇒ the bytes survive a crash" — the contract
// EmitDurable and the tile frontier already ASSUME (the reconciler advances the
// durable frontier, and the builder publishes the horizon, only after EmitDurable
// returns nil). The previous os.WriteFile left bytes in the page cache, so a
// SIGKILL between the write and the kernel flush lost tiles the frontier had
// already certified — permanently stranding the published horizon (issue #189).
func (s *PosixSMTTileStore) Put(_ context.Context, id [32]byte, encoded []byte) error {
	full := filepath.Join(s.root, filepath.FromSlash(smt.TilePath(id)))
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("store/smt_tiles: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tile-*.tmp")
	if err != nil {
		return fmt.Errorf("store/smt_tiles: tmp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store/smt_tiles: write: %w", err)
	}
	if err := tmp.Sync(); err != nil { // file bytes → stable storage
		_ = tmp.Close()
		return fmt.Errorf("store/smt_tiles: fsync file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store/smt_tiles: close: %w", err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		return fmt.Errorf("store/smt_tiles: rename: %w", err)
	}
	// fsync the directory so the rename (the new dir entry) is itself durable —
	// otherwise the file contents survive but the name that points at them may not.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Exists reports whether <root>/<TilePath(id)> is present (a cheap stat — no
// body read), for the reconciler's `known` predicate.
func (s *PosixSMTTileStore) Exists(_ context.Context, id [32]byte) (bool, error) {
	full := filepath.Join(s.root, filepath.FromSlash(smt.TilePath(id)))
	if _, err := os.Stat(full); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else {
		return false, fmt.Errorf("store/smt_tiles: stat: %w", err)
	}
}

// Fetch reads <root>/<TilePath(id)>, mapping a missing file to os.ErrNotExist.
func (s *PosixSMTTileStore) Fetch(_ context.Context, id [32]byte) ([]byte, error) {
	full := filepath.Join(s.root, filepath.FromSlash(smt.TilePath(id)))
	b, err := os.ReadFile(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("store/smt_tiles: read: %w", err)
	}
	return b, nil
}

// ListTiles walks <root>/smt/tile/ and calls fn for each tile file's id (parsed
// from its content-hash filename). A missing tile tree (nothing emitted yet) is
// not an error — the scan is simply empty.
func (s *PosixSMTTileStore) ListTiles(_ context.Context, fn func(id [32]byte) error) error {
	base := filepath.Join(s.root, "smt", "tile")
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if errors.Is(werr, os.ErrNotExist) {
				return nil // no tiles emitted yet
			}
			return werr
		}
		if d.IsDir() {
			return nil
		}
		if id, ok := tileIDFromKey(path); ok {
			return fn(id)
		}
		return nil // skip temp files / non-tile entries
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
