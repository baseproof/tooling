/*
FILE PATH: tessera/tile_shipper_test.go

Tests for the tessera tile shipper:

  - tilesToShip: the incremental enumerator — hand-computed deltas pin the
    minimal-ship contract (frontier re-ship + new tiles only; unchanged levels
    skipped) the 10B/500-TPS scale target depends on.
  - TileShipper: round-trip + durable cursor + resume + fail-closed.
  - ShippingPublisher: tiles ship BEFORE the horizon is published, and a ship
    error withholds the publish (the read front's correctness invariant).
  - End-to-end: a REAL embedded tessera tree → ship to an in-memory object store
    → serve inclusion proofs AND entry-bundle seq→hash from the object store
    ALONE (no POSIX), verified against the head root via the canonical RFC 6962
    verifier. This is the PG-free read-front path the pgoff arm exercises.
*/
package tessera

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// fakeTileSource is an in-memory TileBackend standing in for the writer's POSIX
// tile dir: it records the paths read (so a test can assert the minimal ship set)
// and can be told to miss specific paths (os.ErrNotExist) to exercise fail-closed.
type fakeTileSource struct {
	mu    sync.Mutex
	reads []string
	miss  map[string]bool
}

func newFakeTileSource() *fakeTileSource { return &fakeTileSource{miss: map[string]bool{}} }

// discardLogger is a no-op slog logger so a test can drive the shipper's logging
// path without noise.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func (f *fakeTileSource) ReadTileByPath(_ context.Context, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, path)
	if f.miss[path] {
		return nil, fmt.Errorf("fake: %q: %w", path, os.ErrNotExist)
	}
	return []byte("T:" + path), nil
}

func (f *fakeTileSource) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reads)
}

func sortedRefs(refs []tileRef) []tileRef {
	out := append([]tileRef(nil), refs...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.entry != b.entry {
			return !a.entry // hash tiles first
		}
		if a.level != b.level {
			return a.level < b.level
		}
		if a.index != b.index {
			return a.index < b.index
		}
		return a.width < b.width
	})
	return out
}

func TestTilesToShip(t *testing.T) {
	cases := []struct {
		name              string
		lastSize, newSize uint64
		want              []tileRef
	}{
		{
			name: "first leaf", lastSize: 0, newSize: 1,
			want: []tileRef{{level: 0, index: 0, width: 1}, {entry: true, index: 0, width: 1}},
		},
		{
			// 256 fills level-0 tile 0 (width 0 = full), opens level-1 tile 0 (1 node),
			// and fills entry bundle 0.
			name: "first full tile", lastSize: 0, newSize: 256,
			want: []tileRef{
				{level: 0, index: 0, width: 0},
				{level: 1, index: 0, width: 1},
				{entry: true, index: 0, width: 0},
			},
		},
		{
			// One leaf past a tile boundary: only the NEW level-0 tile 1 + entry
			// bundle 1; level 1 unchanged (3>>8 == 256>>8) ⇒ skipped. Minimal delta.
			name: "one past boundary", lastSize: 256, newSize: 257,
			want: []tileRef{{level: 0, index: 1, width: 1}, {entry: true, index: 1, width: 1}},
		},
		{
			// The 600-leaf scale: level-0 tiles 1 (now full) + 2 (partial 88);
			// level-1 tile 0 grows to 2; entry bundles 1 (full) + 2 (88). Tile 0 at
			// level 0 was full at lastSize=300 ⇒ NOT re-shipped.
			name: "scale delta", lastSize: 300, newSize: 600,
			want: []tileRef{
				{level: 0, index: 1, width: 0},
				{level: 0, index: 2, width: 88},
				{level: 1, index: 0, width: 2},
				{entry: true, index: 1, width: 0},
				{entry: true, index: 2, width: 88},
			},
		},
		{name: "noop equal", lastSize: 500, newSize: 500, want: nil},
		{name: "noop shrink", lastSize: 600, newSize: 599, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sortedRefs(tilesToShip(tc.lastSize, tc.newSize))
			want := sortedRefs(tc.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("tilesToShip(%d,%d):\n got=%+v\nwant=%+v", tc.lastSize, tc.newSize, got, want)
			}
		})
	}
}

// TestTilesToShip_FullTreeCoversEveryTile pins that shipping from 0 enumerates
// EVERY tile of the tree (the union of all audit-path tiles) — the bulk-sync /
// fresh-log case must miss nothing.
func TestTilesToShip_FullTreeCoversEveryTile(t *testing.T) {
	const N = 600
	refs := tilesToShip(0, N)
	// Expected: level0 {0,1,2}, level1 {0}, entries {0,1,2} = 7 objects.
	if len(refs) != 7 {
		t.Fatalf("tilesToShip(0,%d) shipped %d tiles, want 7: %+v", N, len(refs), sortedRefs(refs))
	}
	// Every level-0 hash tile and entry bundle index in [0, ceil(N/256)) must appear.
	seenHash := map[uint64]bool{}
	seenEntry := map[uint64]bool{}
	for _, r := range refs {
		if r.entry {
			seenEntry[r.index] = true
		} else if r.level == 0 {
			seenHash[r.index] = true
		}
	}
	for i := uint64(0); i < 3; i++ {
		if !seenHash[i] {
			t.Errorf("level-0 hash tile %d missing", i)
		}
		if !seenEntry[i] {
			t.Errorf("entry bundle %d missing", i)
		}
	}
}

func TestTileShipper_ShipsDeltaAndPersistsCursor(t *testing.T) {
	ctx := context.Background()
	src := newFakeTileSource()
	obj := newFakeObjectStore()
	s := NewTileShipper(ctx, src, obj, discardLogger()) // also drives the success-path log

	if err := s.ShipUpTo(ctx, 256); err != nil {
		t.Fatalf("ShipUpTo(256): %v", err)
	}
	// The three size-256 objects are in the store under their bare tlog-tiles paths.
	for _, ref := range tilesToShip(0, 256) {
		if !obj.has(ref.path()) {
			t.Errorf("missing shipped object %q; keys=%v", ref.path(), obj.keys())
		}
	}
	// Cursor persisted, and reported.
	if got := s.shipped(); got != 256 {
		t.Fatalf("shipped() = %d, want 256", got)
	}
	if raw, err := obj.GetObject(ctx, tileShipCursorKey); err != nil || string(raw) != "256" {
		t.Fatalf("cursor object = %q (err %v), want \"256\"", raw, err)
	}

	// A second ship to 257 reads ONLY the delta (1 hash tile + 1 entry bundle),
	// never re-walking the tree — the scale-critical property.
	readsBefore := src.readCount()
	if err := s.ShipUpTo(ctx, 257); err != nil {
		t.Fatalf("ShipUpTo(257): %v", err)
	}
	if delta := src.readCount() - readsBefore; delta != 2 {
		t.Fatalf("delta ship read %d tiles, want 2 (minimal); reads=%v", delta, src.reads)
	}

	// Re-shipping an already-covered size is a no-op (idempotent, no reads).
	readsBefore = src.readCount()
	if err := s.ShipUpTo(ctx, 257); err != nil {
		t.Fatalf("ShipUpTo(257) again: %v", err)
	}
	if src.readCount() != readsBefore {
		t.Fatalf("re-ship to same size read %d extra tiles, want 0", src.readCount()-readsBefore)
	}
}

func TestTileShipper_ResumesFromPersistedCursor(t *testing.T) {
	ctx := context.Background()
	obj := newFakeObjectStore()
	// Pre-seed a cursor as if a prior writer had shipped through 256.
	if err := obj.PutObject(ctx, tileShipCursorKey, []byte("256")); err != nil {
		t.Fatal(err)
	}
	src := newFakeTileSource()
	s := NewTileShipper(ctx, src, obj, nil)
	if got := s.shipped(); got != 256 {
		t.Fatalf("resumed cursor = %d, want 256", got)
	}
	// Shipping to a size below the resumed cursor reads nothing (no cold re-ship).
	if err := s.ShipUpTo(ctx, 200); err != nil {
		t.Fatalf("ShipUpTo(200): %v", err)
	}
	if src.readCount() != 0 {
		t.Fatalf("resume re-shipped %d tiles below cursor, want 0", src.readCount())
	}
}

func TestTileShipper_FailClosedOnReadError(t *testing.T) {
	ctx := context.Background()
	src := newFakeTileSource()
	obj := newFakeObjectStore()
	s := NewTileShipper(ctx, src, obj, nil)

	// Make the size-1 frontier hash tile unreadable.
	src.miss[(tileRef{level: 0, index: 0, width: 1}).path()] = true

	err := s.ShipUpTo(ctx, 1)
	if err == nil {
		t.Fatal("ShipUpTo with an unreadable tile returned nil, want error")
	}
	// Fail-closed: the cursor MUST NOT advance, and MUST NOT be persisted — the
	// caller must not publish a horizon whose tiles aren't durable.
	if got := s.shipped(); got != 0 {
		t.Fatalf("cursor advanced to %d after a ship error, want 0", got)
	}
	if obj.has(tileShipCursorKey) {
		t.Fatal("cursor persisted despite a ship error")
	}
}

func TestTileShipper_FailClosedOnPutError(t *testing.T) {
	ctx := context.Background()
	src := newFakeTileSource()
	obj := newFakeObjectStore()
	obj.putErr = errors.New("object store unavailable") // every Put fails
	s := NewTileShipper(ctx, src, obj, nil)

	if err := s.ShipUpTo(ctx, 1); err == nil {
		t.Fatal("ShipUpTo with a failing object store returned nil, want error")
	}
	// Fail-closed on the WRITE leg too: the cursor stays at 0 so the next publish
	// retries the same delta rather than skipping un-shipped tiles.
	if got := s.shipped(); got != 0 {
		t.Fatalf("cursor advanced to %d after a put error, want 0", got)
	}
}

func TestTileShipper_FailClosedOnCursorPersistError(t *testing.T) {
	ctx := context.Background()
	src := newFakeTileSource()
	obj := newFakeObjectStore()
	obj.putErrKey = tileShipCursorKey // tiles ship fine; only the cursor write fails
	s := NewTileShipper(ctx, src, obj, nil)

	if err := s.ShipUpTo(ctx, 1); err == nil {
		t.Fatal("ShipUpTo with a failing cursor write returned nil, want error")
	}
	// The in-memory cursor MUST NOT advance when it could not be persisted —
	// otherwise a restart would resume past tiles whose durability isn't recorded.
	if got := s.shipped(); got != 0 {
		t.Fatalf("cursor advanced to %d when its persist failed, want 0", got)
	}
}

// recordingPublisher captures publish ordering: it records the shipper's cursor
// AT the moment of publish, so a test can prove tiles shipped first.
type recordingPublisher struct {
	calls           int
	publishedSize   uint64
	cursorAtPublish uint64
	shipper         *TileShipper
	err             error
}

func (r *recordingPublisher) PublishCosignedCheckpoint(_ context.Context, head types.CosignedTreeHead) error {
	r.calls++
	r.publishedSize = head.TreeSize
	r.cursorAtPublish = r.shipper.shipped()
	return r.err
}

func headOfSize(n uint64) types.CosignedTreeHead {
	return types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: n}}
}

func TestShippingPublisher_ShipsBeforePublish(t *testing.T) {
	ctx := context.Background()
	src := newFakeTileSource()
	obj := newFakeObjectStore()
	shipper := NewTileShipper(ctx, src, obj, nil)
	inner := &recordingPublisher{shipper: shipper}
	pub := NewShippingPublisher(inner, shipper)

	if err := pub.PublishCosignedCheckpoint(ctx, headOfSize(256)); err != nil {
		t.Fatalf("PublishCosignedCheckpoint(256): %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner publish calls = %d, want 1", inner.calls)
	}
	// The invariant: at publish time the tiles for this size are already shipped.
	if inner.cursorAtPublish < 256 {
		t.Fatalf("publish ran with shipper cursor %d < 256 — tiles not shipped first", inner.cursorAtPublish)
	}
}

func TestShippingPublisher_ShipErrorWithholdsPublish(t *testing.T) {
	ctx := context.Background()
	src := newFakeTileSource()
	obj := newFakeObjectStore()
	shipper := NewTileShipper(ctx, src, obj, nil)
	inner := &recordingPublisher{shipper: shipper}
	pub := NewShippingPublisher(inner, shipper)

	src.miss[(tileRef{level: 0, index: 0, width: 1}).path()] = true // can't ship size 1

	err := pub.PublishCosignedCheckpoint(ctx, headOfSize(1))
	if err == nil {
		t.Fatal("publish returned nil when shipping failed, want error")
	}
	if inner.calls != 0 {
		t.Fatalf("inner publish was called %d times despite a ship error, want 0 (fail-closed)", inner.calls)
	}
}

func TestShippingPublisher_PropagatesInnerError(t *testing.T) {
	ctx := context.Background()
	src := newFakeTileSource()
	obj := newFakeObjectStore()
	shipper := NewTileShipper(ctx, src, obj, nil)
	innerErr := errors.New("checkpoint publish failed")
	inner := &recordingPublisher{shipper: shipper, err: innerErr}
	pub := NewShippingPublisher(inner, shipper)

	// Tiles ship fine; the inner publisher's error must surface (the horizon is
	// the inner publisher's responsibility — the decorator never swallows it).
	err := pub.PublishCosignedCheckpoint(ctx, headOfSize(256))
	if !errors.Is(err, innerErr) {
		t.Fatalf("publish err = %v, want it to wrap the inner error", err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner publish calls = %d, want 1 (ship succeeded, so inner runs)", inner.calls)
	}
}

// TestTileShipper_ObjectBackendServesProofsAtScale is the end-to-end contract: a
// REAL embedded tessera tree → ship its tiles to an in-memory object store →
// serve inclusion proofs and entry-bundle seq→hash from the object store ALONE,
// verified against the head root via the canonical RFC 6962 verifier. Mirrors
// proof_adapter_test.go's scale (600 leaves: 3 level-0 tiles, a level-1 tile, a
// partial frontier; samples span both subtrees) but proves the OBJECT path the
// read front uses — no POSIX backend in the serving path.
func TestTileShipper_ObjectBackendServesProofsAtScale(t *testing.T) {
	app, dir, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	const N = 600
	leafData := make([][32]byte, N)
	for i := 0; i < N; i++ {
		if _, err := rand.Read(leafData[i][:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := app.AppendLeaf(ctx, leafData[i][:]); err != nil {
			t.Fatalf("AppendLeaf(%d): %v", i, err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	var head struct {
		TreeSize uint64
		RootHash [32]byte
	}
	for time.Now().Before(deadline) {
		if h, err := app.Head(); err == nil && h.TreeSize >= N {
			head.TreeSize, head.RootHash = h.TreeSize, h.RootHash
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if head.TreeSize < N {
		t.Fatalf("Head never reached tree_size=%d; dir=%s", N, dir)
	}

	// Ship the writer's POSIX tiles to a fresh object store.
	posix, err := NewPOSIXTileBackend(dir)
	if err != nil {
		t.Fatalf("NewPOSIXTileBackend: %v", err)
	}
	obj := newFakeObjectStore()
	shipper := NewTileShipper(ctx, posix, obj, nil)
	if err := shipper.ShipUpTo(ctx, head.TreeSize); err != nil {
		t.Fatalf("ShipUpTo(%d): %v", head.TreeSize, err)
	}

	// Serve proofs from the OBJECT store only — the read-front path.
	objReader := NewTileReader(NewObjectTileBackend(obj), 1024)
	adapter := NewTesseraAdapter(ctx, app, objReader, nil)

	samples := []uint64{0, 1, 127, 255, 256, 511, 512, 513, 550, 599}
	for _, seq := range samples {
		leafHash := rfc6962.DefaultHasher.HashLeaf(leafData[seq][:])
		raw, err := adapter.RawInclusionProof(seq, head.TreeSize)
		if err != nil {
			t.Fatalf("RawInclusionProof(seq=%d) from object store: %v", seq, err)
		}
		m := raw.(map[string]any)
		hexHashes, _ := m["hashes"].([]string)
		siblings := make([][]byte, len(hexHashes))
		for i, h := range hexHashes {
			b, derr := hexDecodeFixed(h)
			if derr != nil {
				t.Fatalf("decode sibling[%d] seq=%d: %v", i, seq, derr)
			}
			siblings[i] = b
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, seq, head.TreeSize, leafHash, siblings, head.RootHash[:]); err != nil {
			t.Fatalf("VerifyInclusion(seq=%d) from OBJECT store: %v", seq, err)
		}
	}

	// Entry bundles too: the /raw seq→hash fallback must resolve from the object
	// store identically to POSIX (cross-checked, so the assertion needs no
	// knowledge of the entry-tile hash semantics).
	posixReader := NewTileReader(posix, 1024)
	for _, seq := range []uint64{0, 255, 256, 599} {
		wantHash, wantFound, werr := SeqHashFromEntryTile(ctx, posixReader, head.TreeSize, seq)
		if werr != nil || !wantFound {
			t.Fatalf("POSIX SeqHashFromEntryTile(seq=%d) = (found %v, err %v)", seq, wantFound, werr)
		}
		gotHash, gotFound, gerr := SeqHashFromEntryTile(ctx, objReader, head.TreeSize, seq)
		if gerr != nil || !gotFound {
			t.Fatalf("OBJECT SeqHashFromEntryTile(seq=%d) = (found %v, err %v)", seq, gotFound, gerr)
		}
		if gotHash != wantHash {
			t.Fatalf("entry-tile hash seq=%d: object %x != posix %x", seq, gotHash, wantHash)
		}
	}
}
