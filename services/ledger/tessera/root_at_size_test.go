/*
FILE PATH: tessera/root_at_size_test.go

DESCRIPTION:

	Unit tests for TesseraAdapter.RootAtSize — the CT-aligned
	size-bound root primitive (issue #189 follow-on, PR-1).

	Pins:
	  - treeSize == 0 returns the RFC 6962 empty-tree root
	    (SHA-256 of empty string).
	  - For treeSize == Head().TreeSize, RootAtSize returns the
	    same bytes as Head().RootHash (live-head alignment).
	  - For treeSize < Head().TreeSize (a historical size),
	    RootAtSize returns the root captured at that size — proving
	    the tile-derivation is independent of the live head.
	  - For treeSize > integrated, returns ErrTilesNotDurable.
	  - Determinism: two calls with identical inputs return
	    byte-identical roots (including their NetworkID-independent
	    contents — pure tile bytes).

	Follows the proof_adapter_test.go fixture pattern
	(newTestEmbeddedAppender + NewPOSIXTileBackend + NewTileReader).
*/
package tessera

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
)

// rootAtSizeFixture is the shared setup: appends N leaves, waits for
// Tessera to integrate them, wires the TesseraAdapter, and returns the
// adapter + the live head's TreeSize for use by the test.
func rootAtSizeFixture(t *testing.T, n int) (*TesseraAdapter, *EmbeddedAppender, uint64) {
	t.Helper()
	app, dir, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	for i := 0; i < n; i++ {
		var leaf [32]byte
		if _, err := rand.Read(leaf[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := app.AppendLeaf(ctx, leaf[:]); err != nil {
			t.Fatalf("AppendLeaf(%d): %v", i, err)
		}
	}

	// Wait for integration to catch up to N.
	deadline := time.Now().Add(30 * time.Second)
	var headSize uint64
	for time.Now().Before(deadline) {
		if h, err := app.Head(); err == nil && h.TreeSize >= uint64(n) {
			headSize = h.TreeSize
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if headSize < uint64(n) {
		t.Fatalf("integration never reached tree_size=%d; dir: %s", n, dir)
	}

	backend, err := NewPOSIXTileBackend(dir)
	if err != nil {
		t.Fatalf("NewPOSIXTileBackend(%s): %v", dir, err)
	}
	adapter := NewTesseraAdapter(ctx, app, NewTileReader(backend, 1024), nil)
	return adapter, app, headSize
}

// TestRootAtSize_Zero pins the RFC 6962 empty-tree convention. The
// compact-range library returns nil for an empty range; RootAtSize
// must canonicalize that into SHA-256("") so callers (and the cosign
// payload) don't have to special-case the no-leaves boundary.
func TestRootAtSize_Zero(t *testing.T) {
	adapter, _, _ := rootAtSizeFixture(t, 50)

	root, err := adapter.RootAtSize(context.Background(), 0)
	if err != nil {
		t.Fatalf("RootAtSize(0): %v", err)
	}
	wantBytes := rfc6962.DefaultHasher.EmptyRoot()
	// Sanity: empty-tree root is the SHA-256 of the empty byte slice.
	want := sha256.Sum256(nil)
	if string(wantBytes) != string(want[:]) {
		t.Fatalf("rfc6962 EmptyRoot does not match SHA-256(''); upstream contract change?")
	}
	if root != want {
		t.Fatalf("RootAtSize(0) = %x, want %x", root, want)
	}
}

// TestRootAtSize_MatchesLiveHead pins the live-head alignment: when
// treeSize equals the current head's TreeSize, RootAtSize returns
// the bytes Head() would return. This is the basic correctness
// property — the tile-derived root and the signed-checkpoint root
// must agree at the same size.
func TestRootAtSize_MatchesLiveHead(t *testing.T) {
	adapter, app, headSize := rootAtSizeFixture(t, 600)

	root, err := adapter.RootAtSize(context.Background(), headSize)
	if err != nil {
		t.Fatalf("RootAtSize(%d): %v", headSize, err)
	}
	head, err := app.Head()
	if err != nil {
		t.Fatalf("Head(): %v", err)
	}
	if root != head.RootHash {
		t.Fatalf("RootAtSize(%d) = %x, Head().RootHash = %x", headSize, root, head.RootHash)
	}
}

// TestRootAtSize_AtHistoricalSize pins the load-bearing CT property
// for this PR: a root at a historical treeSize is derivable from
// tiles INDEPENDENTLY of the live head. The fixture captures the
// head at size M, then appends more leaves to advance the tree to
// M+more, and asserts RootAtSize(M) still returns the original
// captured root — proving the function is a pure tile-bytes derivation
// that doesn't accidentally read live state.
func TestRootAtSize_AtHistoricalSize(t *testing.T) {
	app, dir, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	// Phase 1: append M leaves, capture the head.
	const M = 300
	for i := 0; i < M; i++ {
		var leaf [32]byte
		if _, err := rand.Read(leaf[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := app.AppendLeaf(ctx, leaf[:]); err != nil {
			t.Fatalf("AppendLeaf phase1 %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	var capturedHead [32]byte
	var capturedSize uint64
	for time.Now().Before(deadline) {
		if h, err := app.Head(); err == nil && h.TreeSize >= M {
			capturedSize = h.TreeSize
			capturedHead = h.RootHash
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if capturedSize < M {
		t.Fatalf("phase1 integration never reached %d; dir: %s", M, dir)
	}

	// Phase 2: append more leaves to advance the tree past M.
	const extra = 200
	for i := 0; i < extra; i++ {
		var leaf [32]byte
		if _, err := rand.Read(leaf[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if _, err := app.AppendLeaf(ctx, leaf[:]); err != nil {
			t.Fatalf("AppendLeaf phase2 %d: %v", i, err)
		}
	}
	deadline = time.Now().Add(30 * time.Second)
	var newSize uint64
	for time.Now().Before(deadline) {
		if h, err := app.Head(); err == nil && h.TreeSize >= capturedSize+extra {
			newSize = h.TreeSize
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if newSize < capturedSize+extra {
		t.Fatalf("phase2 integration never reached %d; dir: %s", capturedSize+extra, dir)
	}

	// Adapter is built AFTER both phases — the tile substrate now
	// contains all M+extra leaves. RootAtSize(capturedSize) must
	// still return the root captured at the M-leaf moment.
	backend, err := NewPOSIXTileBackend(dir)
	if err != nil {
		t.Fatalf("NewPOSIXTileBackend(%s): %v", dir, err)
	}
	adapter := NewTesseraAdapter(ctx, app, NewTileReader(backend, 1024), nil)

	historical, err := adapter.RootAtSize(ctx, capturedSize)
	if err != nil {
		t.Fatalf("RootAtSize(%d) historical: %v", capturedSize, err)
	}
	if historical != capturedHead {
		t.Fatalf("RootAtSize(%d) drift: got %x, want %x (captured at phase 1)",
			capturedSize, historical, capturedHead)
	}

	// Also confirm the live root at the new size is consistent.
	live, err := adapter.RootAtSize(ctx, newSize)
	if err != nil {
		t.Fatalf("RootAtSize(%d) live: %v", newSize, err)
	}
	head, err := app.Head()
	if err != nil {
		t.Fatalf("Head(): %v", err)
	}
	if live != head.RootHash {
		t.Fatalf("RootAtSize(%d) live: got %x, want %x", newSize, live, head.RootHash)
	}
}

// TestRootAtSize_BeyondIntegrated_ReturnsErrTilesNotDurable pins the
// durability gate. Asking for a size that exceeds IntegratedSize must
// surface ErrTilesNotDurable as a matchable sentinel — the signal the
// builder's Step 6 (PR-2) will use to skip the cosign cycle cleanly
// without panicking, retrying, or reading partial tile bytes.
func TestRootAtSize_BeyondIntegrated_ReturnsErrTilesNotDurable(t *testing.T) {
	adapter, _, headSize := rootAtSizeFixture(t, 100)

	// Request a size well past integrated. The integrated upper
	// bound IS headSize for an embedded appender (Head and
	// IntegratedSize converge once integration catches up).
	_, err := adapter.RootAtSize(context.Background(), headSize+1000)
	if !errors.Is(err, ErrTilesNotDurable) {
		t.Fatalf("expected ErrTilesNotDurable, got: %v", err)
	}
}

// TestRootAtSize_Deterministic pins the function's purity: two calls
// with the same (treeSize) on the same tile substrate return
// byte-identical roots. This is the property the cosign payload
// stability depends on — a witness asked to sign the same
// (treeSize, RootAtSize(treeSize)) tuple twice MUST see the same
// bytes, regardless of when each call landed.
func TestRootAtSize_Deterministic(t *testing.T) {
	adapter, _, headSize := rootAtSizeFixture(t, 400)
	ctx := context.Background()

	const target uint64 = 250 // historical, NOT the live head
	if target >= headSize {
		t.Fatalf("test invariant: target %d must be < headSize %d", target, headSize)
	}

	a, err := adapter.RootAtSize(ctx, target)
	if err != nil {
		t.Fatalf("RootAtSize call A: %v", err)
	}
	b, err := adapter.RootAtSize(ctx, target)
	if err != nil {
		t.Fatalf("RootAtSize call B: %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: A=%x B=%x", a, b)
	}
}
