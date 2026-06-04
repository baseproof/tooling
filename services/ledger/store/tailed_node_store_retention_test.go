package store

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
)

// RETENTION INVARIANT GUARD
//
// Offline regeneration of a historical (as-of) governance proof at the 15-year
// horizon requires that a node committed under a published checkpoint root is
// NEVER unservable. PruneTiled (tailed_node_store.go) is the ONLY eviction of
// SMT nodes in the store, and serving an as-of proof reads those nodes, so the
// whole retention guarantee reduces to one fail-closed property of PruneTiled:
//
//	for every committed node, at every instant: (in tail) OR (durably in tiles).
//
// i.e. a node leaves the tail ONLY after the durability oracle confirms it is in
// tiles — there is never a window in which a published root's node is gone from
// both (no GC window). These tests pin that property with positive cases
// (servable after eviction; whole-root servable across prune) and negative
// regression cases (an un-durable node is never evicted; an inconclusive
// existence check retains, never evicts).
//
// Note on scope: the recent-ENTRY cache eviction (evictLocked, recent_entry_cache.go)
// drops entry bodies that remain durable in Postgres independently, and the
// durable root state (smt_root_state) + tiled nodes have NO deletion path at all
// — so PruneTiled is the only place retention could regress, and the only place
// that needs a guard. No Postgres is involved in the eviction decision, so this
// guard is a deterministic, DB-free unit test.

// truthfulExists models the production oracle: the tile store's existence check
// (S3 HEAD / stat). A node "exists durably" iff it is present in the durable
// tile store. PruneTiled's safety is contractually conditioned on a truthful
// oracle; in production that oracle IS the tile store, so it cannot lie.
func truthfulExists(durable *smt.InMemoryNodeStore) func(context.Context, [32]byte) (bool, error) {
	return func(_ context.Context, id [32]byte) (bool, error) {
		n, err := durable.Get(id)
		return n != nil, err
	}
}

// Positive: a node confirmed durable is evicted from the tail (prune does its job
// of bounding the tail) yet stays fully servable — now via the durable tiles.
// There is no window where it is unservable.
func TestRetention_DurableNodeEvictedButStillServable(t *testing.T) {
	ctx := context.Background()
	durable := smt.NewInMemoryNodeStore()
	tn := NewTailedNodeStore(durable)

	n := leaf(1)
	h, _ := tn.Put(n) // committed to the tail
	if got, _ := tn.Get(h); got == nil {
		t.Fatal("precondition: freshly committed node not readable from the tail")
	}

	// The reconciler tiles it (durable), then prunes with the truthful oracle.
	_, _ = durable.Put(n)
	tn.PruneTiled(ctx, truthfulExists(durable))

	if tn.TailLen() != 0 {
		t.Fatalf("durable node was not evicted from the tail: TailLen=%d, want 0", tn.TailLen())
	}
	if got, _ := tn.Get(h); got == nil {
		t.Fatal("RETENTION VIOLATED: durable node unservable after prune (GC window)")
	}
}

// Negative / regression: a node that is NOT yet durable must never be evicted —
// evicting it would erase the only copy and open a serving gap for a published
// root. The truthful oracle reports it absent from tiles, so it must be retained.
func TestRetention_UndurableNodeNeverEvicted(t *testing.T) {
	ctx := context.Background()
	durable := smt.NewInMemoryNodeStore()
	tn := NewTailedNodeStore(durable)

	n := leaf(7)
	h, _ := tn.Put(n) // in the tail, deliberately NOT tiled

	tn.PruneTiled(ctx, truthfulExists(durable))

	if tn.TailLen() != 1 {
		t.Fatalf("RETENTION VIOLATED: un-durable node was evicted (data loss); TailLen=%d, want 1", tn.TailLen())
	}
	if got, _ := tn.Get(h); got == nil {
		t.Fatal("RETENTION VIOLATED: un-durable node unservable after prune")
	}
}

// Negative / regression (fail-closed): on an inconclusive existence check (a
// transient tile HEAD/stat error) the node MUST be retained and re-checked next
// cycle — pruning must never evict on an error, even if the node happens to be
// durable, because the prune cannot prove it.
func TestRetention_ExistsErrorRetains(t *testing.T) {
	ctx := context.Background()
	durable := smt.NewInMemoryNodeStore()
	tn := NewTailedNodeStore(durable)

	n := leaf(9)
	h, _ := tn.Put(n)
	_, _ = durable.Put(n) // it IS durable...

	erroring := func(_ context.Context, _ [32]byte) (bool, error) {
		return false, errors.New("transient tile existence-check failure")
	}
	tn.PruneTiled(ctx, erroring)

	// ...but the inconclusive check means we cannot prove durability → retain.
	if tn.TailLen() != 1 {
		t.Fatalf("RETENTION VIOLATED: node evicted on an existence-check error; TailLen=%d, want 1", tn.TailLen())
	}
	if got, _ := tn.Get(h); got == nil {
		t.Fatal("node unservable after an errored prune cycle")
	}
}

// Positive (combined gating): eviction is strictly gated on durability across
// cycles — a node is retained while un-tiled, and only after it is tiled does a
// later prune drop it from the tail, still leaving it servable. Pins the exact
// "evict only after durable" ordering.
func TestRetention_EvictionGatedOnDurability(t *testing.T) {
	ctx := context.Background()
	durable := smt.NewInMemoryNodeStore()
	tn := NewTailedNodeStore(durable)

	n := leaf(5)
	h, _ := tn.Put(n)

	// Cycle 1 — not yet tiled → retained.
	tn.PruneTiled(ctx, truthfulExists(durable))
	if tn.TailLen() != 1 {
		t.Fatal("node evicted before it was durable (retention violated)")
	}
	if got, _ := tn.Get(h); got == nil {
		t.Fatal("node unservable while legitimately retained")
	}

	// The reconciler tiles it.
	_, _ = durable.Put(n)

	// Cycle 2 — now durable → evicted, but still servable via tiles.
	tn.PruneTiled(ctx, truthfulExists(durable))
	if tn.TailLen() != 0 {
		t.Fatal("durable node not evicted on the cycle after it was tiled")
	}
	if got, _ := tn.Get(h); got == nil {
		t.Fatal("RETENTION VIOLATED: node unservable after eviction (GC window)")
	}
}

// Headline property: a whole published checkpoint root stays fully servable
// across (repeated) prune cycles. Half its nodes are durable (and get evicted
// from the tail), half are still tail-only (and are retained) — and EVERY node
// remains servable throughout. This is the "no GC window for a published root"
// guarantee end-to-end at the node-store layer.
func TestRetention_PublishedRootNoServingGapAcrossPrune(t *testing.T) {
	ctx := context.Background()
	durable := smt.NewInMemoryNodeStore()
	tn := NewTailedNodeStore(durable)

	const n = 24
	hashes := make([][32]byte, 0, n)
	for i := 0; i < n; i++ {
		nd := leaf(byte(i + 1))
		h, _ := tn.Put(nd) // every node of the root enters the tail
		hashes = append(hashes, h)
		if i%2 == 0 { // tile the even-indexed half (durable); odd half stays tail-only
			_, _ = durable.Put(nd)
		}
	}

	// Multiple cycles — pruning is idempotent and must never lose a node.
	for c := 0; c < 3; c++ {
		tn.PruneTiled(ctx, truthfulExists(durable))
	}

	// INVARIANT: every node of the published root is still servable — whether it
	// was pruned (durable in tiles) or retained (not yet tiled).
	for i, h := range hashes {
		if got, _ := tn.Get(h); got == nil {
			t.Fatalf("RETENTION VIOLATED: node %d of the published root is unservable after prune (GC window)", i)
		}
	}
	// Prune actually did work: the durable half left the tail; the un-tiled half
	// is retained (so the tail is bounded to the genuinely un-durable gap).
	if tn.TailLen() != n/2 {
		t.Fatalf("expected the %d un-tiled nodes retained in the tail, got %d", n/2, tn.TailLen())
	}
}
