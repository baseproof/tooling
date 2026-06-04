/*
FILE PATH: store/recent_entry_cache.go

In-process bounded FIFO cache of recently-committed *types.EntryWithMetadata
keyed by sequence number. Short-circuits the builder's hot read path: the
sequencer Put's an entry post-commit; the PostgresEntryFetcher Get's it
instead of round-tripping to the bytestore (S3/SeaweedFS).

KEY ARCHITECTURAL DECISIONS:
  - Bounded FIFO, NOT LRU: the access pattern is monotonic-by-seq (the builder
    reads in seq order). FIFO eviction matches the natural locality; LRU's
    extra bookkeeping buys nothing here.
  - TWO BOUNDS — entry count AND byte budget. Both are optional individually,
    but at least one MUST be positive (the constructor refuses zero/zero — a
    fully unbounded cache is a heap-pressure footgun by construction). The
    byte budget is the load-bearing bound at production scale: entry sizes
    span ~100x (small attestations vs multi-sig EIP-1271 evidence blobs), so
    a count-only cap can drift to OOM under worst-case admission while a
    byte-cap stays predictable.
  - Pure best-effort optimization. Crash-safety is by construction: on restart
    the cache is empty, the fetcher falls back to the durable PG+bytestore
    path. The cache MAY NOT hold an entry the durable store does not.
  - Stable concurrency: ONE mutex around the map + FIFO list + curBytes
    accumulator. Get and Put are O(1). The cache is the ONLY synchronization
    primitive that crosses the sequencer→builder boundary in this code path.
  - The returned *types.EntryWithMetadata MUST be treated as read-only by
    callers. The cache stores a freshly-allocated value at Put time and
    expects no mutation. This is documented on Get.

OVERSIZED-ENTRY REJECTION:

	A Put whose CanonicalBytes ALONE exceeds MaxBytes is refused (Rejects++)
	rather than evicting every other entry to make room for one we still
	can't fit. The durable PG+bytestore path stays correct, so dropping is
	safe; the Rejects counter is a leading indicator that MaxBytes is
	undersized for the workload — operators should bump LEDGER_RECENT_ENTRY_-
	CACHE_MAX_BYTES or shrink entry size upstream. Go's sumdb tile cache uses
	the same shape.

MULTI-LOG / MULTI-NETWORK NOTE:

	Each ledger instance serves ONE log DID; this cache is per-instance. A
	process running multiple logs would instantiate one cache per log. The
	cache binds to its log DID at construction (CacheConfig.LogDID) and
	rejects foreign-log EntryWithMetadata in Put (defense in depth — the
	PostgresEntryFetcher's upstream LogDID filter is no longer load-bearing
	for cache correctness).
*/
package store

import (
	"container/list"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/baseproof/baseproof/types"
)

// CacheConfig is the construction-time scope of a RecentEntryCache.
// At least one of MaxEntries / MaxBytes MUST be positive — a fully-
// unbounded cache is forbidden at construction time (NewBoundedRecent-
// EntryCache returns an error).
type CacheConfig struct {
	// MaxEntries caps entry count. 0 disables this bound (MaxBytes
	// alone governs).
	MaxEntries int

	// MaxBytes caps cumulative len(ewm.CanonicalBytes). Primary bound
	// at production scale — entry size varies ~100x (small attestations
	// vs multi-sig EIP-1271 evidence), so a count-only budget can drift
	// to OOM under worst-case admission. 0 disables this bound.
	MaxBytes int64

	// LogDID binds the cache to a single log. Non-empty ⇒ Put refuses
	// EntryWithMetadata for any other log (defense in depth). Empty ⇒
	// disable the check (multi-log fanout adapters that have validated
	// upstream, or test fixtures).
	LogDID string
}

// RecentEntryCache is the read-side surface PostgresEntryFetcher consults
// before its durable lookup, and the write-side surface the sequencer
// populates after each successful commit. Nil-safe at the call sites by
// convention (both PostgresEntryFetcher.WithCache and Sequencer.With…
// accept nil → no caching).
type RecentEntryCache interface {
	// Put inserts (or overwrites) the cached EntryWithMetadata for seq.
	// O(1). If the cache is at capacity (either bound), oldest entries
	// are evicted FIFO until both bounds are satisfied. An existing
	// entry for seq is overwritten in place (no FIFO churn); the byte
	// tally is adjusted by the delta. A Put whose CanonicalBytes alone
	// exceed MaxBytes is REFUSED (counted in Rejects). The caller MUST
	// NOT mutate ewm after Put.
	Put(seq uint64, ewm *types.EntryWithMetadata)

	// Get returns the cached EntryWithMetadata for seq, or (nil, false)
	// on miss. O(1). Callers MUST NOT mutate the returned value.
	Get(seq uint64) (*types.EntryWithMetadata, bool)

	// Len returns the current number of cached entries. O(1).
	Len() int

	// Capacity returns the configured MaxEntries (0 = no entry-count
	// bound; MaxBytes alone governs).
	Capacity() int

	// BytesCapacity returns the configured MaxBytes (0 = no byte
	// bound; MaxEntries alone governs).
	BytesCapacity() int64

	// Stats returns a snapshot of cache counters for telemetry. Cheap.
	Stats() CacheStats
}

// CacheStats is the telemetry snapshot. Sampled by the F1 instruments
// in recent_entry_cache_instruments.go.
type CacheStats struct {
	Hits      uint64
	Misses    uint64
	Evictions uint64

	// Rejects counts Put calls refused because the entry alone exceeded
	// MaxBytes. A non-zero rate is a misconfiguration signal: either
	// MaxBytes is too low for the workload's worst-case entry size, or
	// the upstream is occasionally constructing pathologically-large
	// entries the durable path will accept but the cache cannot fit.
	Rejects uint64

	// LogDIDDrops counts Put calls refused because the entry's
	// Position.LogDID disagreed with the cache's bound LogDID. A
	// programming error upstream — non-zero indicates the caller is
	// not honoring the cache's per-log invariant.
	LogDIDDrops uint64

	Size      uint64
	BytesUsed int64
}

// BoundedRecentEntryCache is the production implementation: bounded
// FIFO (entry count AND byte budget), concurrent-safe, O(1) Put/Get.
// ONE mutex around the map, FIFO list, and curBytes accumulator.
type BoundedRecentEntryCache struct {
	maxEntries int
	maxBytes   int64
	logDID     string

	mu       sync.Mutex
	items    map[uint64]*cacheNode
	fifo     *list.List // *list.Element.Value = uint64 (the seq)
	curBytes int64      // Σ node.bytes; updated under mu alongside items

	// Counters: every Add() happens under mu, AND Stats() reads them
	// under mu alongside curBytes + len(items). The snapshot is
	// internally consistent across ALL seven fields — including the
	// two reject-path counters (rejects, logDIDDrops). Put takes mu at
	// its top so even the early-reject paths increment under the lock;
	// the ~25ns mutex cost on those paths is acceptable because rejects
	// signal operator misconfig and are rare by definition. atomic.Uint64
	// is the right type for "increment-only + value-read" — the atomic
	// type isn't load-bearing for cross-goroutine visibility (mu provides
	// happens-before) but matches the semantic shape.
	hits        atomic.Uint64
	misses      atomic.Uint64
	evictions   atomic.Uint64
	rejects     atomic.Uint64
	logDIDDrops atomic.Uint64
}

// cacheNode pairs the cached value with its FIFO list element AND the
// byte size captured at Put time. The captured size is immune to
// subsequent CanonicalBytes mutation — callers MUST NOT mutate, but
// the cache's invariants don't depend on that.
type cacheNode struct {
	ewm   *types.EntryWithMetadata
	bytes int64 // len(ewm.CanonicalBytes) at Put time
	elt   *list.Element
}

// ErrCacheConfig is returned when CacheConfig is invalid.
var ErrCacheConfig = errors.New("store: invalid CacheConfig")

// NewBoundedRecentEntryCache constructs a cache. Both bounds individually
// are optional, but at least one (MaxEntries or MaxBytes) MUST be positive
// — an unbounded cache is forbidden by construction. Negative bounds are
// rejected as malformed.
//
// LogDID, when non-empty, scopes the cache to a single log (foreign-log
// Puts are dropped, counted in Stats().LogDIDDrops). Empty disables the
// check (test fixtures, multi-log adapters that validated upstream).
func NewBoundedRecentEntryCache(cfg CacheConfig) (*BoundedRecentEntryCache, error) {
	if cfg.MaxEntries < 0 || cfg.MaxBytes < 0 {
		return nil, fmt.Errorf("%w: MaxEntries and MaxBytes must be non-negative (got %d, %d)",
			ErrCacheConfig, cfg.MaxEntries, cfg.MaxBytes)
	}
	if cfg.MaxEntries == 0 && cfg.MaxBytes == 0 {
		return nil, fmt.Errorf("%w: at least one of MaxEntries / MaxBytes must be positive (unbounded cache forbidden)",
			ErrCacheConfig)
	}
	// Map sizing hint: MaxEntries if set, else 64 (the map grows
	// naturally beyond — the hint is just to avoid the first few resizes).
	hint := cfg.MaxEntries
	if hint <= 0 {
		hint = 64
	}
	return &BoundedRecentEntryCache{
		maxEntries: cfg.MaxEntries,
		maxBytes:   cfg.MaxBytes,
		logDID:     cfg.LogDID,
		items:      make(map[uint64]*cacheNode, hint),
		fifo:       list.New(),
	}, nil
}

// MustNewBoundedRecentEntryCache is a test-helper variant that panics
// on configuration error. Production callers MUST use NewBoundedRecent-
// EntryCache and surface the error (a misconfigured cache should fail
// startup loudly, not at the first Put). Kept exported because the test
// suite spans multiple packages (store, store_test, sequencer) and the
// alternative would be duplicate copies of the same panic-wrapper in
// every test file.
func MustNewBoundedRecentEntryCache(cfg CacheConfig) *BoundedRecentEntryCache {
	c, err := NewBoundedRecentEntryCache(cfg)
	if err != nil {
		panic(err)
	}
	return c
}

// Capacity returns the entry-count cap (0 disables that bound).
func (c *BoundedRecentEntryCache) Capacity() int { return c.maxEntries }

// BytesCapacity returns the byte cap (0 disables that bound).
func (c *BoundedRecentEntryCache) BytesCapacity() int64 { return c.maxBytes }

// Put implements RecentEntryCache.
//
// The lock is taken at the TOP — before any counter increment, before
// any field read of c.logDID / c.maxBytes — so EVERY counter Add()
// in this method happens under mu. Stats() also reads everything
// under mu, which gives the seven-field snapshot its internal
// consistency claim (no in-flight reject can be invisible to a Stats
// reader). The two early-reject paths (logDID mismatch, oversized
// entry) pay ~25ns of mutex acquisition each — acceptable because
// both signal operator misconfig and are rare by definition. The
// alternative (atomic Adds outside the lock) would force Stats to
// either accept torn snapshots or skip the consistency claim — both
// worse trades than the mutex acquisition here.
//
// Reject-path ordering: nil → logDID mismatch → oversized → normal
// insert. The nil check is pre-lock because it's a pure expression
// with no state read and no counter increment — paying the mutex
// for the no-op case would only add cost.
func (c *BoundedRecentEntryCache) Put(seq uint64, ewm *types.EntryWithMetadata) {
	if ewm == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Foreign-log rejection (defense in depth — upstream caller's
	// LogDID filter is no longer load-bearing for cache correctness).
	if c.logDID != "" && ewm.Position.LogDID != c.logDID {
		c.logDIDDrops.Add(1)
		return
	}

	newBytes := int64(len(ewm.CanonicalBytes))
	// Refuse entries that alone exceed the byte budget. Caching them
	// would either violate MaxBytes (silent invariant break) or trigger
	// pathological eviction — every other entry removed to make room
	// for one we still can't fit. The durable path is correct, so
	// dropping is safe; Rejects surfaces the misconfig.
	if c.maxBytes > 0 && newBytes > c.maxBytes {
		c.rejects.Add(1)
		return
	}

	// Overwrite-in-place: adjust byte tally by delta, preserve FIFO
	// position (re-Put of the same seq is the post-commit replay path).
	// A grow-on-overwrite may push past MaxBytes — evictLocked drops
	// older entries until both bounds are met.
	if node, ok := c.items[seq]; ok {
		c.curBytes += newBytes - node.bytes
		node.ewm = ewm
		node.bytes = newBytes
		c.evictLocked()
		return
	}

	elt := c.fifo.PushBack(seq)
	c.items[seq] = &cacheNode{ewm: ewm, bytes: newBytes, elt: elt}
	c.curBytes += newBytes
	c.evictLocked()
}

// evictLocked drops oldest entries until BOTH configured bounds are
// satisfied. MUST be called with c.mu held.
//
// Termination: every iteration removes one map entry. The loop exits
// when both bounds are met OR the FIFO is empty (impossible in
// practice: a Put-only-just-evicted-everything-else state means the
// newly-Put entry alone exceeds MaxBytes, but Put's pre-lock guard
// already refused that case — so the FIFO is never emptied here).
func (c *BoundedRecentEntryCache) evictLocked() {
	for c.overBoundsLocked() {
		front := c.fifo.Front()
		if front == nil {
			return
		}
		seq := front.Value.(uint64)
		node := c.items[seq]
		c.fifo.Remove(front)
		delete(c.items, seq)
		c.curBytes -= node.bytes
		c.evictions.Add(1)
	}
}

// overBoundsLocked reports whether either bound is currently violated.
// MUST be called with c.mu held.
func (c *BoundedRecentEntryCache) overBoundsLocked() bool {
	if c.maxEntries > 0 && len(c.items) > c.maxEntries {
		return true
	}
	if c.maxBytes > 0 && c.curBytes > c.maxBytes {
		return true
	}
	return false
}

// Get implements RecentEntryCache.
//
// node.ewm AND the hit/miss counter increment are both performed UNDER
// the lock. This serves two correctness needs:
//
//  1. node.ewm cannot race with a concurrent overwrite-in-place Put on
//     the same seq. A bare unlocked read would be a Go-memory-model
//     data race; a torn pointer would silently serve corrupt cache hits.
//
//  2. Stats() reads ALL six fields under the same lock. Incrementing
//     hits/misses outside the lock would leave a window where Size
//     advanced but the counter hadn't — an internally-inconsistent
//     snapshot.
//
// The lock cost is essentially zero: Get already holds the lock for
// the map lookup.
func (c *BoundedRecentEntryCache) Get(seq uint64) (*types.EntryWithMetadata, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	node, ok := c.items[seq]
	if !ok {
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return node.ewm, true
}

// Len implements RecentEntryCache.
func (c *BoundedRecentEntryCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Stats implements RecentEntryCache.
//
// All seven values are read UNDER the lock. Every WRITE to those
// values also happens under the same lock (Put/evictLocked for Size +
// BytesUsed + Evictions + Rejects + LogDIDDrops; Get for Hits +
// Misses). The snapshot is internally consistent across the whole
// struct — not the partially-consistent reading the original
// implementation produced (where Hits.Add ran AFTER the Get released
// the lock).
func (c *BoundedRecentEntryCache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{
		Hits:        c.hits.Load(),
		Misses:      c.misses.Load(),
		Evictions:   c.evictions.Load(),
		Rejects:     c.rejects.Load(),
		LogDIDDrops: c.logDIDDrops.Load(),
		Size:        uint64(len(c.items)),
		BytesUsed:   c.curBytes,
	}
}
