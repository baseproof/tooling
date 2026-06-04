/*
FILE PATH: libs/cache/cache.go

DESCRIPTION:

	Minimal TTL cache used by JN's read-time policy enforcement to
	absorb repeat lookups against the ledger's read-side query
	endpoints (cosignature_of, delegate_did). Per the v1.5.1 design
	matrix, "JN owns its own projection + TTL — NOT ledger code":
	the ledger is the authoritative source; consumers pick caching
	policy per workload.

	# SHAPE

	One generic TTL map keyed by string, holding any value type via
	a per-entry expiry. Lazy eviction on access — no goroutine, no
	mutex contention from a sweeper.

	Two workloads share this primitive:

	  * Historical verification (long-running queries against
	    finalized data): TTL on the order of minutes is fine —
	    the underlying ledger entries are immutable.
	  * Real-time gate (admission-time decisions where staleness
	    matters): seconds-level TTL keeps the cache useful for
	    burst traffic without serving stale view of a freshly-
	    delegated authority.

	The cache does NOT subscribe to ledger invalidation events
	(the ledger's gossip layer is its own concern); freshness is
	bounded by TTL alone.

	# NOT A PRODUCTION-GRADE LRU

	No size cap, no LRU eviction. Sized for JN's expected key
	space (active delegations per network: low-thousands; recent
	primary entries with cosignatures: low-tens-per-minute). Add
	a size cap when measured working-set demands it.

KEY DEPENDENCIES:
  - stdlib sync, time. No SDK or framework couplings.
*/
package cache

import (
	"sync"
	"time"
)

// Cache is a goroutine-safe TTL cache. Zero-value is unusable; call
// New.
type Cache[V any] struct {
	mu    sync.RWMutex
	items map[string]entry[V]

	// now lets tests inject a deterministic clock. Production
	// leaves this nil and falls through to time.Now.
	now func() time.Time
}

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

// New constructs an empty cache.
func New[V any]() *Cache[V] {
	return &Cache[V]{items: make(map[string]entry[V])}
}

// NewWithClock is the test-only constructor that injects a clock.
// Production callers use New.
func NewWithClock[V any](now func() time.Time) *Cache[V] {
	return &Cache[V]{items: make(map[string]entry[V]), now: now}
}

// Get returns the value for key when present AND not expired. Lazy
// eviction: a stale entry is deleted on miss so cache size tracks
// the active key set over time. The second return is true ONLY when
// the value is fresh; an expired entry returns (zero, false).
func (c *Cache[V]) Get(key string) (V, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()
	var zero V
	if !ok {
		return zero, false
	}
	if c.clock().After(e.expiresAt) {
		// Stale — evict on read.
		c.mu.Lock()
		// Re-check under write lock: another goroutine may have
		// refreshed the entry between our RUnlock and Lock.
		if cur, stillOK := c.items[key]; stillOK && !c.clock().After(cur.expiresAt) {
			c.mu.Unlock()
			return cur.value, true
		}
		delete(c.items, key)
		c.mu.Unlock()
		return zero, false
	}
	return e.value, true
}

// Set stores value under key with the supplied TTL. TTL <= 0 is a
// no-op (the call returns without storing); callers that want
// "cache forever" must compute a finite TTL.
func (c *Cache[V]) Set(key string, value V, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.items[key] = entry[V]{value: value, expiresAt: c.clock().Add(ttl)}
	c.mu.Unlock()
}

// Delete removes a key. Useful for explicit invalidation when the
// caller has external knowledge that the cached value is stale
// (e.g., a delegation revocation event).
func (c *Cache[V]) Delete(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}

// Len returns the number of items currently stored, including ones
// that are expired but not yet evicted. Diagnostic / test use only.
func (c *Cache[V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *Cache[V]) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}
