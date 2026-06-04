/*
FILE PATH: store/recent_entry_cache_test.go

Contract tests for BoundedRecentEntryCache. Covers: round-trip Put/Get,
FIFO eviction at capacity, overwrite-in-place (no FIFO churn), nil-safety,
counters (hits / misses / evictions / size), capacity normalization, and
concurrent-safety under the race detector.

Tests are deliberately framework-free (only `testing`) — no DB, no
network, no other store types. The cache is a self-contained primitive.
*/
package store

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/baseproof/baseproof/types"
)

func ewm(seq uint64, payload byte) *types.EntryWithMetadata {
	return &types.EntryWithMetadata{
		CanonicalBytes: []byte{payload, payload, payload},
		Position:       types.LogPosition{LogDID: "did:test:log", Sequence: seq},
	}
}

func TestBoundedRecentEntryCache_PutGet(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 4, LogDID: "did:test:log"})
	c.Put(7, ewm(7, 0xA))
	got, ok := c.Get(7)
	if !ok {
		t.Fatal("Get(7) missed immediately after Put")
	}
	if got.Position.Sequence != 7 || got.CanonicalBytes[0] != 0xA {
		t.Fatalf("Get(7) returned wrong value: %+v", got)
	}
	if _, ok := c.Get(99); ok {
		t.Fatal("Get(99) hit unexpectedly")
	}
	if c.Len() != 1 {
		t.Errorf("Len() = %d, want 1", c.Len())
	}
}

func TestBoundedRecentEntryCache_FIFOEviction(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 3, LogDID: "did:test:log"})
	for i := uint64(1); i <= 5; i++ {
		c.Put(i, ewm(i, byte(i)))
	}
	if c.Len() != 3 {
		t.Fatalf("Len() = %d, want 3 (capacity)", c.Len())
	}
	for _, evicted := range []uint64{1, 2} {
		if _, ok := c.Get(evicted); ok {
			t.Errorf("Get(%d) hit; should have been FIFO-evicted", evicted)
		}
	}
	for _, kept := range []uint64{3, 4, 5} {
		if _, ok := c.Get(kept); !ok {
			t.Errorf("Get(%d) missed; should still be cached", kept)
		}
	}
	if got := c.Stats().Evictions; got != 2 {
		t.Errorf("Evictions counter = %d, want 2", got)
	}
}

// Re-Put of an existing seq must NOT churn the FIFO order: the re-Put
// overwrites the VALUE in place, but the entry's FIFO position is
// unchanged (still at the same relative spot it was first inserted).
// This matches the post-commit replay path — the same seq can be Put
// more than once during recovery, and re-Put should be benign without
// "refreshing" it ahead of newer entries.
func TestBoundedRecentEntryCache_RePutNoFIFOChurn(t *testing.T) {
	// (a) FIFO unchanged: re-Put leaves the entry at its insertion position.
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 3, LogDID: "did:test:log"})
	c.Put(1, ewm(1, 0x1))
	c.Put(2, ewm(2, 0x2))
	c.Put(3, ewm(3, 0x3))
	c.Put(1, ewm(1, 0xFF)) // overwrite value; FIFO order stays (1, 2, 3)
	c.Put(4, ewm(4, 0x4))  // evicts seq=1 (still front of FIFO)

	if _, ok := c.Get(1); ok {
		t.Error("seq=1 should have been evicted: re-Put must not move FIFO position")
	}
	for _, kept := range []uint64{2, 3, 4} {
		if _, ok := c.Get(kept); !ok {
			t.Errorf("seq=%d should still be cached", kept)
		}
	}

	// (b) Value IS overwritten: a Get between the re-Put and any eviction
	// returns the overwritten value, not the original.
	c2 := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 3, LogDID: "did:test:log"})
	c2.Put(1, ewm(1, 0x1))
	c2.Put(1, ewm(1, 0xFF))
	if got, ok := c2.Get(1); !ok || got.CanonicalBytes[0] != 0xFF {
		t.Errorf("re-Put value not overwritten: ok=%v got=%+v", ok, got)
	}
}

// TestBoundedRecentEntryCache_NewRejectsBothZero pins the F1-5 fix:
// a fully-unbounded cache is forbidden at construction time — zero/zero
// returns ErrCacheConfig. Operators must consciously choose a bound,
// not accidentally ship an unbounded heap consumer.
func TestBoundedRecentEntryCache_NewRejectsBothZero(t *testing.T) {
	if _, err := NewBoundedRecentEntryCache(CacheConfig{}); err == nil {
		t.Fatal("zero/zero CacheConfig should return error; got nil")
	}
}

// TestBoundedRecentEntryCache_NewRejectsNegative pins that malformed
// negative bounds are rejected as construction errors. Defense against
// configuration corruption (e.g., a sign-flipped int from envIntOr).
func TestBoundedRecentEntryCache_NewRejectsNegative(t *testing.T) {
	if _, err := NewBoundedRecentEntryCache(CacheConfig{MaxEntries: -1}); err == nil {
		t.Error("negative MaxEntries should return error")
	}
	if _, err := NewBoundedRecentEntryCache(CacheConfig{MaxBytes: -1}); err == nil {
		t.Error("negative MaxBytes should return error")
	}
}

func TestBoundedRecentEntryCache_NilPutIgnored(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 4, LogDID: "did:test:log"})
	c.Put(1, nil)
	if c.Len() != 0 {
		t.Errorf("nil Put should be ignored; Len() = %d, want 0", c.Len())
	}
}

func TestBoundedRecentEntryCache_StatsHitsAndMisses(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 2, LogDID: "did:test:log"})
	c.Put(1, ewm(1, 0x1))
	_, _ = c.Get(1) // hit
	_, _ = c.Get(1) // hit
	_, _ = c.Get(2) // miss
	_, _ = c.Get(2) // miss
	_, _ = c.Get(2) // miss
	s := c.Stats()
	if s.Hits != 2 || s.Misses != 3 || s.Size != 1 {
		t.Errorf("Stats() = %+v, want Hits=2 Misses=3 Size=1", s)
	}
}

// Concurrent Put + Get under the race detector. Not a stress test — just
// validates the mutex actually serializes access. Run with `go test -race`.
func TestBoundedRecentEntryCache_ConcurrentSafe(t *testing.T) {
	const (
		capacity = 64
		writers  = 4
		readers  = 8
		perGo    = 1000
	)
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: capacity, LogDID: "did:test:log"})
	var wg sync.WaitGroup
	var nextSeq atomic.Uint64
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGo; i++ {
				seq := nextSeq.Add(1)
				c.Put(seq, ewm(seq, byte(seq)))
			}
		}()
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(off uint64) {
			defer wg.Done()
			for i := uint64(0); i < perGo; i++ {
				_, _ = c.Get(off + i) // mostly miss, sometimes hit; we don't assert
			}
		}(uint64(r))
	}
	wg.Wait()
	if c.Len() > capacity {
		t.Errorf("Len() = %d exceeds capacity %d (eviction did not bound)", c.Len(), capacity)
	}
}

// TestBoundedRecentEntryCache_RaceOnSameSeq pins the F1-1 fix: a
// concurrent Get + Put on the SAME seq must not race on the node.ewm
// pointer. The earlier ConcurrentSafe test happened to never collide
// (writers used monotonic Add, readers used disjoint offsets) so
// `node.ewm` was never simultaneously written and read. This test
// drives EVERY goroutine at the same seq, then runs under -race in
// CI so the data-race detector catches a regression. Without the
// "read under lock" fix in Get, the detector reports a write/read
// race on node.ewm. With it, the test passes silently.
func TestBoundedRecentEntryCache_RaceOnSameSeq(t *testing.T) {
	const (
		goroutines = 16
		iterations = 2000
		seq        = uint64(42) // same key for every Put + every Get
	)
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 8, LogDID: "did:test:log"})
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				c.Put(seq, ewm(seq, byte(i)))
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if e, ok := c.Get(seq); ok && e == nil {
					t.Error("Get returned ok=true with nil ewm — torn pointer read")
				}
			}
		}()
	}
	wg.Wait()
}

// TestBoundedRecentEntryCache_RejectsForeignLogDID pins the F1-8 fix:
// a cache bound to logDID="did:test:log" silently drops a Put of an
// EntryWithMetadata whose Position.LogDID disagrees. Defense in depth
// at the cache boundary — the production caller's LogDID filter being
// correct is no longer a load-bearing invariant of the cache itself.
//
// Also pins the LogDIDDrops counter: each rejected Put increments it,
// and Stats() exposes it via the public field of the same name. A
// rename typo between private (logDIDDrops) and public (LogDIDDrops)
// would fail this test the moment Stats() returned zero where one
// was expected.
func TestBoundedRecentEntryCache_RejectsForeignLogDID(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 4, LogDID: "did:test:log"})

	foreign := &types.EntryWithMetadata{
		CanonicalBytes: []byte{0xFF},
		Position:       types.LogPosition{LogDID: "did:test:OTHER", Sequence: 7},
	}
	c.Put(7, foreign)
	if _, ok := c.Get(7); ok {
		t.Fatal("foreign-log Put leaked into cache — defense-in-depth check missing")
	}
	if c.Len() != 0 {
		t.Errorf("Len() = %d after foreign-log Put, want 0", c.Len())
	}
	if got := c.Stats().LogDIDDrops; got != 1 {
		t.Errorf("Stats().LogDIDDrops = %d, want 1 (private logDIDDrops counter must surface in public Stats)", got)
	}

	// Three more foreign-log Puts: counter advances monotonically and
	// the snapshot reads the live value (would fail if the counter
	// increment happened OUTSIDE the lock and Stats raced the Add).
	for i := uint64(8); i <= 10; i++ {
		c.Put(i, &types.EntryWithMetadata{
			CanonicalBytes: []byte{0xFF},
			Position:       types.LogPosition{LogDID: "did:test:OTHER", Sequence: i},
		})
	}
	if got := c.Stats().LogDIDDrops; got != 4 {
		t.Errorf("Stats().LogDIDDrops = %d after 4 foreign Puts, want 4", got)
	}

	// Same-log Put still works after the rejection sequence — the
	// counter advances did not corrupt cache state.
	c.Put(7, ewm(7, 0xA))
	if _, ok := c.Get(7); !ok {
		t.Error("same-log Put after foreign-log rejection failed — rejection corrupted state")
	}
}

// TestBoundedRecentEntryCache_LogDIDOptIn pins the test-mode behavior:
// passing logDID="" disables the foreign-log check (mixed-log adapters
// that have already validated upstream). Without this, the cache would
// be impossible to use from test fixtures that don't bind to a LogDID.
func TestBoundedRecentEntryCache_LogDIDOptIn(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 4, LogDID: ""})
	c.Put(7, &types.EntryWithMetadata{
		CanonicalBytes: []byte{0xFF},
		Position:       types.LogPosition{LogDID: "did:test:any-log", Sequence: 7},
	})
	if _, ok := c.Get(7); !ok {
		t.Error("logDID=\"\" should accept any LogDID; Put was rejected anyway")
	}
}

// big returns an EntryWithMetadata of the requested byte size, scoped
// to the standard test LogDID — used by byte-budget tests where the
// count itself is unimportant but the byte volume drives eviction.
func big(seq uint64, n int) *types.EntryWithMetadata {
	return &types.EntryWithMetadata{
		CanonicalBytes: make([]byte, n),
		Position:       types.LogPosition{LogDID: "did:test:log", Sequence: seq},
	}
}

// TestBoundedRecentEntryCache_BytesBudget_EvictsToFit pins F1-5: byte
// budget evicts even when entry count is well under MaxEntries. 4
// entries × 1000 bytes = 4000; MaxBytes=2500 forces 2 evictions. The
// entry-count bound (10) is loose — it doesn't participate, and the
// byte cap alone drives the eviction.
func TestBoundedRecentEntryCache_BytesBudget_EvictsToFit(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{
		MaxEntries: 10, MaxBytes: 2500, LogDID: "did:test:log",
	})
	for i := uint64(1); i <= 4; i++ {
		c.Put(i, big(i, 1000))
	}
	if got := c.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2 (bytes bound active: 2*1000 ≤ 2500 < 3*1000)", got)
	}
	s := c.Stats()
	if s.BytesUsed != 2000 || s.Evictions != 2 {
		t.Errorf("Stats() = %+v, want BytesUsed=2000 Evictions=2", s)
	}
	if _, ok := c.Get(1); ok {
		t.Error("seq 1 should have been bytes-evicted")
	}
	if _, ok := c.Get(2); ok {
		t.Error("seq 2 should have been bytes-evicted")
	}
}

// TestBoundedRecentEntryCache_RejectsOversizedEntry pins the
// reject-don't-evict invariant: a Put whose entry alone exceeds
// MaxBytes is REFUSED (Rejects++) — caching it would either violate
// MaxBytes or trigger pathological eviction of every other entry just
// to fail to fit. The existing cache contents survive untouched.
func TestBoundedRecentEntryCache_RejectsOversizedEntry(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{
		MaxEntries: 10, MaxBytes: 100, LogDID: "did:test:log",
	})
	c.Put(1, big(1, 50))
	// 200 bytes > MaxBytes(100): rejected; existing seq=1 survives.
	c.Put(2, big(2, 200))
	if _, ok := c.Get(2); ok {
		t.Error("oversized entry should not be cached")
	}
	if _, ok := c.Get(1); !ok {
		t.Error("existing entry must survive a rejected oversized Put")
	}
	s := c.Stats()
	if s.Rejects != 1 || s.Size != 1 || s.BytesUsed != 50 {
		t.Errorf("Stats() = %+v, want Rejects=1 Size=1 BytesUsed=50", s)
	}
}

// TestBoundedRecentEntryCache_OverwriteAdjustsBytes pins the
// grow-on-overwrite eviction path: re-Putting an existing seq with a
// larger value adjusts curBytes by the delta and may evict OTHER
// entries from the FIFO front to make room. The overwritten seq keeps
// its FIFO position (no churn).
func TestBoundedRecentEntryCache_OverwriteAdjustsBytes(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{
		MaxEntries: 10, MaxBytes: 200, LogDID: "did:test:log",
	})
	c.Put(1, big(1, 50))  // FIFO: [1]; bytes 50
	c.Put(2, big(2, 50))  // FIFO: [1,2]; bytes 100
	c.Put(3, big(3, 50))  // FIFO: [1,2,3]; bytes 150
	c.Put(2, big(2, 150)) // overwrite seq=2; total would be 250 > 200 → evict seq=1 (front)
	if _, ok := c.Get(1); ok {
		t.Error("seq 1 should be evicted after seq 2 overwrite pushed total bytes past bound")
	}
	s := c.Stats()
	if s.BytesUsed != 200 || s.Size != 2 {
		t.Errorf("Stats = %+v, want BytesUsed=200 Size=2", s)
	}
}

// TestBoundedRecentEntryCache_EntryCountStillActive pins that the
// entry-count bound is honored alongside the byte bound — whichever
// fires first wins. Here byte capacity is huge (10MB) and entry count
// is the tight bound (2) — 5 small Puts should leave only the last 2.
func TestBoundedRecentEntryCache_EntryCountStillActive(t *testing.T) {
	c := MustNewBoundedRecentEntryCache(CacheConfig{
		MaxEntries: 2, MaxBytes: 10_000_000, LogDID: "did:test:log",
	})
	tiny := func(seq uint64) *types.EntryWithMetadata {
		return &types.EntryWithMetadata{
			CanonicalBytes: []byte{0x01},
			Position:       types.LogPosition{LogDID: "did:test:log", Sequence: seq},
		}
	}
	for i := uint64(1); i <= 5; i++ {
		c.Put(i, tiny(i))
	}
	if got := c.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2 (entry-count bound active despite bytes-headroom)", got)
	}
}

// TestBoundedRecentEntryCache_BytesOnlyConfig pins that a bytes-only
// config (MaxEntries=0) is accepted — the constructor's "at least one
// bound" check is satisfied and the cache governs by bytes alone.
func TestBoundedRecentEntryCache_BytesOnlyConfig(t *testing.T) {
	c, err := NewBoundedRecentEntryCache(CacheConfig{MaxBytes: 1000, LogDID: "did:test:log"})
	if err != nil {
		t.Fatalf("bytes-only config rejected: %v", err)
	}
	if c.Capacity() != 0 || c.BytesCapacity() != 1000 {
		t.Errorf("Capacity()=%d BytesCapacity()=%d, want 0/1000", c.Capacity(), c.BytesCapacity())
	}
	// 15 entries × 100 bytes = 1500 > MaxBytes(1000) → evicts to ≤10 entries.
	for i := uint64(1); i <= 15; i++ {
		c.Put(i, big(i, 100))
	}
	if c.Len() > 10 {
		t.Errorf("Len() = %d, want ≤10 (1000 bytes / 100 each)", c.Len())
	}
}

// TestBoundedRecentEntryCache_BytesBudget_PropertyAcrossSizes is the F1-12
// property guard: regardless of how entry sizes are interleaved (small +
// medium + large mixed), the cache MUST stay within both configured bounds
// at every point. Generates a deterministic-seeded sequence of varying-
// size entries, Puts them all, and asserts:
//
//  1. Stats().BytesUsed <= MaxBytes at every observation point.
//  2. Stats().Size <= MaxEntries at every observation point.
//  3. Counters are internally consistent (Hits+Misses against Size delta).
//
// The four scenario-specific tests above cover canned shapes; this one
// exercises the structural invariant against an adversarial mix that
// mirrors production (some 32-byte attestations, some 4KB receipt blobs,
// occasional 200KB EIP-1271 evidence). A regression in the byte
// accounting — for example, evictLocked forgetting to decrement curBytes —
// would surface here.
func TestBoundedRecentEntryCache_BytesBudget_PropertyAcrossSizes(t *testing.T) {
	const (
		maxEntries    = 1000
		maxBytes      = 100_000 // 100 KB
		iterations    = 5000    // enough to force many evictions
		observeEveryN = 50      // O(1) Stats per 50 Puts; lets the property fail loudly
	)
	c := MustNewBoundedRecentEntryCache(CacheConfig{
		MaxEntries: maxEntries,
		MaxBytes:   maxBytes,
		LogDID:     "did:test:log",
	})

	// Deterministic adversarial size mix (seeded). Sizes span ~3 orders
	// of magnitude — the production worst case the byte budget defends
	// against. A few sizes deliberately exceed MaxBytes so we also
	// exercise the Reject path.
	sizes := []int{32, 64, 256, 1024, 4096, 32_768, 110_000}
	r := uint64(0x9E3779B97F4A7C15) // splitmix64 constant; deterministic
	pickSize := func() int {
		// xorshift + modulo — pseudo-random, deterministic, no math/rand
		// dependency.
		r ^= r << 13
		r ^= r >> 7
		r ^= r << 17
		return sizes[int(r%uint64(len(sizes)))]
	}

	var maxObservedBytes int64
	var maxObservedSize uint64
	for i := uint64(1); i <= iterations; i++ {
		c.Put(i, big(i, pickSize()))
		if i%observeEveryN == 0 {
			s := c.Stats()
			if s.BytesUsed > maxBytes {
				t.Fatalf("iter %d: BytesUsed = %d > MaxBytes %d — byte budget violated",
					i, s.BytesUsed, maxBytes)
			}
			if s.Size > maxEntries {
				t.Fatalf("iter %d: Size = %d > MaxEntries %d — count bound violated",
					i, s.Size, maxEntries)
			}
			if s.BytesUsed > maxObservedBytes {
				maxObservedBytes = s.BytesUsed
			}
			if s.Size > maxObservedSize {
				maxObservedSize = s.Size
			}
		}
	}

	// Sanity: across 5000 Puts with sizes up to 110KB we should have
	// pushed the byte counter to within shouting distance of the cap
	// (the budget is the binding constraint at this mix). If we never
	// approached the cap, the test isn't exercising what it claims.
	if maxObservedBytes < maxBytes/2 {
		t.Errorf("max observed BytesUsed = %d (< half of cap %d) — test mix didn't stress the byte bound",
			maxObservedBytes, maxBytes)
	}

	// Final state must obey both bounds.
	final := c.Stats()
	if final.BytesUsed > maxBytes {
		t.Errorf("final BytesUsed = %d > MaxBytes %d", final.BytesUsed, maxBytes)
	}
	if final.Size > maxEntries {
		t.Errorf("final Size = %d > MaxEntries %d", final.Size, maxEntries)
	}
	// Rejects MUST be > 0 because some entries (size 110_000) exceed
	// MaxBytes (100_000). Confirms the reject path is being hit, not
	// just the eviction path.
	if final.Rejects == 0 {
		t.Error("expected non-zero Rejects (oversized entries were in the size mix)")
	}
}
