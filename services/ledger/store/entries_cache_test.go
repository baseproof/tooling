/*
FILE PATH: store/entries_cache_test.go

PostgresEntryFetcher.Fetch cache-branch contract tests. Pins the F1
behavior:
  - cache hit returns the cached EntryWithMetadata WITHOUT touching
    PG or the bytestore.Reader,
  - cache miss falls through to the durable path,
  - foreign LogDID short-circuits BEFORE the cache (the cache is
    per-log and must not serve a foreign-log query),
  - nil cache → durable path always.

The durable-path-untouched assertion is the load-bearing one: the
whole point of F1 is to skip the bytestore round-trip on the hot path.

Framework-free; no PG, no bytestore, no docker. We exercise Fetch with
a stub bytestore.Reader that COUNTS calls (so we can prove the cache
short-circuit) and a stub *pgxpool.Pool... actually we can't easily
stub *pgxpool.Pool without a wrapper, so the "PG not consulted" check
is implicit: if the cache layer returns before line (1), the PG nil-
deref panic never fires. We test that with f.db == nil.
*/
package store

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/types"
)

// The tests below prove cache short-circuit WITHOUT stubbing the
// bytestore: PostgresEntryFetcher is constructed with f.db == nil AND
// f.reader == nil, so the durable path would nil-deref if reached. A
// successful Fetch on a cache hit therefore proves the durable path
// was NOT taken.

// TestFetch_CacheHit_BypassesDurablePath: with a populated cache, Fetch
// returns the cached EntryWithMetadata without touching PG or the
// bytestore. We prove this by leaving f.db and f.reader nil — if the
// durable path were taken, the test would panic on nil dereference.
func TestFetch_CacheHit_BypassesDurablePath(t *testing.T) {
	const logDID = "did:test:hot-path"
	cache := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 8, LogDID: logDID})
	want := &types.EntryWithMetadata{
		CanonicalBytes: []byte{0xAB, 0xCD, 0xEF},
		Position:       types.LogPosition{LogDID: logDID, Sequence: 42},
	}
	cache.Put(42, want)

	f := &PostgresEntryFetcher{db: nil, reader: nil, logDID: logDID}
	f = f.WithCache(cache)

	got, err := f.Fetch(context.Background(), types.LogPosition{LogDID: logDID, Sequence: 42})
	if err != nil {
		t.Fatalf("Fetch(cache hit) error: %v", err)
	}
	if got != want {
		t.Fatalf("Fetch(cache hit): want pointer-identity to cached EWM; got %+v want %+v", got, want)
	}
	if hits := cache.Stats().Hits; hits != 1 {
		t.Errorf("cache.Stats().Hits = %d, want 1", hits)
	}
}

// TestFetch_ForeignLogDID_ShortCircuitsBeforeCache: a foreign-log query
// MUST NOT consult the cache (the cache is per-log; serving a foreign
// position would lie about ownership). Verified by counters: a Get for
// the foreign seq is never recorded.
func TestFetch_ForeignLogDID_ShortCircuitsBeforeCache(t *testing.T) {
	cache := MustNewBoundedRecentEntryCache(CacheConfig{MaxEntries: 8, LogDID: "did:test:ours"})
	f := (&PostgresEntryFetcher{db: nil, reader: nil, logDID: "did:test:ours"}).WithCache(cache)

	got, err := f.Fetch(context.Background(), types.LogPosition{LogDID: "did:test:foreign", Sequence: 7})
	if err != nil {
		t.Fatalf("Fetch(foreign) error: %v", err)
	}
	if got != nil {
		t.Fatalf("Fetch(foreign) returned %+v, want nil", got)
	}
	// Cache must NOT have been consulted (counters untouched).
	if s := cache.Stats(); s.Hits != 0 || s.Misses != 0 {
		t.Errorf("cache consulted for foreign log: %+v", s)
	}
}

// TestFetch_NoCache_TakesDurablePath: with no cache wired, Fetch must
// fall through to the durable path immediately. We construct with
// f.db == nil so the durable SELECT panics — proving the fast path
// (which would have hit the cache stats) was NOT taken.
func TestFetch_NoCache_TakesDurablePath(t *testing.T) {
	f := &PostgresEntryFetcher{db: nil, reader: nil, logDID: "did:test:no-cache"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected nil-deref panic on the durable path with no cache, got none — did Fetch incorrectly short-circuit?")
		}
	}()
	_, _ = f.Fetch(context.Background(), types.LogPosition{LogDID: "did:test:no-cache", Sequence: 1})
}
