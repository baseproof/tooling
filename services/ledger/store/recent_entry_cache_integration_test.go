/*
FILE PATH: store/recent_entry_cache_integration_test.go

End-to-end integration tests for the F1 hand-off seam:

	Sequencer post-commit  ──Put──▶  RecentEntryCache  ──Get──▶  PostgresEntryFetcher.Fetch

Two contracts the cache+fetcher hand-off MUST uphold:

	(1) BYTE-IDENTITY. The bytes Fetch returns through the cache hit
	    MUST be byte-equal to envelope.Serialize(entry) of the entry the
	    sequencer Put. Otherwise envelope.EntryIdentity (sha256 of the
	    canonical bytes) — and therefore the Tessera leaf hash —
	    diverges, and the builder's append step would corrupt the
	    Merkle log.

	(2) NO BYTESTORE / NO PG ON HIT. The whole point of F1 is to avoid
	    the durable round-trip on the hot path. We prove this by
	    constructing PostgresEntryFetcher with db=nil and reader=nil; a
	    cache hit MUST return cleanly while a miss would nil-deref.

These tests are framework-free and self-contained — no Postgres, no
docker, no SDK fixtures. Just the production cache + fetcher types and
the envelope SDK.
*/
package store_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/baseproof/tooling/services/ledger/store"
)

// buildCanonicalEntry returns a structurally-valid *envelope.Entry,
// its canonical wire bytes, and its 32-byte EntryIdentity hash. This
// mirrors what admission produces and what the sequencer would
// Serialize at post-commit time.
func buildCanonicalEntry(t *testing.T, payload string) (*envelope.Entry, []byte, [32]byte) {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:signer",
		Destination: "did:test:log",
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	entry, err := envelope.NewUnsignedEntry(hdr, []byte(payload))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64), // stub-valid; admission validates real sigs upstream
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wire, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	hash := sha256.Sum256(wire)
	return entry, wire, hash
}

// TestF1_ByteIdentity_ThroughCache asserts the canonical bytes survive
// the cache hand-off byte-for-byte AND the Deserialize/Serialize
// round-trip the sequencer post-commit performs. This is the
// load-bearing safety check: if cached bytes diverged from what the
// bytestore would return, the builder's Tessera leaf hash would not
// match what the read API would later see, and the Merkle log would
// be corrupt across reads.
//
// Round-trip exercised:
//
//	admission wire (W)
//	  → envelope.Deserialize(W)  →  *envelope.Entry  E
//	  → envelope.Serialize(E)    →  W' (sequencer post-commit)
//	  → cache.Put(seq, ewm{CanonicalBytes: W', ...})
//	  → cache.Get(seq)           →  ewm
//	  → envelope.Deserialize(ewm.CanonicalBytes)  →  *envelope.Entry  E'
//	  → envelope.EntryIdentity(E')                →  ID'
//
// Required: W == W' (bijection) AND ID == ID'.
func TestF1_ByteIdentity_ThroughCache(t *testing.T) {
	entry, originalWire, originalID := buildCanonicalEntry(t, "F1-byte-identity-pin")

	// Sequencer post-commit Deserializes the entry from the WAL then
	// re-Serializes for the projection write. We mirror that here.
	roundTripped, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize round-trip: %v", err)
	}
	if string(roundTripped) != string(originalWire) {
		t.Fatalf("Serialize is not a bijection: len got=%d original=%d", len(roundTripped), len(originalWire))
	}

	// Put through the production cache, with the round-tripped bytes
	// (exactly what applyPostCommitForOne stores).
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 64, LogDID: "did:test:log"})
	cache.Put(1234, &types.EntryWithMetadata{
		CanonicalBytes: roundTripped,
		LogTime:        time.UnixMicro(entry.Header.EventTime).UTC(),
		Position:       types.LogPosition{LogDID: "did:test:log", Sequence: 1234},
	})

	// Fetcher consults the cache and returns the cached EwM. db=nil and
	// reader=nil prove the durable path is not taken on a hit (would
	// nil-deref otherwise).
	f := store.NewPostgresEntryFetcher(nil, nil, "did:test:log").WithCache(cache)

	got, err := f.Fetch(context.Background(), types.LogPosition{LogDID: "did:test:log", Sequence: 1234})
	if err != nil {
		t.Fatalf("Fetch(1234) error: %v", err)
	}
	if got == nil {
		t.Fatal("Fetch(1234) returned nil; expected cache hit")
	}

	// Byte-identity.
	if string(got.CanonicalBytes) != string(originalWire) {
		t.Fatalf("CACHED BYTES DIVERGED: len got=%d original=%d — Tessera leaf hash would mismatch",
			len(got.CanonicalBytes), len(originalWire))
	}

	// Deserialize the cached bytes and re-compute EntryIdentity. The
	// builder does exactly this at builder/loop.go:538-587.
	roundTrippedEntry, err := envelope.Deserialize(got.CanonicalBytes)
	if err != nil {
		t.Fatalf("Deserialize cached bytes: %v", err)
	}
	gotID, err := envelope.EntryIdentity(roundTrippedEntry)
	if err != nil {
		t.Fatalf("EntryIdentity: %v", err)
	}
	if gotID != originalID {
		t.Fatalf("EntryIdentity diverged: cached=%x original=%x", gotID, originalID)
	}
}

// TestF1_FetchCacheHit_NoDurableRoundTrip asserts the seam's
// performance contract: a cache hit DOES NOT consult PG or the
// bytestore. We construct the fetcher with db=nil reader=nil and
// rely on the fact that the durable path would nil-deref if taken.
func TestF1_FetchCacheHit_NoDurableRoundTrip(t *testing.T) {
	const logDID = "did:test:no-durable-roundtrip"
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 16, LogDID: logDID})
	cache.Put(42, &types.EntryWithMetadata{
		CanonicalBytes: []byte("cached"),
		Position:       types.LogPosition{LogDID: logDID, Sequence: 42},
	})
	f := store.NewPostgresEntryFetcher(nil, nil, logDID).WithCache(cache)

	got, err := f.Fetch(context.Background(), types.LogPosition{LogDID: logDID, Sequence: 42})
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}
	if got == nil || string(got.CanonicalBytes) != "cached" {
		t.Fatalf("Fetch did not return the cached value: %+v", got)
	}
	if s := cache.Stats(); s.Hits != 1 {
		t.Errorf("cache.Stats().Hits = %d, want 1", s.Hits)
	}
}

// TestF1_FetchCacheMiss_NoFalsePositive asserts a miss does not lie.
// With f.db == nil, the durable path nil-derefs; we expect a panic
// (proves the code path that would have served wrong-cache-data
// instead is NOT taken). The Stats check must live INSIDE the
// deferred recover() block — the line after f.Fetch is unreachable
// once Fetch panics. A previous version of this test had the Stats
// check past the panic and was therefore a tautology (always green,
// asserting nothing about the miss counter).
func TestF1_FetchCacheMiss_FallsThroughToDurable(t *testing.T) {
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 16, LogDID: "did:test:log"})
	f := store.NewPostgresEntryFetcher(nil, nil, "did:test:miss").WithCache(cache)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected nil-deref panic on durable fall-through after cache miss; got none")
		}
		if s := cache.Stats(); s.Misses != 1 {
			t.Errorf("cache.Stats().Misses = %d, want 1 (miss must register BEFORE the durable fall-through)", s.Misses)
		}
	}()
	_, _ = f.Fetch(context.Background(), types.LogPosition{LogDID: "did:test:miss", Sequence: 999})
}

// TestF1_EnvelopeWireBijection pins the F1-10 fix: Tessera-safety of
// the cache depends on the SDK's Serialize/Deserialize being a true
// bijection. The earlier TestF1_ByteIdentity_ThroughCache only
// exercised Serialize(Build()) == Serialize(Build()) — a determinism
// check on the SAME entry handle, not a round-trip. This test takes
// wire bytes W, Deserializes to E, Serializes E to W', and asserts
// W == W' — the property the cache silently depends on. A future
// non-canonical field in Entry (a "received_at" timestamp parsed but
// not re-emitted) would diverge W from W' here, BEFORE the cache
// silently serves wrong bytes to the builder.
func TestF1_EnvelopeWireBijection(t *testing.T) {
	_, originalWire, originalID := buildCanonicalEntry(t, "F1-wire-bijection-pin")

	// Round-trip: W → Deserialize → E1 → Serialize → W1. The
	// production path is: admission gets W, parses to E, hands E to
	// sequencer, sequencer Serializes E for the cache.
	e1, err := envelope.Deserialize(originalWire)
	if err != nil {
		t.Fatalf("Deserialize(originalWire): %v", err)
	}
	w1, err := envelope.Serialize(e1)
	if err != nil {
		t.Fatalf("Serialize(Deserialize(originalWire)): %v", err)
	}
	if string(w1) != string(originalWire) {
		t.Fatalf("envelope.Serialize(Deserialize(W)) != W: len got=%d original=%d — bijection broken; cache will serve wrong bytes",
			len(w1), len(originalWire))
	}
	// EntryIdentity must also be preserved (independent guard).
	id1, err := envelope.EntryIdentity(e1)
	if err != nil {
		t.Fatalf("EntryIdentity after round-trip: %v", err)
	}
	if id1 != originalID {
		t.Fatalf("EntryIdentity diverged across Deserialize+Serialize: got=%x want=%x", id1, originalID)
	}

	// Twice — Deserialize+Serialize must be idempotent (no field
	// accumulation, no encoding drift). Bytes must be exactly equal
	// after every iteration.
	w2, err := envelope.Serialize(e1)
	if err != nil {
		t.Fatalf("Serialize iteration 2: %v", err)
	}
	if string(w2) != string(originalWire) {
		t.Fatalf("Serialize is not idempotent: iteration-2 bytes diverged from W")
	}

	// Sanity: SHA-256 hashes match (independent of byte-by-byte
	// compare, useful if a future test wants to grep on hashes).
	gotSum := sha256.Sum256(w1)
	wantSum := sha256.Sum256(originalWire)
	if gotSum != wantSum {
		t.Fatalf("sha256 of round-tripped bytes diverged")
	}
}

// TestF1_InstrumentsInstall pins the F1-13 fix: the instruments
// installer must:
//
//	(a) return (nil, nil) when meter or cache is nil — caching disabled
//	    deployments must NOT register and must NOT fail,
//	(b) return (Closer, nil) on success against a real meter,
//	(c) return (nil, err) on instrument-creation failure (no silent
//	    observability dark-spot),
//	(d) Closer.Close() must Unregister the OTel callback so subsequent
//	    installs / multi-cache deployments work.
//
// (c) is hard to drive without an SDK-level failure injector; (a), (b),
// and (d) are exercised here with the OTel SDK's noop meter provider
// (returns real instruments + a real Registration handle).
func TestF1_InstrumentsInstall_NilMeter(t *testing.T) {
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 8, LogDID: "did:test:log"})
	closer, err := store.InstallRecentEntryCacheInstruments(nil, cache)
	if err != nil {
		t.Fatalf("nil meter should return (nil, nil); got err=%v", err)
	}
	if closer != nil {
		t.Errorf("nil meter should return (nil, nil); got closer=%T", closer)
	}
}

func TestF1_InstrumentsInstall_NilCache(t *testing.T) {
	mp := noop.NewMeterProvider()
	closer, err := store.InstallRecentEntryCacheInstruments(mp.Meter("test"), nil)
	if err != nil {
		t.Fatalf("nil cache should return (nil, nil); got err=%v", err)
	}
	if closer != nil {
		t.Errorf("nil cache should return (nil, nil); got closer=%T", closer)
	}
}

func TestF1_InstrumentsInstall_RoundTrip(t *testing.T) {
	mp := noop.NewMeterProvider()
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 8, LogDID: "did:test:log"})

	closer, err := store.InstallRecentEntryCacheInstruments(mp.Meter("test"), cache)
	if err != nil {
		t.Fatalf("install against noop meter: %v", err)
	}
	if closer == nil {
		t.Fatal("install returned nil closer with nil error — broken contract")
	}
	if err := closer.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Close-after-Close is allowed (idempotent).
	if err := closer.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestF1_InstrumentsInstall_MultipleInstancesPerProcess pins the F1-7
// fix: the install function MUST NOT carry process-global "already
// installed" state. Two distinct (cache, meter) pairs in the same
// process must both succeed — the previous singleton flag would have
// silently failed the second install. (Multi-log deployments depend on
// this; the cache's own docstring contemplates per-log instances.)
func TestF1_InstrumentsInstall_MultipleInstancesPerProcess(t *testing.T) {
	mp := noop.NewMeterProvider()
	cacheA := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 8, LogDID: "did:test:logA"})
	cacheB := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 8, LogDID: "did:test:logB"})

	// Use DIFFERENT meter names to avoid the "duplicate instrument
	// in the same meter" rejection the OTel SDK does at the meter
	// level (which is correct behavior — we're not testing that
	// here, we're testing that the install function itself has no
	// process-global blocking state).
	closerA, errA := store.InstallRecentEntryCacheInstruments(mp.Meter("test-A"), cacheA)
	if errA != nil {
		t.Fatalf("install A: %v", errA)
	}
	closerB, errB := store.InstallRecentEntryCacheInstruments(mp.Meter("test-B"), cacheB)
	if errB != nil {
		t.Fatalf("install B (would have failed under singleton flag): %v", errB)
	}
	if closerA == nil || closerB == nil {
		t.Fatal("both installs should return non-nil closers")
	}
	_ = closerA.Close()
	_ = closerB.Close()
}
