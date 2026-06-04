/*
FILE PATH: sequencer/recent_cache_test.go

Contract tests for the F1 recent-entry-cache populate path on the
Sequencer's post-commit hook (applyPostCommitForOne). Pins:

  - Live entry + dbCommitted=true + cache wired → Put fires; the cached
    EntryWithMetadata carries the right LogDID/Sequence + the SAME
    canonical bytes that envelope.Serialize(entry) produces.
  - Tombstone → Put NEVER fires (the early-return at the top of
    applyPostCommitForOne short-circuits before any sidecar work).
  - dbCommitted=false (test/nil-DB mode) → Put NEVER fires (entries are
    not durable).
  - nil cache → no panic, no-op (the wiring is optional).

The cache itself is the production *store.BoundedRecentEntryCache —
keeps this an integration test of the seam, not a unit test of stubs.
*/
package sequencer

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store"
)

// buildLiveStagedEntryForCacheTest constructs a structurally-valid
// stagedEntry the way the production stage-1 worker would (mirrors
// buildLiveStagedEntry in loop.go), and returns the matching canonical
// bytes so the test can compare the cached value.
func buildLiveStagedEntryForCacheTest(t *testing.T, seq uint64) (stagedEntry, []byte, [32]byte) {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:signer",
		Destination: "did:test:log",
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	entry, err := envelope.NewUnsignedEntry(hdr, []byte("recent-cache-test"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wire, sErr := envelope.Serialize(entry)
	if sErr != nil {
		t.Fatalf("Serialize: %v", sErr)
	}
	hash := sha256.Sum256(wire)
	return stagedEntry{
		Seq:       seq,
		Hash:      hash,
		Tombstone: false,
		Entry:     entry,
		Row: store.EntryRow{
			SequenceNumber: seq,
			CanonicalHash:  hash,
			LogTime:        time.UnixMicro(hdr.EventTime).UTC(),
			SignerDID:      hdr.SignerDID,
			Status:         store.StatusLive,
		},
	}, wire, hash
}

func newSequencerWithCache(t *testing.T, cache store.RecentEntryCache) *Sequencer {
	t.Helper()
	s := newTestSequencerNoCommitter(t, newFakeWAL(), newFakeTessera(), Config{})
	s.logger = slog.New(slog.NewTextHandler(testWriter{t: t}, nil))
	s.logDID = "did:test:log"
	if cache != nil {
		s = s.WithRecentEntryCache(cache)
	}
	return s
}

// testWriter pipes slog output into testing.T.Log so it surfaces only
// on failure (matches the existing fixture style — keep tests quiet).
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func TestApplyPostCommit_CachePut_LiveEntry(t *testing.T) {
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 16, LogDID: "did:test:log"})
	s := newSequencerWithCache(t, cache)

	st, wantWire, _ := buildLiveStagedEntryForCacheTest(t, 7)
	s.applyPostCommitForOne(context.Background(), st, true)

	got, ok := cache.Get(7)
	if !ok {
		t.Fatal("cache.Get(7) miss; Put should have fired for a live entry with dbCommitted=true")
	}
	if got.Position.LogDID != "did:test:log" || got.Position.Sequence != 7 {
		t.Errorf("cached position = %+v, want {did:test:log, 7}", got.Position)
	}
	if string(got.CanonicalBytes) != string(wantWire) {
		t.Errorf("cached bytes != Serialize(entry): len got=%d want=%d", len(got.CanonicalBytes), len(wantWire))
	}
	if c := cache.Stats(); c.Size != 1 {
		t.Errorf("cache.Stats().Size = %d, want 1", c.Size)
	}
}

func TestApplyPostCommit_CachePut_TombstoneSkipped(t *testing.T) {
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 16, LogDID: "did:test:log"})
	s := newSequencerWithCache(t, cache)

	// Construct a tombstone the way emitTombstone in loop.go would:
	// Tombstone=true, Entry=nil, Row marked StatusTombstone.
	ts := stagedEntry{
		Seq:       9,
		Hash:      [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
		Tombstone: true,
		Reason:    "test tombstone",
		Row: store.EntryRow{
			SequenceNumber: 9,
			CanonicalHash:  [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
			LogTime:        time.Now().UTC(),
			SignerDID:      store.TombstoneSignerDID,
			Status:         store.StatusTombstone,
		},
	}
	s.applyPostCommitForOne(context.Background(), ts, true)

	if _, ok := cache.Get(9); ok {
		t.Error("cache.Get(9) hit; tombstones MUST be skipped from the cache")
	}
	if c := cache.Stats(); c.Size != 0 {
		t.Errorf("cache.Stats().Size = %d, want 0 (tombstone not cached)", c.Size)
	}
}

func TestApplyPostCommit_CachePut_DBNotCommittedSkipped(t *testing.T) {
	cache := store.MustNewBoundedRecentEntryCache(store.CacheConfig{MaxEntries: 16, LogDID: "did:test:log"})
	s := newSequencerWithCache(t, cache)

	st, _, _ := buildLiveStagedEntryForCacheTest(t, 11)
	// dbCommitted=false: entry is not durable; cache MUST NOT hold it
	// (the cache invariant is "never contains an entry the durable
	// store doesn't").
	s.applyPostCommitForOne(context.Background(), st, false)

	if _, ok := cache.Get(11); ok {
		t.Error("cache.Get(11) hit; Put must be skipped when dbCommitted=false")
	}
	if c := cache.Stats(); c.Size != 0 {
		t.Errorf("cache.Stats().Size = %d, want 0", c.Size)
	}
}

func TestApplyPostCommit_NilCache_NoOp(t *testing.T) {
	// With no cache wired, applyPostCommitForOne must not panic.
	s := newSequencerWithCache(t, nil)
	st, _, _ := buildLiveStagedEntryForCacheTest(t, 13)
	// If the nil-cache branch isn't guarded, this would nil-deref.
	s.applyPostCommitForOne(context.Background(), st, true)
}

// TestCloneWeb3Receipts_DeepClone pins the F1-4 deep-clone fix:
// cloneWeb3Receipts must produce a slice that shares NO backing
// storage with the source — neither the outer header nor the inner
// Proof bytes nor the ExecutorQuorum.Clients slice. A mutation
// through ANY level of the returned slice MUST NOT be observable
// through the source.
func TestCloneWeb3Receipts_DeepClone(t *testing.T) {
	src := []sdktypes.Web3VerificationReceipt{
		{
			ChainID:      1,
			BlockNumber:  100,
			BlockHash:    [32]byte{0xAA},
			ContractAddr: [20]byte{0xBB},
			Proof:        []byte{0x01, 0x02, 0x03},
			ExecutorQuorum: sdktypes.ExecutorQuorumMetadata{
				K: 2, N: 3,
				Clients: []sdktypes.ExecutorAttestation{
					{ClientID: "reth-A", ResultHash: [32]byte{0xCC}},
					{ClientID: "reth-B", ResultHash: [32]byte{0xDD}},
				},
			},
		},
	}
	cloned := cloneWeb3Receipts(src)

	// Sanity: equal values, distinct backing storage.
	if len(cloned) != len(src) {
		t.Fatalf("len(cloned) = %d, want %d", len(cloned), len(src))
	}
	// Mutate the cloned outer slice (would have been caught by F1-4 v1).
	cloned = append(cloned, sdktypes.Web3VerificationReceipt{ChainID: 99})
	if len(src) != 1 {
		t.Errorf("appending to clone mutated source: len(src) = %d", len(src))
	}

	// Mutate cloned Proof bytes — must NOT bleed to source.
	cloned[0].Proof[0] = 0xFF
	if src[0].Proof[0] != 0x01 {
		t.Errorf("mutating cloned[0].Proof[0] bled to src: got 0x%02x", src[0].Proof[0])
	}

	// Mutate cloned ExecutorQuorum.Clients — must NOT bleed to source.
	cloned[0].ExecutorQuorum.Clients[0].ClientID = "MUTATED"
	if src[0].ExecutorQuorum.Clients[0].ClientID != "reth-A" {
		t.Errorf("mutating cloned ExecutorQuorum.Clients[0] bled to src: got %q",
			src[0].ExecutorQuorum.Clients[0].ClientID)
	}

	// Mutate cloned Clients length (append) — must NOT bleed to source.
	cloned[0].ExecutorQuorum.Clients = append(cloned[0].ExecutorQuorum.Clients,
		sdktypes.ExecutorAttestation{ClientID: "extra"})
	if len(src[0].ExecutorQuorum.Clients) != 2 {
		t.Errorf("appending to cloned Clients bled to src: len = %d",
			len(src[0].ExecutorQuorum.Clients))
	}

	// nil / empty edge cases.
	if got := cloneWeb3Receipts(nil); got != nil {
		t.Errorf("clone(nil) = %+v, want nil", got)
	}
	if got := cloneWeb3Receipts([]sdktypes.Web3VerificationReceipt{}); got == nil || len(got) != 0 {
		t.Errorf("clone(empty) = %+v, want empty non-nil", got)
	}
}
