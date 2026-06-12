// FILE PATH: libs/witnessrotation/journal_memory_test.go
//
// MemoryRotationJournal contract suite — the same observable contract the
// durable journal locks (the cross-implementation parity test lives beside
// the PG implementation in journalpg). Plus the seams the in-memory journal
// exists for: both reconciler interfaces, and race-freedom under concurrent
// reconciler writes + resolver reads.
package witnessrotation

import (
	"context"
	"sync"
	"testing"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/libs/monitoring"
	"github.com/baseproof/tooling/libs/witnessrotation/internal/rottest"
)

// Static conformance: BOTH reconciler seams — the gossip reconciler's
// journal hook and the scan reconciler's read+append seam. (The monitoring
// assert lives here, not in production code, so the witnessrotation package
// itself stays free of a monitoring import.)
var (
	_ monitoring.RotationJournal = (*MemoryRotationJournal)(nil)
	_ RotationJournal            = (*MemoryRotationJournal)(nil)
)

const memLogDID = "did:web:source-log.memjournal.test"

func memJournalFixture(t *testing.T) (*MemoryRotationJournal, []types.WitnessRotationRecord) {
	t.Helper()
	netID := rottest.NetID()
	s0, s1, s2 := newEraKit(t, 3, 2, netID), newEraKit(t, 3, 2, netID), newEraKit(t, 3, 2, netID)
	records := []types.WitnessRotationRecord{
		{Rotation: witnesstest.MintRotation(t, netID, s0.ws, s1.ws, 2), EffectivePos: types.LogPosition{LogDID: memLogDID, Sequence: 100}},
		{Rotation: witnesstest.MintRotation(t, netID, s1.ws, s2.ws, 2), EffectivePos: types.LogPosition{LogDID: memLogDID, Sequence: 200}},
	}
	return NewMemoryRotationJournal(), records
}

func TestMemoryJournal_RecordAndReadBack_SortedAndIdempotent(t *testing.T) {
	j, records := memJournalFixture(t)
	ctx := context.Background()

	// Deliberately out of order — RecordsFor must return ascending.
	if err := j.RecordRotation(ctx, records[1]); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordRotation(ctx, records[0]); err != nil {
		t.Fatal(err)
	}
	// Idempotent re-delivery (gossip is at-least-once) is a harmless no-op.
	if err := j.RecordRotation(ctx, records[0]); err != nil {
		t.Fatalf("idempotent RecordRotation: %v", err)
	}

	got, err := j.RecordsFor(ctx, memLogDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].EffectivePos.Sequence != 100 || got[1].EffectivePos.Sequence != 200 {
		t.Fatalf("RecordsFor must be ascending and deduped: %+v", got)
	}
	// The round-trip is byte-exact through the SDK codec: the read-back
	// rotation re-encodes to the same canonical payload.
	wantPayload, err := witness.EncodeWitnessRotationPayload(records[0].Rotation)
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, err := witness.EncodeWitnessRotationPayload(got[0].Rotation)
	if err != nil {
		t.Fatal(err)
	}
	if string(wantPayload) != string(gotPayload) {
		t.Fatal("read-back rotation must round-trip byte-exactly through the SDK codec")
	}

	// An unknown log has no chain — empty, not an error (genesis-only log).
	empty, err := j.RecordsFor(ctx, "did:web:never-rotated")
	if err != nil || len(empty) != 0 {
		t.Fatalf("unknown log: records=%d err=%v", len(empty), err)
	}
}

func TestMemoryJournal_NullPositionRefused(t *testing.T) {
	j, records := memJournalFixture(t)
	r := records[0]
	r.EffectivePos = types.LogPosition{}
	if err := j.RecordRotation(context.Background(), r); err == nil {
		t.Fatal("a null EffectivePos must be refused — reconstruction requires a proven position")
	}
}

func TestMemoryJournal_MalformedRotationRefusedAtRecord(t *testing.T) {
	j, _ := memJournalFixture(t)
	// A structurally-invalid rotation (zero value) must be refused by the SDK
	// codec AT RECORD TIME — the journal never stores undecodable rows.
	err := j.RecordRotation(context.Background(), types.WitnessRotationRecord{
		Rotation:     types.WitnessRotation{},
		EffectivePos: types.LogPosition{LogDID: memLogDID, Sequence: 1},
	})
	if err == nil {
		t.Fatal("a rotation the SDK codec refuses must never be journaled")
	}
}

func TestMemoryJournal_LatestRecordedAtAndPurge(t *testing.T) {
	j, records := memJournalFixture(t)
	ctx := context.Background()

	if _, ok, err := j.LatestRecordedAtFor(ctx, memLogDID); ok || err != nil {
		t.Fatalf("empty journal: ok=%v err=%v", ok, err)
	}
	for _, r := range records {
		if err := j.RecordRotation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	at, ok, err := j.LatestRecordedAtFor(ctx, memLogDID)
	if err != nil || !ok || at.IsZero() {
		t.Fatalf("LatestRecordedAtFor: at=%v ok=%v err=%v", at, ok, err)
	}

	// The DoD rebuild cycle: purge → empty → re-ingest → identical chain.
	if err := j.PurgeFor(ctx, memLogDID); err != nil {
		t.Fatal(err)
	}
	if got, _ := j.RecordsFor(ctx, memLogDID); len(got) != 0 {
		t.Fatal("purge must empty the chain")
	}
	for _, r := range records {
		if err := j.RecordRotation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rebuilt, err := j.RecordsFor(ctx, memLogDID)
	if err != nil || len(rebuilt) != 2 {
		t.Fatalf("rebuild after purge: n=%d err=%v", len(rebuilt), err)
	}
}

// TestMemoryJournal_ConcurrentWritersAndReaders: reconciler writes and
// resolver reads race-free (run under -race in CI).
func TestMemoryJournal_ConcurrentWritersAndReaders(t *testing.T) {
	j, records := memJournalFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = j.RecordRotation(ctx, records[i%len(records)])
				_, _ = j.RecordsFor(ctx, memLogDID)
				_, _, _ = j.LatestRecordedAtFor(ctx, memLogDID)
			}
		}()
	}
	wg.Wait()
	got, err := j.RecordsFor(ctx, memLogDID)
	if err != nil || len(got) != 2 {
		t.Fatalf("after the hammer: n=%d err=%v (idempotency must hold under concurrency)", len(got), err)
	}
}

// TestMemoryJournal_DrivesTheResolver: the journal IS a RotationRecordSource —
// the resolver resolves era-correct sets straight off it (the exact JN wiring:
// reconciler writes the journal, the verify path resolves from it).
func TestMemoryJournal_DrivesTheResolver(t *testing.T) {
	netID := rottest.NetID()
	s0, s1 := newEraKit(t, 3, 2, netID), newEraKit(t, 3, 2, netID)
	j := NewMemoryRotationJournal()
	ctx := context.Background()
	if err := j.RecordRotation(ctx, types.WitnessRotationRecord{
		Rotation:     witnesstest.MintRotation(t, netID, s0.ws, s1.ws, 2),
		EffectivePos: types.LogPosition{LogDID: memLogDID, Sequence: 100},
	}); err != nil {
		t.Fatal(err)
	}
	r, err := NewJournalWitnessSetResolver(j, []LogTrustRoot{{LogDID: memLogDID, Genesis: s0.set}})
	if err != nil {
		t.Fatal(err)
	}
	era0, err := r.SetAt(ctx, memLogDID, types.LogPosition{LogDID: memLogDID, Sequence: 50})
	if err != nil || era0.SetHash() != s0.set.SetHash() {
		t.Fatalf("era 0 resolution off the memory journal: %v", err)
	}
	era1, err := r.SetAt(ctx, memLogDID, types.LogPosition{LogDID: memLogDID, Sequence: 150})
	if err != nil || era1.SetHash() == s0.set.SetHash() {
		t.Fatalf("era 1 resolution off the memory journal: %v", err)
	}
}
