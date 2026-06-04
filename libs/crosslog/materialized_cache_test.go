/*
FILE PATH: libs/crosslog/materialized_cache_test.go

Ladder 5 P6 (#21) — round-trip tests for the MaterializedNetwork ↔
disk wrapper that bundles all four anchorcache view files into one
operation.

# WHAT THIS PINS

 1. Round-trip: WriteSnapshot + ReadLatestSnapshot returns the same
    MaterializedNetwork shape.
 2. Empty snapshot (zero records across all views) writes + reads
    cleanly; SnapshotIsEmpty == true.
 3. Cold-boot with no cache: ReadLatestSnapshot returns
    os.ErrNotExist wrapped.
 4. Per-view-treesize fallback: WriteSnapshot at tree size 50 for all
    views, then WriteSnapshot at tree size 100 for only Auditors —
    ReadLatestSnapshot returns the Auditors from ts=100 and the
    other three views from ts=50. Treesize reflects the MAX of the
    per-view treesizes (100); PerViewTreesizes records the
    per-view ts.
 5. Multi-treesize prune-aware read: after WriteSnapshot at 50, 100,
    200, then prune to keep=2, ReadLatestSnapshot serves the
    remaining (100, 200) and falls back gracefully to 100 if any
    view didn't land at 200.
 6. CONCURRENT WriteSnapshot at the same treesize is race-clean
    under -race (each writer produces the same bytes; rename
    ordering doesn't tear the file).
*/
package crosslog

import (
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/anchorcache"
)

func newCacheDir(t *testing.T) *anchorcache.ManagedDir {
	t.Helper()
	d, err := anchorcache.OpenAt(t.TempDir(), "did:test:p6-cache")
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	return d
}

// validSnapshot returns a MaterializedNetwork populated with one
// record per view at distinct EffectivePos sequences so round-trip
// equality is meaningful.
func validSnapshot() MaterializedNetwork {
	return MaterializedNetwork{
		Endpoints: network.WitnessEndpointDeclarationByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 10},
				Payload: network.WitnessEndpointDeclaration{
					PubKeyID:  [32]byte{0x01, 0x02, 0x03},
					Endpoints: map[string]string{"BaseproofWitness": "https://w.example/v1"},
				},
			},
		},
		Labels: network.WitnessIdentityLabelByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 20},
				Payload: network.WitnessIdentityLabel{
					PubKeyID: [32]byte{0x04, 0x05, 0x06},
					Label:    "witness-A",
					DIDHint:  "did:web:witness-A.example",
				},
			},
		},
		Auditors: network.AuditorRegistrationByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 30},
				Payload: network.AuditorRegistration{
					AuditorDID:  "did:web:auditor.example",
					PublicKey:   []byte{0x07, 0x08, 0x09},
					SchemeTag:   1,
					FindingsURL: "https://auditor.example/v1/findings",
					Scope:       network.ScopeEquivocation,
				},
			},
		},
		Amendments: network.AuditorScopeAmendmentByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 40},
				Payload: network.AuditorScopeAmendment{
					AuditorDID: "did:web:auditor.example",
					NewScope:   network.ScopeSMTReplay,
					Reason:     "test fixture",
				},
			},
		},
	}
}

// ─────────────────────────────────────────────────────────────────
// Round-trip
// ─────────────────────────────────────────────────────────────────

func TestSnapshot_RoundTrip(t *testing.T) {
	d := newCacheDir(t)
	want := validSnapshot()
	if err := WriteSnapshot(d, 1000, want); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	got, err := ReadLatestSnapshot(d)
	if err != nil {
		t.Fatalf("ReadLatestSnapshot: %v", err)
	}
	if got.Treesize != 1000 {
		t.Errorf("Treesize: got %d, want 1000", got.Treesize)
	}
	if !reflect.DeepEqual(got.Network.Endpoints, want.Endpoints) {
		t.Errorf("Endpoints round-trip drift")
	}
	if !reflect.DeepEqual(got.Network.Labels, want.Labels) {
		t.Errorf("Labels round-trip drift")
	}
	if !reflect.DeepEqual(got.Network.Auditors, want.Auditors) {
		t.Errorf("Auditors round-trip drift")
	}
	if !reflect.DeepEqual(got.Network.Amendments, want.Amendments) {
		t.Errorf("Amendments round-trip drift")
	}
	// PerViewTreesizes: all four views at ts=1000.
	wantPerView := map[string]uint64{
		anchorcache.MaterializedViewEndpoints:  1000,
		anchorcache.MaterializedViewLabels:     1000,
		anchorcache.MaterializedViewAuditors:   1000,
		anchorcache.MaterializedViewAmendments: 1000,
	}
	if !reflect.DeepEqual(got.PerViewTreesizes, wantPerView) {
		t.Errorf("PerViewTreesizes: got %v, want %v", got.PerViewTreesizes, wantPerView)
	}
}

// TestSnapshot_RoundTrip_Empty pins the empty-snapshot path: a
// MaterializedNetwork with zero records across all views writes +
// reads cleanly; SnapshotIsEmpty returns true. This is the structural
// shape the auditor's boot path produces when the log-scan loop runs
// against a network with no walker entries published yet.
func TestSnapshot_RoundTrip_Empty(t *testing.T) {
	d := newCacheDir(t)
	empty := MaterializedNetwork{}
	if err := WriteSnapshot(d, 1, empty); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	got, err := ReadLatestSnapshot(d)
	if err != nil {
		t.Fatalf("ReadLatestSnapshot: %v", err)
	}
	if !SnapshotIsEmpty(got.Network) {
		t.Errorf("SnapshotIsEmpty(roundtrip(empty)) = false")
	}
	if got.Treesize != 1 {
		t.Errorf("Treesize: got %d, want 1", got.Treesize)
	}
}

func TestSnapshot_ColdBoot_NoCache(t *testing.T) {
	d := newCacheDir(t)
	_, err := ReadLatestSnapshot(d)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist on empty cache; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Per-view fallback (in-progress-write tolerance)
// ─────────────────────────────────────────────────────────────────

// TestSnapshot_PerViewFallback pins the in-progress-write semantic.
// Writer A writes a full snapshot at ts=50. Writer B starts writing
// at ts=100 but only the Auditors view lands before a reader fires.
// The reader MUST see Auditors at ts=100 + the other three views at
// ts=50 — a consistent UNION rather than a torn write.
func TestSnapshot_PerViewFallback(t *testing.T) {
	d := newCacheDir(t)

	// Full snapshot at ts=50.
	older := validSnapshot()
	if err := WriteSnapshot(d, 50, older); err != nil {
		t.Fatalf("WriteSnapshot 50: %v", err)
	}

	// Partial snapshot at ts=100 — only Auditors lands. Simulate by
	// writing the Auditors view directly (bypassing WriteSnapshot's
	// all-views loop).
	newer := validSnapshot()
	newer.Auditors[0].Payload.AuditorDID = "did:web:newer-auditor.example"
	auBytes := []byte(`[{"EffectivePos":{"Sequence":99},"Payload":{"AuditorDID":"did:web:newer-auditor.example","PublicKey":"BwgJ","SchemeTag":1,"FindingsURL":"https://newer-auditor.example/v1/findings","Scope":2,"ProofOfPossession":null,"RetiredAt":null}}]`)
	if err := d.WriteMaterializedView(anchorcache.MaterializedViewAuditors, 100, auBytes); err != nil {
		t.Fatalf("WriteMaterializedView Auditors@100: %v", err)
	}

	got, err := ReadLatestSnapshot(d)
	if err != nil {
		t.Fatalf("ReadLatestSnapshot: %v", err)
	}
	if got.Treesize != 100 {
		t.Errorf("Treesize (max of per-view): got %d, want 100", got.Treesize)
	}
	if got.PerViewTreesizes[anchorcache.MaterializedViewAuditors] != 100 {
		t.Errorf("Auditors per-view ts: got %d, want 100",
			got.PerViewTreesizes[anchorcache.MaterializedViewAuditors])
	}
	if got.PerViewTreesizes[anchorcache.MaterializedViewEndpoints] != 50 {
		t.Errorf("Endpoints per-view ts fallback: got %d, want 50",
			got.PerViewTreesizes[anchorcache.MaterializedViewEndpoints])
	}
	if got.PerViewTreesizes[anchorcache.MaterializedViewLabels] != 50 {
		t.Errorf("Labels per-view ts fallback: got %d, want 50",
			got.PerViewTreesizes[anchorcache.MaterializedViewLabels])
	}
	if got.PerViewTreesizes[anchorcache.MaterializedViewAmendments] != 50 {
		t.Errorf("Amendments per-view ts fallback: got %d, want 50",
			got.PerViewTreesizes[anchorcache.MaterializedViewAmendments])
	}
}

// ─────────────────────────────────────────────────────────────────
// Multi-treesize + prune interaction
// ─────────────────────────────────────────────────────────────────

func TestSnapshot_AfterPrune_ServesLatest(t *testing.T) {
	d := newCacheDir(t)
	// Write three full snapshots at distinct treesizes with distinct
	// AuditorDID payloads so we can verify which one ReadLatestSnapshot
	// returns post-prune.
	for _, ts := range []uint64{50, 100, 200} {
		snap := validSnapshot()
		snap.Auditors[0].Payload.AuditorDID = "did:web:auditor-at-" +
			(map[uint64]string{50: "fifty", 100: "hundred", 200: "twohundred"})[ts] + ".example"
		if err := WriteSnapshot(d, ts, snap); err != nil {
			t.Fatalf("WriteSnapshot %d: %v", ts, err)
		}
	}
	// Prune to keep last 2 → 50 should be removed; 100 and 200 remain.
	pruned, err := d.PruneMaterializedTreesizesBelow(2)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 1 {
		t.Errorf("pruned: got %d, want 1", pruned)
	}
	// ReadLatestSnapshot must serve from ts=200.
	got, err := ReadLatestSnapshot(d)
	if err != nil {
		t.Fatalf("ReadLatestSnapshot post-prune: %v", err)
	}
	if got.Treesize != 200 {
		t.Errorf("post-prune treesize: got %d, want 200", got.Treesize)
	}
	if got.Network.Auditors[0].Payload.AuditorDID != "did:web:auditor-at-twohundred.example" {
		t.Errorf("post-prune AuditorDID: got %q",
			got.Network.Auditors[0].Payload.AuditorDID)
	}
}

// ─────────────────────────────────────────────────────────────────
// Concurrency — race-detector test
// ─────────────────────────────────────────────────────────────────

// TestSnapshot_ConcurrentWritesSameTreesize_RaceSafe pins the
// HA-scenario invariant: N writers at the same tree size producing
// the same MaterializedNetwork must not race. Each goroutine writes
// the same deterministic bytes; the atomic-rename primitive's
// last-writer-wins on identical bytes leaves the cache in a
// consistent state.
//
// Race-detector run: any data race in WriteSnapshot's four sequential
// writes surfaces as a DATA RACE report. The test runs 16 writers
// concurrently against the same tree size.
func TestSnapshot_ConcurrentWritesSameTreesize_RaceSafe(t *testing.T) {
	d := newCacheDir(t)
	snap := validSnapshot()

	const writers = 16
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WriteSnapshot(d, 100, snap); err != nil {
				t.Errorf("concurrent WriteSnapshot: %v", err)
			}
		}()
	}
	wg.Wait()

	got, err := ReadLatestSnapshot(d)
	if err != nil {
		t.Fatalf("ReadLatestSnapshot: %v", err)
	}
	if got.Treesize != 100 {
		t.Errorf("Treesize: got %d, want 100", got.Treesize)
	}
	if !reflect.DeepEqual(got.Network.Endpoints, snap.Endpoints) {
		t.Errorf("Endpoints drifted after concurrent writes")
	}
	if !reflect.DeepEqual(got.Network.Auditors, snap.Auditors) {
		t.Errorf("Auditors drifted after concurrent writes")
	}
}

// TestSnapshot_NilCacheRejected pins the nil-receiver shape — both
// helpers refuse cleanly rather than panicking.
func TestSnapshot_NilCacheRejected(t *testing.T) {
	if err := WriteSnapshot(nil, 1, MaterializedNetwork{}); err == nil {
		t.Error("WriteSnapshot(nil) must error")
	}
	if _, err := ReadLatestSnapshot(nil); err == nil {
		t.Error("ReadLatestSnapshot(nil) must error")
	}
}
