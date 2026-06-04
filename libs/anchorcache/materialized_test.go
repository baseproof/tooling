/*
FILE PATH: libs/anchorcache/materialized_test.go

Ladder 5 P6 (#21) — tree-size-keyed materialized-view cache coverage.

# WHAT THIS PINS

  1. Round-trip: Write then Read returns the same bytes at the same
     (view, treesize).
  2. ReadMaterializedView for an absent file returns wrapped
     os.ErrNotExist (callers branch on os.IsNotExist).
  3. ListMaterializedTreesizes / LatestMaterializedTreesize on an
     empty cache return empty slice / ErrNotExist.
  4. ListMaterializedTreesizes returns the available subdirectories
     SORTED ASCENDING.
  5. ReadLatestMaterializedView returns the bytes + treesize from
     the HIGHEST tree size that contains the view, even when the
     next-highest tree size directory exists without the view
     (in-progress-write case).
  6. Pruning keeps the most recent `keep` subdirectories.
  7. Pruning with keep <= 0 is a no-op.
  8. Pruning with keep >= len(available) is a no-op.
  9. CONCURRENT WRITERS AT THE SAME (view, treesize) — race-safe
     under -race; no torn files, no data races.
 10. CONCURRENT WRITERS AT DIFFERENT TREESIZES — no contention; all
     writers' bytes survive.
 11. UNKNOWN VIEW NAME is rejected by both write and read paths.
 12. Non-numeric subdirectories in materialized/ are silently
     skipped by the lister (forward-compat for legacy
     materialized/labels.json flat files).
*/
package anchorcache

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

// openTestDir constructs an isolated ManagedDir for one test. Mirrors
// the helper in anchorcache_test.go without inheriting any other
// fixture state.
func openTestDir(t *testing.T) *ManagedDir {
	t.Helper()
	root := t.TempDir()
	d, err := OpenAt(root, "did:test:p6-network")
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	return d
}

// ─────────────────────────────────────────────────────────────────
// Round-trip
// ─────────────────────────────────────────────────────────────────

func TestMaterialized_RoundTrip(t *testing.T) {
	d := openTestDir(t)
	want := []byte(`[{"effective_seq":42}]`)
	if err := d.WriteMaterializedView(MaterializedViewAuditors, 100, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := d.ReadMaterializedView(MaterializedViewAuditors, 100)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestMaterialized_RoundTrip_AllViews(t *testing.T) {
	d := openTestDir(t)
	const treesize = 200
	cases := map[string][]byte{
		MaterializedViewEndpoints:  []byte(`[{"endpoint":"e"}]`),
		MaterializedViewLabels:     []byte(`[{"label":"l"}]`),
		MaterializedViewAuditors:   []byte(`[{"auditor":"a"}]`),
		MaterializedViewAmendments: []byte(`[{"amendment":"m"}]`),
	}
	for view, want := range cases {
		if err := d.WriteMaterializedView(view, treesize, want); err != nil {
			t.Errorf("Write %s: %v", view, err)
		}
	}
	for view, want := range cases {
		got, err := d.ReadMaterializedView(view, treesize)
		if err != nil {
			t.Errorf("Read %s: %v", view, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s round-trip mismatch:\n got %q\nwant %q", view, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// Missing-file semantics
// ─────────────────────────────────────────────────────────────────

func TestMaterialized_ReadMissingFile_ErrNotExist(t *testing.T) {
	d := openTestDir(t)
	_, err := d.ReadMaterializedView(MaterializedViewAuditors, 999)
	if err == nil {
		t.Fatal("expected ErrNotExist for missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("errors.Is(err, os.ErrNotExist) = false; got %v", err)
	}
}

func TestMaterialized_ListEmpty(t *testing.T) {
	d := openTestDir(t)
	got, err := d.ListMaterializedTreesizes()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty; got %v", got)
	}
}

func TestMaterialized_LatestEmpty(t *testing.T) {
	d := openTestDir(t)
	_, err := d.LatestMaterializedTreesize()
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist; got %v", err)
	}
}

func TestMaterialized_ReadLatest_NoCache(t *testing.T) {
	d := openTestDir(t)
	_, _, err := d.ReadLatestMaterializedView(MaterializedViewAuditors)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Listing semantics
// ─────────────────────────────────────────────────────────────────

func TestMaterialized_ListReturnsAscending(t *testing.T) {
	d := openTestDir(t)
	for _, ts := range []uint64{300, 100, 200, 50} {
		if err := d.WriteMaterializedView(MaterializedViewAuditors, ts, []byte(`[]`)); err != nil {
			t.Fatalf("Write %d: %v", ts, err)
		}
	}
	got, err := d.ListMaterializedTreesizes()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []uint64{50, 100, 200, 300}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestMaterialized_LatestReturnsMax(t *testing.T) {
	d := openTestDir(t)
	for _, ts := range []uint64{100, 500, 200} {
		if err := d.WriteMaterializedView(MaterializedViewAuditors, ts, []byte(`[]`)); err != nil {
			t.Fatalf("Write %d: %v", ts, err)
		}
	}
	got, err := d.LatestMaterializedTreesize()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != 500 {
		t.Errorf("got %d, want 500", got)
	}
}

func TestMaterialized_ListIgnoresNonNumericSubdirs(t *testing.T) {
	d := openTestDir(t)
	// Drop a legacy flat-path file directly into materialized/ to
	// simulate a v1.32.0 deployment's leftover state.
	legacy := filepath.Join(d.dirPath, "materialized", "labels.json")
	if err := os.WriteFile(legacy, []byte(`[]`), 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}
	// Add a stray non-numeric subdirectory (forward-compat seam).
	strayDir := filepath.Join(d.dirPath, "materialized", "index")
	if err := os.MkdirAll(strayDir, 0o700); err != nil {
		t.Fatalf("mkdir stray: %v", err)
	}
	// Write a real tree-size snapshot.
	if err := d.WriteMaterializedView(MaterializedViewAuditors, 42, []byte(`[]`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := d.ListMaterializedTreesizes()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !reflect.DeepEqual(got, []uint64{42}) {
		t.Errorf("got %v, want [42] (legacy + non-numeric subdirs ignored)", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// ReadLatestMaterializedView — in-progress-write fallback
// ─────────────────────────────────────────────────────────────────

func TestMaterialized_ReadLatest_FallsBackOnMissingView(t *testing.T) {
	d := openTestDir(t)
	// At treesize 100, write only Auditors. Endpoints is missing.
	if err := d.WriteMaterializedView(MaterializedViewAuditors, 100, []byte(`[{"a":100}]`)); err != nil {
		t.Fatalf("Write 100/auditors: %v", err)
	}
	// At treesize 50, write both Auditors and Endpoints.
	if err := d.WriteMaterializedView(MaterializedViewAuditors, 50, []byte(`[{"a":50}]`)); err != nil {
		t.Fatalf("Write 50/auditors: %v", err)
	}
	if err := d.WriteMaterializedView(MaterializedViewEndpoints, 50, []byte(`[{"e":50}]`)); err != nil {
		t.Fatalf("Write 50/endpoints: %v", err)
	}

	// Auditors at the LATEST treesize (100) is present — picks 100.
	body, ts, err := d.ReadLatestMaterializedView(MaterializedViewAuditors)
	if err != nil {
		t.Fatalf("ReadLatest Auditors: %v", err)
	}
	if ts != 100 {
		t.Errorf("Auditors latest ts: got %d, want 100", ts)
	}
	if !bytes.Equal(body, []byte(`[{"a":100}]`)) {
		t.Errorf("Auditors body: got %q", body)
	}

	// Endpoints at the LATEST treesize (100) is MISSING — fall back
	// to the next-lower treesize (50). This is the in-progress-write
	// case the comment in materialized.go calls out: the highest
	// treesize directory exists (Auditors landed first) but Endpoints
	// is still mid-write.
	body, ts, err = d.ReadLatestMaterializedView(MaterializedViewEndpoints)
	if err != nil {
		t.Fatalf("ReadLatest Endpoints: %v", err)
	}
	if ts != 50 {
		t.Errorf("Endpoints fallback ts: got %d, want 50", ts)
	}
	if !bytes.Equal(body, []byte(`[{"e":50}]`)) {
		t.Errorf("Endpoints body: got %q", body)
	}
}

func TestMaterialized_ReadLatest_AllMissing_ReturnsErrNotExist(t *testing.T) {
	d := openTestDir(t)
	// Tree-size directories exist but none contains the Endpoints view.
	if err := d.WriteMaterializedView(MaterializedViewAuditors, 50, []byte(`[]`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := d.WriteMaterializedView(MaterializedViewAuditors, 100, []byte(`[]`)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_, _, err := d.ReadLatestMaterializedView(MaterializedViewEndpoints)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Prune
// ─────────────────────────────────────────────────────────────────

func TestMaterialized_PruneKeepsLastN(t *testing.T) {
	d := openTestDir(t)
	for _, ts := range []uint64{10, 20, 30, 40, 50, 60, 70} {
		if err := d.WriteMaterializedView(MaterializedViewAuditors, ts, []byte(`[]`)); err != nil {
			t.Fatalf("Write %d: %v", ts, err)
		}
	}
	pruned, err := d.PruneMaterializedTreesizesBelow(3)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 4 {
		t.Errorf("pruned: got %d, want 4", pruned)
	}
	got, err := d.ListMaterializedTreesizes()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !reflect.DeepEqual(got, []uint64{50, 60, 70}) {
		t.Errorf("remaining: got %v, want [50 60 70]", got)
	}
}

func TestMaterialized_PruneKeepZero_NoOp(t *testing.T) {
	d := openTestDir(t)
	for _, ts := range []uint64{10, 20, 30} {
		if err := d.WriteMaterializedView(MaterializedViewAuditors, ts, []byte(`[]`)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	pruned, err := d.PruneMaterializedTreesizesBelow(0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 0 {
		t.Errorf("pruned: got %d, want 0 (keep<=0 is no-op)", pruned)
	}
	got, _ := d.ListMaterializedTreesizes()
	if len(got) != 3 {
		t.Errorf("remaining: got %d, want 3", len(got))
	}
}

func TestMaterialized_PruneKeepMoreThanAvailable_NoOp(t *testing.T) {
	d := openTestDir(t)
	for _, ts := range []uint64{10, 20} {
		if err := d.WriteMaterializedView(MaterializedViewAuditors, ts, []byte(`[]`)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	pruned, err := d.PruneMaterializedTreesizesBelow(10)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 0 {
		t.Errorf("pruned: got %d, want 0 (keep >= len is no-op)", pruned)
	}
	got, _ := d.ListMaterializedTreesizes()
	if len(got) != 2 {
		t.Errorf("remaining: got %d, want 2", len(got))
	}
}

// ─────────────────────────────────────────────────────────────────
// Unknown view validation
// ─────────────────────────────────────────────────────────────────

func TestMaterialized_UnknownViewRejected_Write(t *testing.T) {
	d := openTestDir(t)
	err := d.WriteMaterializedView("not-a-view.json", 100, []byte(`[]`))
	if err == nil {
		t.Fatal("expected error for unknown view name")
	}
}

func TestMaterialized_UnknownViewRejected_Read(t *testing.T) {
	d := openTestDir(t)
	_, err := d.ReadMaterializedView("not-a-view.json", 100)
	if err == nil {
		t.Fatal("expected error for unknown view name")
	}
}

// ─────────────────────────────────────────────────────────────────
// Concurrency — race-detector tests
// ─────────────────────────────────────────────────────────────────

// TestMaterialized_ConcurrentSameTreesize_RaceSafe pins the
// HA-scenario invariant: N writers at the same (view, treesize)
// producing the same bytes must not race. Each goroutine writes
// the SAME bytes because the on-log state at a given tree size is
// deterministic — but the temp-file inodes differ, and the atomic
// rename's order is non-deterministic. After all goroutines settle,
// Read MUST return the canonical bytes.
//
// Race-detector run: any tearing or shared-mutable-state regression
// in writeAtomic's helper surfaces as a DATA RACE report.
func TestMaterialized_ConcurrentSameTreesize_RaceSafe(t *testing.T) {
	d := openTestDir(t)
	canonical := []byte(`[{"deterministic":true}]`)

	const writers = 16
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := d.WriteMaterializedView(MaterializedViewAuditors, 100, canonical); err != nil {
				t.Errorf("concurrent Write: %v", err)
			}
		}()
	}
	wg.Wait()

	got, err := d.ReadMaterializedView(MaterializedViewAuditors, 100)
	if err != nil {
		t.Fatalf("Read after concurrent writes: %v", err)
	}
	if !bytes.Equal(got, canonical) {
		t.Errorf("post-concurrent-write bytes drifted:\n got %q\nwant %q", got, canonical)
	}
}

// TestMaterialized_ConcurrentDifferentTreesizes_NoContention pins that
// writers at DIFFERENT treesizes target different files, so all
// writers' bytes survive. This is the structural property
// tree-size-keying provides over the flat materialized/<view>.json
// path: every writer's snapshot is independently visible.
func TestMaterialized_ConcurrentDifferentTreesizes_NoContention(t *testing.T) {
	d := openTestDir(t)

	const writers = 32
	var wg sync.WaitGroup
	var writeErrors atomic.Int64
	for i := uint64(0); i < writers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte(fmt.Sprintf(`[{"ts":%d}]`, i*10))
			if err := d.WriteMaterializedView(MaterializedViewAuditors, i*10, body); err != nil {
				writeErrors.Add(1)
				t.Errorf("concurrent Write ts=%d: %v", i*10, err)
			}
		}()
	}
	wg.Wait()

	if writeErrors.Load() != 0 {
		t.Fatalf("%d writes errored under concurrent load", writeErrors.Load())
	}

	all, err := d.ListMaterializedTreesizes()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != writers {
		t.Errorf("expected %d distinct treesizes; got %d (%v)", writers, len(all), all)
	}
	// Every writer's bytes must be readable from its own treesize.
	for i := uint64(0); i < writers; i++ {
		want := []byte(fmt.Sprintf(`[{"ts":%d}]`, i*10))
		got, err := d.ReadMaterializedView(MaterializedViewAuditors, i*10)
		if err != nil {
			t.Errorf("Read ts=%d: %v", i*10, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ts=%d bytes drifted:\n got %q\nwant %q", i*10, got, want)
		}
	}
}

// TestMaterialized_ConcurrentWriteAndPrune pins that a Prune running
// concurrently with new writes settles to a consistent state — old
// treesizes are removed, new treesizes survive, the operation is
// race-clean under -race.
//
// The test is not deterministic about exactly WHICH treesizes survive
// (prune may run before or after specific writes), only that:
//   - no writer errors
//   - after settle, ListMaterializedTreesizes returns at most `keep`
//     entries
//   - all surviving treesizes have readable bytes
func TestMaterialized_ConcurrentWriteAndPrune(t *testing.T) {
	d := openTestDir(t)
	const writes = 50
	const keep = 5

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint64(1); i <= writes; i++ {
			body := []byte(fmt.Sprintf(`[{"ts":%d}]`, i))
			if err := d.WriteMaterializedView(MaterializedViewAuditors, i, body); err != nil {
				t.Errorf("write ts=%d: %v", i, err)
			}
		}
	}()
	// Concurrent prune. Runs a few times while writes are in
	// progress; the test pins that the FINAL state is consistent.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			if _, err := d.PruneMaterializedTreesizesBelow(keep); err != nil {
				t.Errorf("prune iter %d: %v", j, err)
			}
		}
	}()
	wg.Wait()

	// Final settle.
	_, err := d.PruneMaterializedTreesizesBelow(keep)
	if err != nil {
		t.Fatalf("final prune: %v", err)
	}
	all, err := d.ListMaterializedTreesizes()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) > keep {
		t.Errorf("post-settle: %d treesizes survive, want <= %d", len(all), keep)
	}
	// Every surviving treesize must be readable.
	for _, ts := range all {
		_, err := d.ReadMaterializedView(MaterializedViewAuditors, ts)
		if err != nil {
			t.Errorf("post-prune Read ts=%d: %v", ts, err)
		}
	}
}
