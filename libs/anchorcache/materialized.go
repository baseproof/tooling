/*
FILE PATH: libs/anchorcache/materialized.go

Ladder 5 P6 (#21) — tree-size-keyed materialized-view cache.

# WHY TREE-SIZE-KEYED

The original `materialized/<view>.json` paths (defined in views.go as
PolicyViewMaterializedXxx) are a SHARED resource: at HA scale with N
auditor instances per network, all N writers race on the same file
path. The atomic-rename primitive means each write is atomic in
isolation, but two writers producing DIFFERENT bytes (each from a
slightly-different on-log scan timestamp) leave the loser's bytes
silently overwritten with no signal to the operator.

Tree-size-keyed paths solve this structurally:

    materialized/<treesize>/<view>.json

A write at tree size T cannot collide with a write at tree size T+1
— they target different files. Two writers AT THE SAME tree size still
collide on the same file, but they're writing the SAME bytes (the
on-log state at tree size T is deterministic), so the rename order is
behaviorally irrelevant.

# READER SEMANTICS

Cold-boot readers want the LATEST snapshot. LatestMaterializedTreesize
scans the materialized/ directory for tree-size subdirectories and
returns the maximum. ReadMaterializedView(view, treesize) reads the
specific file. ReadLatestMaterializedView is a convenience composing
the two.

# GC

PruneMaterializedTreesizesBelow keeps the most recent `keep`
treesize subdirectories and removes the rest. Operators set this via
the auditor's `AUDITOR_MATERIALIZED_KEEP_LAST` env var (default 5).

# RELATIONSHIP TO THE LEGACY PolicyViewMaterializedXxx CONSTANTS

The legacy constants (materialized/labels.json, etc. — flat paths) are
preserved for callers that already use WritePolicyBytes /
ReadPolicyBytes against the v1.32.0 API. The new tree-size-keyed API
lives BESIDE them, not replacing them. No production consumer uses the
legacy materialized paths today (Ladder 2 D4 noted the seam without
write/read wiring); the new API is the recommended path going forward.

# CONCURRENCY GUARANTEES

  - WriteMaterializedView at the same (view, treesize) — atomic rename;
    last-writer-wins on identical bytes, no torn files.
  - WriteMaterializedView at different treesizes — no contention;
    targets different files.
  - LatestMaterializedTreesize while a write is in progress — sees
    treesizes that have been COMPLETELY written (the temp-then-rename
    discipline of writeAtomic ensures partial files do not appear with
    the final name).
  - PruneMaterializedTreesizesBelow while reads are in progress — a
    reader that loaded the path can still open the file even after
    Prune removes it (Unix's "unlink-while-open" semantics; the file
    backing keeps the inode alive until the reader closes). On Windows
    the semantic is weaker; deployments concerned about this run with
    the GOOS=linux container.
*/
package anchorcache

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// Materialized view names — the four kinds the SDK's MaterializedNetwork
// carries. Reused as filenames inside each tree-size subdirectory.
//
// Layout under materialized/<treesize>/:
//   endpoints.json   — WitnessEndpointDeclarationByPosition
//   labels.json      — WitnessIdentityLabelByPosition
//   auditors.json    — AuditorRegistrationByPosition
//   amendments.json  — AuditorScopeAmendmentByPosition  (v1.33.x Gap 2)
const (
	MaterializedViewEndpoints  = "endpoints.json"
	MaterializedViewLabels     = "labels.json"
	MaterializedViewAuditors   = "auditors.json"
	MaterializedViewAmendments = "amendments.json"
)

// validMaterializedView reports whether view names a known v1.33.x
// materialized record kind.
func validMaterializedView(view string) bool {
	switch view {
	case MaterializedViewEndpoints, MaterializedViewLabels,
		MaterializedViewAuditors, MaterializedViewAmendments:
		return true
	default:
		return false
	}
}

// WriteMaterializedView writes raw to
//
//	<dirPath>/materialized/<treesize>/<view>
//
// atomically (temp + rename). Creates the tree-size subdirectory if
// missing. Concurrent writers at the same (view, treesize) are
// behaviorally safe — the on-log state at a given tree size is
// deterministic, so identical bytes are written by every concurrent
// scanner; the rename order only affects which writer's exact temp
// inode wins.
//
// view MUST be one of the MaterializedView* constants.
func (d *ManagedDir) WriteMaterializedView(view string, treesize uint64, raw []byte) error {
	if !validMaterializedView(view) {
		return fmt.Errorf("anchorcache: unknown materialized view %q", view)
	}
	dir := filepath.Join(d.dirPath, "materialized", strconv.FormatUint(treesize, 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("anchorcache: mkdir %s: %w", dir, err)
	}
	full := filepath.Join(dir, view)
	return writeAtomic(full, raw, 0o600)
}

// ReadMaterializedView reads the file at
//
//	<dirPath>/materialized/<treesize>/<view>
//
// Returns the wrapped os.ErrNotExist when the file (or its tree-size
// subdirectory) doesn't exist. Callers that want the "latest available"
// snapshot use ReadLatestMaterializedView instead.
//
// view MUST be one of the MaterializedView* constants.
func (d *ManagedDir) ReadMaterializedView(view string, treesize uint64) ([]byte, error) {
	if !validMaterializedView(view) {
		return nil, fmt.Errorf("anchorcache: unknown materialized view %q", view)
	}
	full := filepath.Join(d.dirPath, "materialized",
		strconv.FormatUint(treesize, 10), view)
	body, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// ListMaterializedTreesizes returns the tree-size subdirectories under
// materialized/, sorted ascending. Empty slice if no snapshots have
// been written. Non-numeric subdirectory names are silently skipped —
// a forward-compat seam in case a future schema adds e.g. an "index"
// subdir.
func (d *ManagedDir) ListMaterializedTreesizes() ([]uint64, error) {
	root := filepath.Join(d.dirPath, "materialized")
	entries, err := os.ReadDir(root)
	if err != nil {
		// Materialized/ is created eagerly at OpenAt time, so its
		// absence is not expected; still, propagate the error.
		return nil, fmt.Errorf("anchorcache: read materialized dir: %w", err)
	}
	out := make([]uint64, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ts, err := strconv.ParseUint(e.Name(), 10, 64)
		if err != nil {
			// Skip non-numeric entries (e.g., legacy
			// materialized/labels.json files written via the v1.32.0
			// flat-path API). They're harmless; a future GC pass
			// over the legacy paths would delete them, but the
			// tree-size scanner doesn't need to.
			continue
		}
		out = append(out, ts)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// LatestMaterializedTreesize returns the largest tree size under
// materialized/. Returns os.ErrNotExist when no tree-size
// subdirectory exists.
//
// This DOES NOT verify that any specific view file is present at the
// returned tree size — a directory may exist with an in-progress
// write that hasn't yet flushed all four views. Callers reading the
// returned tree size handle per-view os.ErrNotExist by falling back
// to the next-lower treesize OR by treating the missing view as
// "empty snapshot".
func (d *ManagedDir) LatestMaterializedTreesize() (uint64, error) {
	all, err := d.ListMaterializedTreesizes()
	if err != nil {
		return 0, err
	}
	if len(all) == 0 {
		return 0, os.ErrNotExist
	}
	return all[len(all)-1], nil
}

// ReadLatestMaterializedView reads view at the highest available
// tree size. Returns the bytes + the tree size that was read. If
// no tree-size subdirectory has the supplied view, returns
// os.ErrNotExist.
//
// Cold-boot path: a consumer calls this once per view (Endpoints /
// Labels / Auditors / Amendments) to populate its in-memory snapshot.
// If all four return os.ErrNotExist, no cache exists yet and the
// consumer falls through to a fresh on-log scan.
func (d *ManagedDir) ReadLatestMaterializedView(view string) ([]byte, uint64, error) {
	all, err := d.ListMaterializedTreesizes()
	if err != nil {
		return nil, 0, err
	}
	// Walk treesizes high-to-low; the FIRST one with the view file
	// wins. This handles the in-progress-write case where the highest
	// treesize directory exists but doesn't yet have all views.
	for i := len(all) - 1; i >= 0; i-- {
		body, err := d.ReadMaterializedView(view, all[i])
		if err == nil {
			return body, all[i], nil
		}
		if !os.IsNotExist(err) {
			return nil, 0, err
		}
	}
	return nil, 0, os.ErrNotExist
}

// PruneMaterializedTreesizesBelow keeps the most recent `keep`
// tree-size subdirectories under materialized/ and removes the rest.
// Returns the count pruned + any error from os.RemoveAll on a removal.
//
// keep <= 0 keeps everything (no-op). keep larger than the current
// count keeps everything (no-op).
//
// Concurrent readers: a reader that already opened a file in a pruned
// directory continues reading it (Unix unlink-while-open semantics).
// New readers that call ListMaterializedTreesizes after Prune see only
// the kept set.
func (d *ManagedDir) PruneMaterializedTreesizesBelow(keep int) (int, error) {
	if keep <= 0 {
		return 0, nil
	}
	all, err := d.ListMaterializedTreesizes()
	if err != nil {
		return 0, err
	}
	if len(all) <= keep {
		return 0, nil
	}
	prune := all[:len(all)-keep]
	pruned := 0
	for _, ts := range prune {
		dir := filepath.Join(d.dirPath, "materialized",
			strconv.FormatUint(ts, 10))
		if err := os.RemoveAll(dir); err != nil {
			return pruned, fmt.Errorf("anchorcache: prune %s: %w", dir, err)
		}
		pruned++
	}
	return pruned, nil
}
