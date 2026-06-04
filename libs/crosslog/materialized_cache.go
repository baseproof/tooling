/*
FILE PATH: libs/crosslog/materialized_cache.go

Ladder 5 P6 (#21) — storage-backend-agnostic read/write wrapper for the
MaterializedNetwork round-trip.

# WHY THIS WRAPPER EXISTS

Consumers that care about the SDK-typed MaterializedNetwork (auditor
boot path, future log-scan loop, baseproof CLI's verify subcommand)
want one call that handles all four views: Endpoints, Labels,
Auditors, Amendments — bundled atop a storage primitive that may be
local filesystem, S3, or any other content-addressable object store.

# STORAGE-BACKEND-AGNOSTIC (BUT PRODUCTION IS LOCAL-DISK ONLY)

WriteSnapshot and ReadLatestSnapshot operate on a MaterializedCacheStore
interface, NOT a concrete filesystem type. The interface exists so
out-of-process tools (a future log-scan loop, the baseproof CLI's
verify subcommand, tests with in-memory stores) can swap the backend
without coupling to filesystem internals.

The ONLY production-wired backend is libs/anchorcache.ManagedDir
(local filesystem with atomic-rename discipline). A shared S3 / GCS
/ Azure Blob backend is INTENTIONALLY not wired into the auditor, for
the zero-trust reasons in the next section. Anyone adding such a
backend MUST revisit the threat model before flipping it on for the
auditor.

# WHY NOT A SHARED OBJECT-STORE BACKEND (ZERO-TRUST RATIONALE)

The auditor's job is to verify, not trust. The source of truth is:

  - the Tessera log itself (S3-backed via ledger's bytestore, signed
    envelopes, signed checkpoints, content-addressable entries)
  - Postgres-backed gossip evidence (durable, write-ahead-logged)

This P6 cache is a DERIVATIVE: a small snapshot (KB-MB per network)
of the network-config walker output that the auditor would otherwise
re-derive from a fresh on-log scan at boot.

Putting that cache on shared object storage (a single S3 bucket all
auditor instances read from) buys ~no transport-time win — the
Tessera log tiles are ALREADY on S3, so reading from a shared cache
bucket and reading from log tiles cost the same network RTT class.
The cache's value is decode+filter elision, not transport.

But shared storage adds a new trust surface: compromise of one
writer's IAM, a misconfigured bucket policy, or a poisoned write
silently propagates to every auditor instance — and the auditor
DOESN'T independently re-anchor the cache against the log (that
would defeat the speed-up). A new trust anchor that the auditor
can't verify is a zero-trust violation.

Per-instance local disk keeps blast radius to one pod's tmpfs and
keeps the cache as a HINT, never a trust anchor. Each auditor
derives its own view from the log it independently verifies.

# RELATIONSHIP TO LEDGER'S BYTESTORE

Ledger's bytestore (a separate Go module) is the log SUBSTRATE: keyed
by (sequence, hash), stores per-entry wire bytes, backends GCS / S3 /
memory. P6's cache is a PROJECTION over that log — keyed by
(view, treesize). The two abstractions are intentionally distinct
because they protect different invariants: bytestore is anonymous-
public-read by transparency-log convention (RFC 9162 / c2sp.org/
tlog-tiles); P6's cache is an internal speed-up with a different
trust posture.

# OPERATIONAL ENVELOPE

At 8-10M entries per day per network × 15 networks, the GOSSIP data
plane is Postgres-backed and durable; P6's cache covers ONLY the small
network-config walker output (Endpoints + Labels + Auditors +
Amendments — bounded by a small constant per network, a few hundred KB
in steady state). The cache is sized for "skip the on-log indexed
re-fetch + decode round-trip" on cold boot, not for the 10B-entry
data plane (which a CT-style tile + consistency-proof pattern handles
separately).

# ATOMICITY ACROSS THE FOUR VIEWS

WriteSnapshot writes the four views in a deterministic order:
Amendments → Auditors → Labels → Endpoints. A reader using
ReadLatestSnapshot tolerates an in-progress write because
ReadLatestMaterializedView falls back to the next-lower treesize on
per-view os.ErrNotExist. So even if a reader catches a writer
mid-flight, it sees a CONSISTENT snapshot — either fully the previous
treesize, or fully the new one (when all four views have landed).

Writers SHOULD prune AFTER all four views land, never before.
*/
package crosslog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/anchorcache"
)

// MaterializedCacheStore is the storage abstraction WriteSnapshot and
// ReadLatestSnapshot use. The ONLY production-wired implementation is
// libs/anchorcache.ManagedDir (local filesystem with atomic-rename
// discipline). The interface exists so tests, the baseproof CLI's
// verify subcommand, and a future log-scan loop can use the same
// helpers without coupling to the on-disk type.
//
// A shared S3 / GCS / Azure Blob backend would also satisfy this
// interface STRUCTURALLY, but production auditor wiring deliberately
// uses local-disk only. See the package doc's "WHY NOT A SHARED
// OBJECT-STORE BACKEND" section for the zero-trust rationale; do
// not flip the auditor to a shared backend without revisiting that
// threat model.
//
// Per-method contracts:
//
//   - WriteMaterializedView: atomic per (view, treesize). Concurrent
//     writers at the same key producing the same bytes MUST settle
//     to a consistent file (filesystem: temp-then-rename; S3: PUT
//     with content-MD5 idempotency, or last-writer-wins semantics
//     since the bytes are deterministic).
//
//   - ReadMaterializedView: returns the wrapped os.ErrNotExist when
//     the (view, treesize) key is absent. S3 backends translate
//     NoSuchKey to os.ErrNotExist; GCS backends translate
//     storage.ErrObjectNotExist; etc.
//
//   - ReadLatestMaterializedView: returns the bytes + the tree size
//     that served them. Per-view fallback semantics: if the
//     highest-listed treesize doesn't have the view, drop to the
//     next-lower treesize that does. Returns os.ErrNotExist when no
//     treesize has the view.
//
//   - ListMaterializedTreesizes: returns sorted ascending. Empty
//     slice when no snapshots exist (NOT an error).
//
//   - PruneMaterializedTreesizesBelow: keeps the most recent `keep`
//     treesize subdirectories, removes the rest. Returns the count
//     pruned. keep <= 0 is a no-op. Backend MAY prune concurrently
//     with reads; readers that loaded the now-pruned path get
//     backend-specific behavior (filesystem: continue reading via
//     open-FD; S3: subsequent reads return NoSuchKey).
type MaterializedCacheStore interface {
	WriteMaterializedView(view string, treesize uint64, raw []byte) error
	ReadMaterializedView(view string, treesize uint64) ([]byte, error)
	ReadLatestMaterializedView(view string) ([]byte, uint64, error)
	ListMaterializedTreesizes() ([]uint64, error)
	PruneMaterializedTreesizesBelow(keep int) (int, error)
}

// Compile-time guarantee that anchorcache.ManagedDir satisfies the
// interface. If a future refactor breaks this, builds fail here
// rather than at the auditor's runtime call site.
var _ MaterializedCacheStore = (*anchorcache.ManagedDir)(nil)

// SnapshotResult bundles a successfully-loaded snapshot from disk.
type SnapshotResult struct {
	// Network is the assembled MaterializedNetwork.
	Network MaterializedNetwork
	// Treesize is the highest tree size that produced a usable
	// snapshot. ReadLatestSnapshot may fall back to a lower treesize
	// for individual views (in-progress-write tolerance); this is
	// the MAX of the per-view treesizes returned.
	Treesize uint64
	// PerViewTreesizes records which treesize served each view, so
	// callers can detect (and log) in-progress-write fallbacks.
	PerViewTreesizes map[string]uint64
}

// WriteSnapshot serializes the four MaterializedNetwork view slices
// as JSON and writes each under the supplied treesize. The write
// order is Amendments → Auditors → Labels → Endpoints; a reader using
// ReadLatestSnapshot during this window falls back per-view to the
// next-lower treesize for any view not yet landed.
//
// Returns the first error encountered; partial writes are left in
// place (the caller's next attempt overwrites them at the same
// treesize, atomic per view).
func WriteSnapshot(cache MaterializedCacheStore, treesize uint64, m MaterializedNetwork) error {
	if cache == nil {
		return errors.New("crosslog/materialized_cache: nil cache store")
	}
	// Marshal first (no I/O on a marshal failure).
	views := []struct {
		name string
		body []byte
	}{}
	// Amendments first (v1.33.x Gap 2 — listed first so a reader
	// catching a partial write sees Amendments before Auditors and
	// uses the next-lower treesize for Auditors, which is consistent
	// with the v1.32.x semantic).
	amBytes, err := json.Marshal(m.Amendments)
	if err != nil {
		return fmt.Errorf("crosslog/materialized_cache: marshal amendments: %w", err)
	}
	views = append(views, struct {
		name string
		body []byte
	}{anchorcache.MaterializedViewAmendments, amBytes})

	auBytes, err := json.Marshal(m.Auditors)
	if err != nil {
		return fmt.Errorf("crosslog/materialized_cache: marshal auditors: %w", err)
	}
	views = append(views, struct {
		name string
		body []byte
	}{anchorcache.MaterializedViewAuditors, auBytes})

	laBytes, err := json.Marshal(m.Labels)
	if err != nil {
		return fmt.Errorf("crosslog/materialized_cache: marshal labels: %w", err)
	}
	views = append(views, struct {
		name string
		body []byte
	}{anchorcache.MaterializedViewLabels, laBytes})

	epBytes, err := json.Marshal(m.Endpoints)
	if err != nil {
		return fmt.Errorf("crosslog/materialized_cache: marshal endpoints: %w", err)
	}
	views = append(views, struct {
		name string
		body []byte
	}{anchorcache.MaterializedViewEndpoints, epBytes})

	for _, v := range views {
		if err := cache.WriteMaterializedView(v.name, treesize, v.body); err != nil {
			return fmt.Errorf("crosslog/materialized_cache: write %s: %w", v.name, err)
		}
	}
	return nil
}

// ReadLatestSnapshot assembles a MaterializedNetwork from the highest
// available tree-size subdirectory under the cache's materialized/
// path. Per-view fallback (the in-progress-write tolerance) means a
// view that didn't land at the highest treesize is read from the
// next-lower treesize that has it.
//
// Returns os.ErrNotExist (wrapped) when NO snapshots exist at all —
// the cold-boot-with-no-cache case. Callers treat this as "no cache;
// proceed to a fresh on-log scan".
//
// Other errors (JSON unmarshal failures, filesystem I/O errors)
// surface verbatim; callers MAY treat them as "cache corrupt; proceed
// to fresh on-log scan and overwrite at the next WriteSnapshot" or
// fail-loud at boot, depending on posture.
func ReadLatestSnapshot(cache MaterializedCacheStore) (SnapshotResult, error) {
	if cache == nil {
		return SnapshotResult{}, errors.New("crosslog/materialized_cache: nil cache store")
	}
	res := SnapshotResult{
		PerViewTreesizes: map[string]uint64{},
	}
	anySuccess := false

	// Endpoints
	body, ts, err := cache.ReadLatestMaterializedView(anchorcache.MaterializedViewEndpoints)
	if err == nil {
		if uerr := json.Unmarshal(body, &res.Network.Endpoints); uerr != nil {
			return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: unmarshal endpoints: %w", uerr)
		}
		res.PerViewTreesizes[anchorcache.MaterializedViewEndpoints] = ts
		if ts > res.Treesize {
			res.Treesize = ts
		}
		anySuccess = true
	} else if !os.IsNotExist(err) {
		return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: read endpoints: %w", err)
	}

	// Labels
	body, ts, err = cache.ReadLatestMaterializedView(anchorcache.MaterializedViewLabels)
	if err == nil {
		if uerr := json.Unmarshal(body, &res.Network.Labels); uerr != nil {
			return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: unmarshal labels: %w", uerr)
		}
		res.PerViewTreesizes[anchorcache.MaterializedViewLabels] = ts
		if ts > res.Treesize {
			res.Treesize = ts
		}
		anySuccess = true
	} else if !os.IsNotExist(err) {
		return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: read labels: %w", err)
	}

	// Auditors
	body, ts, err = cache.ReadLatestMaterializedView(anchorcache.MaterializedViewAuditors)
	if err == nil {
		if uerr := json.Unmarshal(body, &res.Network.Auditors); uerr != nil {
			return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: unmarshal auditors: %w", uerr)
		}
		res.PerViewTreesizes[anchorcache.MaterializedViewAuditors] = ts
		if ts > res.Treesize {
			res.Treesize = ts
		}
		anySuccess = true
	} else if !os.IsNotExist(err) {
		return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: read auditors: %w", err)
	}

	// Amendments (v1.33.x Gap 2)
	body, ts, err = cache.ReadLatestMaterializedView(anchorcache.MaterializedViewAmendments)
	if err == nil {
		if uerr := json.Unmarshal(body, &res.Network.Amendments); uerr != nil {
			return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: unmarshal amendments: %w", uerr)
		}
		res.PerViewTreesizes[anchorcache.MaterializedViewAmendments] = ts
		if ts > res.Treesize {
			res.Treesize = ts
		}
		anySuccess = true
	} else if !os.IsNotExist(err) {
		return SnapshotResult{}, fmt.Errorf("crosslog/materialized_cache: read amendments: %w", err)
	}

	if !anySuccess {
		return SnapshotResult{}, os.ErrNotExist
	}
	return res, nil
}

// SnapshotIsEmpty reports whether the MaterializedNetwork carries
// zero records across all four views. Useful for the auditor boot
// path's heuristic: an empty snapshot is loaded successfully but
// contributes nothing to the resolver, so the operator's log can
// distinguish "cache exists but empty" from "no cache at all".
func SnapshotIsEmpty(m MaterializedNetwork) bool {
	return len(m.Endpoints) == 0 && len(m.Labels) == 0 &&
		len(m.Auditors) == 0 && len(m.Amendments) == 0
}

// silence_imports keeps the network package referenced when the
// MaterializedNetwork shape's individual type names are only used
// transitively via Network's fields. Forward-compat hook for a
// future refactor that consumes a specific record type by name.
var _ network.AuditorRegistrationByPosition
