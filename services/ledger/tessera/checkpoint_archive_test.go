package tessera

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/baseproof/baseproof/types"
)

// TestArchivedCheckpointPath_Scheme pins the per-size object scheme the readers
// (api/horizon.go, store/horizon_s3.go) must match: <dir>/checkpoints/<N>.
func TestArchivedCheckpointPath_Scheme(t *testing.T) {
	got := archivedCheckpointPath(filepath.FromSlash("/data/tessera/cosigned-checkpoint"), 12345)
	want := filepath.FromSlash("/data/tessera/checkpoints/12345")
	if got != want {
		t.Fatalf("archivedCheckpointPath = %q, want %q", got, want)
	}
}

// TestPublishCheckpointFiles_DualWrite: a publish writes BOTH the latest
// checkpoint and a per-size archive copy, byte-identical and decodable back to
// the same cosigned head.
func TestPublishCheckpointFiles_DualWrite(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "cosigned-checkpoint")

	head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 42, SMTRoot: [32]byte{0xAB}}}
	if err := publishCheckpoint(publicPath, head); err != nil {
		t.Fatalf("publishCheckpoint: %v", err)
	}

	latest, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	archived, err := os.ReadFile(filepath.Join(dir, "checkpoints", "42"))
	if err != nil {
		t.Fatalf("read per-size archive: %v", err)
	}
	if string(latest) != string(archived) {
		t.Fatalf("latest and per-size archive differ:\n latest=%s\n archived=%s", latest, archived)
	}

	// The archived bytes decode back to the same head (size preserved).
	var w types.WireCosignedTreeHead
	if err := json.Unmarshal(archived, &w); err != nil {
		t.Fatalf("decode archived: %v", err)
	}
	got, err := w.ToCosignedTreeHead()
	if err != nil {
		t.Fatalf("ToCosignedTreeHead: %v", err)
	}
	if got.TreeSize != 42 {
		t.Errorf("archived TreeSize = %d, want 42", got.TreeSize)
	}
}

// TestPublishCheckpointFiles_ArchiveRetainsAllSizes is the +/- keystone guard:
// the latest checkpoint is overwritten each publish, but the per-size archive
// retains EVERY historical head. Without the archive write, sizes 42/50 would be
// gone after the size-99 publish — and PG-off cold-seq anchoring would have
// nothing to bind to.
func TestPublishCheckpointFiles_ArchiveRetainsAllSizes(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "cosigned-checkpoint")

	sizes := []uint64{42, 50, 99}
	for _, n := range sizes {
		head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: n, SMTRoot: [32]byte{byte(n)}}}
		if err := publishCheckpoint(publicPath, head); err != nil {
			t.Fatalf("publish size %d: %v", n, err)
		}
	}

	// Latest reflects only the final publish...
	latest, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	var lw types.WireCosignedTreeHead
	if err := json.Unmarshal(latest, &lw); err != nil {
		t.Fatalf("decode latest: %v", err)
	}
	if lh, _ := lw.ToCosignedTreeHead(); lh.TreeSize != 99 {
		t.Errorf("latest TreeSize = %d, want 99 (last publish)", lh.TreeSize)
	}

	// ...but the archive retains every size — the load-bearing property.
	for _, n := range sizes {
		p := filepath.Join(dir, "checkpoints", strconv.FormatUint(n, 10))
		if _, err := os.Stat(p); err != nil {
			t.Errorf("archived checkpoint for size %d missing (%s): %v — historical heads must survive later publishes", n, p, err)
		}
	}
}

// TestPublishCheckpoint_ArchiveFailure_WithholdsHorizon is the load-bearing
// fail-closed invariant (Phase 1, symmetric with store/horizon_s3.go): the per-size
// archive is written BEFORE the horizon, so a failed archive write FAILS the publish
// AND the horizon never advances — a cold/PG-off reader must never see a horizon whose
// covering per-size checkpoint archive is missing. Reverting the archive write to
// best-effort (swallowing its error and writing the horizon anyway) makes this fail.
func TestPublishCheckpoint_ArchiveFailure_WithholdsHorizon(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "cosigned-checkpoint")

	// Block the archive: put a regular FILE where the checkpoints/ dir must be, so
	// MkdirAll(<dir>/checkpoints) fails — simulating an archive-backend fault.
	if err := os.WriteFile(filepath.Join(dir, "checkpoints"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 7, SMTRoot: [32]byte{0x7}}}
	if err := publishCheckpoint(publicPath, head); err == nil {
		t.Fatal("publish must FAIL when the per-size archive write fails (fail-closed) — the horizon must not advance past a non-durable archive")
	}

	// Fail-closed: the horizon (latest checkpoint) was NOT written — the archive is
	// durable-before-horizon, so an archive fault aborts before the horizon advances.
	if _, err := os.Stat(publicPath); !os.IsNotExist(err) {
		t.Fatalf("horizon must NOT exist after a failed archive (fail-closed); stat err = %v", err)
	}
}
