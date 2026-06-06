package tessera

import (
	"context"
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
	if err := publishCheckpoint(context.Background(), publicPath, head, nil); err != nil {
		t.Fatalf("publishCheckpointFiles: %v", err)
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
		if err := publishCheckpoint(context.Background(), publicPath, head, nil); err != nil {
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

// TestPublishCheckpoint_ArchiveFailure_DoesNotFailPublish is the load-bearing
// resilience invariant (Phase 1): the per-size archive is BEST-EFFORT, so a failed
// archive write must NOT fail the publish — the load-bearing latest checkpoint (the
// horizon) is still written and the checkpoint loop is never stalled. Reverting the
// archive write to load-bearing (propagating its error) makes this test fail.
func TestPublishCheckpoint_ArchiveFailure_DoesNotFailPublish(t *testing.T) {
	dir := t.TempDir()
	publicPath := filepath.Join(dir, "cosigned-checkpoint")

	// Block the archive: put a regular FILE where the checkpoints/ dir must be, so
	// MkdirAll(<dir>/checkpoints) fails — simulating an archive-backend fault.
	if err := os.WriteFile(filepath.Join(dir, "checkpoints"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 7, SMTRoot: [32]byte{0x7}}}
	if err := publishCheckpoint(context.Background(), publicPath, head, nil); err != nil {
		t.Fatalf("publish must SUCCEED despite a failed archive write (best-effort), got: %v", err)
	}

	// The load-bearing latest checkpoint (the horizon) was still written.
	body, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("latest checkpoint (horizon) missing after archive failure: %v", err)
	}
	var w types.WireCosignedTreeHead
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatalf("decode latest: %v", err)
	}
	if h, _ := w.ToCosignedTreeHead(); h.TreeSize != 7 {
		t.Errorf("horizon TreeSize = %d, want 7", h.TreeSize)
	}
}
