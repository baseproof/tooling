package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/baseproof/baseproof/types"
)

// publishedCheckpoint builds the wire bytes the builder writes for a cosigned
// head at the given size — the same shape as tessera publishCheckpointFiles.
func publishedCheckpoint(t *testing.T, size uint64) []byte {
	t.Helper()
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: size, SMTRoot: [32]byte{byte(size)}}}
	b, err := json.Marshal(types.FromCosignedTreeHead(head))
	if err != nil {
		t.Fatalf("marshal checkpoint: %v", err)
	}
	return b
}

// TestReadCheckpointAt_ReadsPerSizeArchive: the POSIX horizon reads the archived
// cosigned head at checkpoints/<N> — PG-free — and decodes the right size. The
// pathSeen assertion ties this reader to the writer's checkpoints/<N> scheme.
func TestReadCheckpointAt_ReadsPerSizeArchive(t *testing.T) {
	stub := &stubTileBackend{tiles: map[string][]byte{
		"checkpoints/42": publishedCheckpoint(t, 42),
		"checkpoints/50": publishedCheckpoint(t, 50),
	}}
	car, ok := NewTileBackendHorizon(stub).(CheckpointArchiveReader)
	if !ok {
		t.Fatal("tileBackendHorizon does not implement CheckpointArchiveReader")
	}

	for _, n := range []uint64{42, 50} {
		head, raw, err := car.ReadCheckpointAt(context.Background(), n)
		if err != nil {
			t.Fatalf("ReadCheckpointAt(%d): %v", n, err)
		}
		if head.TreeSize != n {
			t.Errorf("ReadCheckpointAt(%d): TreeSize = %d", n, head.TreeSize)
		}
		if len(raw) == 0 {
			t.Errorf("ReadCheckpointAt(%d): empty raw bytes", n)
		}
	}
	if stub.pathSeen != "checkpoints/50" {
		t.Errorf("requested object key = %q, want checkpoints/50 (writer scheme)", stub.pathSeen)
	}
}

// TestReadCheckpointAt_UnarchivedSize_NotExist: a size never archived returns a
// wrapped os.ErrNotExist, so the caller maps it to a genuine not-found rather
// than fabricating a head.
func TestReadCheckpointAt_UnarchivedSize_NotExist(t *testing.T) {
	stub := &stubTileBackend{tiles: map[string][]byte{"checkpoints/42": publishedCheckpoint(t, 42)}}
	car := NewTileBackendHorizon(stub).(CheckpointArchiveReader)
	if _, _, err := car.ReadCheckpointAt(context.Background(), 99); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadCheckpointAt(99): err = %v, want wrapped os.ErrNotExist", err)
	}
}

func archiveHandler(t *testing.T, tiles map[string][]byte) http.Handler {
	t.Helper()
	reader := NewTileBackendHorizon(&stubTileBackend{tiles: tiles}).(CheckpointArchiveReader)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/checkpoint/{size}", NewCheckpointArchiveHandler(reader, quietLogger()))
	return mux
}

// + case: an archived size serves 200 with the verbatim cosigned head.
func TestCheckpointArchiveHandler_ServesArchivedSize(t *testing.T) {
	h := archiveHandler(t, map[string][]byte{"checkpoints/42": publishedCheckpoint(t, 42)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/tree/checkpoint/42", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var w types.WireCosignedTreeHead
	if err := json.Unmarshal(rec.Body.Bytes(), &w); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if h, _ := w.ToCosignedTreeHead(); h.TreeSize != 42 {
		t.Errorf("served TreeSize = %d, want 42", h.TreeSize)
	}
}

// Genuine negative: a size never archived → 404 (not a fabricated head, not 500).
func TestCheckpointArchiveHandler_UnarchivedSize_404(t *testing.T) {
	h := archiveHandler(t, map[string][]byte{"checkpoints/42": publishedCheckpoint(t, 42)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/tree/checkpoint/99", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (size never archived)", rec.Code)
	}
}

// - case: no archive configured → graceful 503, never a panic.
func TestCheckpointArchiveHandler_NilReader_503(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/checkpoint/{size}", NewCheckpointArchiveHandler(nil, quietLogger()))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/tree/checkpoint/42", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (no archive configured)", rec.Code)
	}
}
