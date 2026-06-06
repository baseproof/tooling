// FILE PATH: api/tree_inclusion_treesize_test.go
//
// Tests the optional ?tree_size=N parameter on GET /v1/tree/inclusion/{seq}.
//
// WHY THIS PARAM EXISTS. An auditor rebuilding the witness-rotation chain
// (tooling libs/witnessrotation) must verify each rotation's inclusion
// proof against the witness-COSIGNED horizon — which lags the live head — not
// against the live sub-quorum head the handler defaults to. ?tree_size=N pins
// the proof to a specific (cosigned) size. N must be in (seq, head.TreeSize].
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/services/ledger/apitypes"
)

// fakeHeadFetcher returns a fixed current head size.
type fakeHeadFetcher struct{ size uint64 }

func (f fakeHeadFetcher) Latest(_ context.Context) (*apitypes.CosignedTreeHead, error) {
	return &apitypes.CosignedTreeHead{TreeSize: f.size}, nil
}
func (f fakeHeadFetcher) GetBySize(_ context.Context, _ uint64) (*apitypes.CosignedTreeHead, error) {
	return nil, nil
}

// captureInclusion records the treeSize it was asked to prove against.
type captureInclusion struct{ gotTreeSize uint64 }

func (c *captureInclusion) RawInclusionProof(position, treeSize uint64) (any, error) {
	c.gotTreeSize = treeSize
	return map[string]any{"leaf_index": position, "tree_size": treeSize, "hashes": []string{}}, nil
}

func serveInclusion(t *testing.T, headSize uint64, target string) (*httptest.ResponseRecorder, *captureInclusion) {
	t.Helper()
	cap := &captureInclusion{}
	deps := &TreeDeps{TreeHeadStore: fakeHeadFetcher{size: headSize}, Inclusion: cap}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", NewTreeInclusionHandler(deps))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec, cap
}

// Default (no param) proves against the current head size — unchanged behavior.
func TestTreeInclusion_DefaultsToHeadSize(t *testing.T) {
	rec, cap := serveInclusion(t, 1000, "/v1/tree/inclusion/42")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if cap.gotTreeSize != 1000 {
		t.Errorf("default tree_size = %d, want head size 1000", cap.gotTreeSize)
	}
}

// ?tree_size=N (valid: seq < N <= head) pins the proof to N — the horizon case.
func TestTreeInclusion_HonorsTreeSizeParam(t *testing.T) {
	rec, cap := serveInclusion(t, 1000, "/v1/tree/inclusion/42?tree_size=500")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if cap.gotTreeSize != 500 {
		t.Errorf("tree_size = %d, want pinned 500 (the cosigned horizon)", cap.gotTreeSize)
	}
	// Sanity: the response echoes the pinned size.
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := fmt.Sprintf("%v", body["tree_size"]); got != "500" {
		t.Errorf("response tree_size = %s, want 500", got)
	}
}

// tree_size > head is rejected (cannot prove against a future size).
func TestTreeInclusion_TreeSizeBeyondHeadRejected(t *testing.T) {
	rec, _ := serveInclusion(t, 1000, "/v1/tree/inclusion/42?tree_size=2000")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (tree_size > head)", rec.Code)
	}
}

// tree_size=0 and non-numeric are rejected.
func TestTreeInclusion_TreeSizeInvalidRejected(t *testing.T) {
	for _, bad := range []string{"0", "abc", "-1"} {
		rec, _ := serveInclusion(t, 1000, "/v1/tree/inclusion/42?tree_size="+bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("tree_size=%q: status = %d, want 400", bad, rec.Code)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// PG-off read front (1.3e): when TreeHeadStore.Latest is unavailable, the
// default/maximum provable size comes from the cosigned horizon (object
// store) instead of Postgres — the inclusion surface stays up during an
// outage. With NO horizon configured the same outage is a 503: that pair is
// the +/- guard.
// ─────────────────────────────────────────────────────────────────────

// erroringHeadFetcher simulates Postgres being unavailable.
type erroringHeadFetcher struct{}

func (erroringHeadFetcher) Latest(_ context.Context) (*apitypes.CosignedTreeHead, error) {
	return nil, errors.New("postgres unreachable")
}
func (erroringHeadFetcher) GetBySize(_ context.Context, _ uint64) (*apitypes.CosignedTreeHead, error) {
	return nil, errors.New("postgres unreachable")
}

// servePGOffInclusion wires the handler with PG down (Latest errors) and an
// optional cosigned horizon of horizonSize (0 ⇒ no horizon configured).
func servePGOffInclusion(t *testing.T, horizonSize uint64, target string) (*httptest.ResponseRecorder, *captureInclusion) {
	t.Helper()
	cap := &captureInclusion{}
	deps := &TreeDeps{TreeHeadStore: erroringHeadFetcher{}, Inclusion: cap}
	if horizonSize > 0 {
		deps.Horizon = fakeHorizon{head: &types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: horizonSize}}}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", NewTreeInclusionHandler(deps))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec, cap
}

// + case: with a horizon, the default proof size is the horizon size.
func TestTreeInclusion_PGOff_DefaultsToHorizonSize(t *testing.T) {
	rec, cap := servePGOffInclusion(t, 800, "/v1/tree/inclusion/42")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (horizon fallback); body=%s", rec.Code, rec.Body.String())
	}
	if cap.gotTreeSize != 800 {
		t.Errorf("default tree_size = %d, want horizon size 800", cap.gotTreeSize)
	}
}

// PG-off: ?tree_size=N is bounded by the horizon, not the unavailable head.
func TestTreeInclusion_PGOff_HonorsTreeSizeWithinHorizon(t *testing.T) {
	rec, cap := servePGOffInclusion(t, 800, "/v1/tree/inclusion/42?tree_size=500")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if cap.gotTreeSize != 500 {
		t.Errorf("tree_size = %d, want pinned 500", cap.gotTreeSize)
	}
}

func TestTreeInclusion_PGOff_TreeSizeBeyondHorizonRejected(t *testing.T) {
	rec, _ := servePGOffInclusion(t, 800, "/v1/tree/inclusion/42?tree_size=900")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (tree_size > horizon)", rec.Code)
	}
}

// - case: PG down AND no horizon configured → 503 (nothing to fall back to).
func TestTreeInclusion_PGOff_NoHorizon_Unavailable(t *testing.T) {
	rec, _ := servePGOffInclusion(t, 0, "/v1/tree/inclusion/42")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (PG down, no horizon)", rec.Code)
	}
}
