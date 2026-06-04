/*
FILE PATH: api/horizon_test.go

Tests for the serveable-horizon read front:

  - NewCosignedCheckpointHandler (GET /v1/tree/horizon): serves the published
    CosignedTreeHead verbatim; 503 before first publish; 503 on nil backend.
  - tileBackendHorizon.ReadHorizon: round-trips the published bytes and parsed
    head; propagates os.ErrNotExist (pre-genesis).
  - NewSMTProofHandler anchored on the horizon: proofs are generated as-of the
    cosigned SMTRoot, the checkpoint is bundled additively, "type" is read off
    the proof terminal, and the fail-closed error mapping holds
    (own-horizon-root-unknown ⇒ 500, client-root-unknown ⇒ 404,
    horizon-missing ⇒ 503). Legacy live-root serving still works when no
    horizon is wired.

Reuses stubTileBackend + quietLogger from tile_handler_test.go (same package).
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// fakeHorizon is an injectable HorizonReader for the proof-handler tests.
type fakeHorizon struct {
	head *types.CosignedTreeHead
	raw  []byte
	err  error
}

func (f fakeHorizon) ReadHorizon(context.Context) (*types.CosignedTreeHead, []byte, error) {
	return f.head, f.raw, f.err
}

// ── GET /v1/tree/horizon ────────────────────────────────────────

func TestCosignedCheckpointHandler_ServesPublishedHead(t *testing.T) {
	head := &types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: [32]byte{0xAB}, TreeSize: 7}}
	raw, _ := json.Marshal(types.FromCosignedTreeHead(*head)) // the exact published (wire-shape) bytes the handler serves verbatim
	h := NewCosignedCheckpointHandler(fakeHorizon{head: head, raw: raw}, quietLogger())

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/v1/tree/horizon", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Body.Bytes(); string(got) != string(raw) {
		t.Errorf("body = %q, want the exact published bytes %q", got, raw)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc == "" {
		t.Errorf("Cache-Control not set (CDN-frontable expected)")
	}
	if et := rr.Header().Get("ETag"); et != `"7"` {
		t.Errorf("ETag = %q, want \"7\" (tree_size, for CDN revalidation)", et)
	}
}

func TestCosignedCheckpointHandler_NotYetPublished(t *testing.T) {
	// Pre-genesis: the horizon read returns os.ErrNotExist → 503 (not a cacheable
	// 404, so a CDN edge never pins "no checkpoint").
	h := NewCosignedCheckpointHandler(fakeHorizon{err: os.ErrNotExist}, quietLogger())

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/v1/tree/horizon", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (pre-genesis)", rr.Code)
	}
}

func TestCosignedCheckpointHandler_NilBackend(t *testing.T) {
	h := NewCosignedCheckpointHandler(nil, quietLogger())
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/v1/tree/horizon", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (nil backend)", rr.Code)
	}
}

func TestTileBackendHorizon_ReadHorizon(t *testing.T) {
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{
		SMTRoot:  [32]byte{0xAB, 0xCD},
		TreeSize: 42,
	}}
	raw, _ := json.Marshal(types.FromCosignedTreeHead(head)) // wire shape, as the builder publishes
	backend := &stubTileBackend{tiles: map[string][]byte{cosignedCheckpointObject: raw}}

	hr := NewTileBackendHorizon(backend)
	got, gotRaw, err := hr.ReadHorizon(context.Background())
	if err != nil {
		t.Fatalf("ReadHorizon: %v", err)
	}
	if got.SMTRoot != head.SMTRoot || got.TreeSize != 42 {
		t.Errorf("parsed head = %+v, want SMTRoot=%x TreeSize=42", got.TreeHead, head.SMTRoot)
	}
	if string(gotRaw) != string(raw) {
		t.Errorf("raw bytes not round-tripped")
	}

	// Pre-genesis: os.ErrNotExist propagates verbatim.
	if _, _, err := NewTileBackendHorizon(&stubTileBackend{}).ReadHorizon(context.Background()); !os.IsNotExist(err) {
		t.Errorf("absent horizon err = %v, want os.ErrNotExist", err)
	}
}

// ── GET /v1/smt/proof/{key} anchored on the horizon ──────────────────────

// singleLeafTree builds an in-memory SMT holding exactly `key`, returns the
// tree, its in-mem leaf store, and the committed root.
func singleLeafTree(t *testing.T, key [32]byte) (*smt.Tree, *smt.InMemoryLeafStore, [32]byte) {
	t.Helper()
	leaves := smt.NewInMemoryLeafStore()
	nodes := smt.NewInMemoryNodeStore()
	tree := smt.NewTree(leaves, nodes)
	pos := types.LogPosition{LogDID: "did:web:test", Sequence: 1}
	if err := tree.SetLeaf(context.Background(), key, types.SMTLeaf{Key: key, OriginTip: pos, AuthorityTip: pos}); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	root, err := tree.Root(context.Background())
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	return tree, leaves, root
}

func doProof(t *testing.T, deps *SMTDeps, key [32]byte, query string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewSMTProofHandler(deps)
	url := "/v1/smt/proof/" + hex.EncodeToString(key[:]) + query
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetPathValue("key", hex.EncodeToString(key[:]))
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func TestSMTProof_AnchorsOnHorizon_MembershipAndBundle(t *testing.T) {
	key := [32]byte{0x01, 0x02, 0x03}
	tree, leaves, root := singleLeafTree(t, key)
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: root, TreeSize: 1}}
	raw, _ := json.Marshal(types.FromCosignedTreeHead(head))

	deps := &SMTDeps{
		Tree:      tree,
		LeafStore: leaves,
		Logger:    quietLogger(),
		Horizon:   fakeHorizon{head: &head, raw: raw},
	}

	rr := doProof(t, deps, key, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if m["type"] != "membership" {
		t.Errorf("type = %v, want membership", m["type"])
	}
	if _, ok := m["checkpoint"]; !ok {
		t.Errorf("response missing bundled checkpoint")
	}
	if _, ok := m["proof"]; !ok {
		t.Errorf("response missing proof")
	}
}

func TestSMTProof_AnchorsOnHorizon_NonMembership(t *testing.T) {
	present := [32]byte{0x01}
	absent := [32]byte{0x99}
	tree, leaves, root := singleLeafTree(t, present)
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: root, TreeSize: 1}}
	raw, _ := json.Marshal(types.FromCosignedTreeHead(head))
	deps := &SMTDeps{Tree: tree, LeafStore: leaves, Logger: quietLogger(), Horizon: fakeHorizon{head: &head, raw: raw}}

	rr := doProof(t, deps, absent, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["type"] != "non_membership" {
		t.Errorf("type = %v, want non_membership", m["type"])
	}
}

func TestSMTProof_HorizonRootUnknown_Is500(t *testing.T) {
	key := [32]byte{0x01}
	tree, leaves, _ := singleLeafTree(t, key)
	// Horizon advertises a root the node store does not hold → the publish/
	// tile-durability invariant is violated → corruption, not catching-up.
	bogus := [32]byte{0xFF, 0xFF, 0xFF}
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: bogus, TreeSize: 1}}
	raw, _ := json.Marshal(types.FromCosignedTreeHead(head))
	deps := &SMTDeps{Tree: tree, LeafStore: leaves, Logger: quietLogger(), Horizon: fakeHorizon{head: &head, raw: raw}}

	rr := doProof(t, deps, key, "")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (anchored own-horizon root unknown)", rr.Code)
	}
}

func TestSMTProof_ExplicitUnknownRoot_Is404(t *testing.T) {
	key := [32]byte{0x01}
	tree, leaves, _ := singleLeafTree(t, key)
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: [32]byte{0x01}, TreeSize: 1}}
	raw, _ := json.Marshal(types.FromCosignedTreeHead(head))
	deps := &SMTDeps{Tree: tree, LeafStore: leaves, Logger: quietLogger(), Horizon: fakeHorizon{head: &head, raw: raw}}

	// Client asks for a root the store does not retain → 404 (client-class),
	// distinct from the operator's own horizon being corrupt (500).
	bogusHex := hex.EncodeToString([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	})
	rr := doProof(t, deps, key, "?smt_root="+bogusHex)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (client-supplied unknown root)", rr.Code)
	}
}

func TestSMTProof_HorizonMissing_Is503(t *testing.T) {
	key := [32]byte{0x01}
	tree, leaves, _ := singleLeafTree(t, key)
	deps := &SMTDeps{Tree: tree, LeafStore: leaves, Logger: quietLogger(), Horizon: fakeHorizon{err: os.ErrNotExist}}

	rr := doProof(t, deps, key, "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (pre-genesis, no checkpoint)", rr.Code)
	}
}

func TestSMTProof_LegacyLiveRoot_NoHorizon(t *testing.T) {
	key := [32]byte{0x01}
	tree, leaves, _ := singleLeafTree(t, key)
	// No Horizon wired → legacy live-root path; membership decided by the
	// LeafStore pre-check; no bundled checkpoint.
	deps := &SMTDeps{Tree: tree, LeafStore: leaves, Logger: quietLogger()}

	rr := doProof(t, deps, key, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["type"] != "membership" {
		t.Errorf("type = %v, want membership", m["type"])
	}
	if _, ok := m["checkpoint"]; ok {
		t.Errorf("legacy path must not bundle a checkpoint")
	}
}
