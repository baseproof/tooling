/*
FILE PATH: api/smt_root_test.go

Tests for GET /v1/smt/root (NewSMTRootHandler) — previously uncovered.

Phase 1 (proof-served-outside-Postgres) makes the read front serve the
witness-cosigned SMTRoot from the published horizon when no live RootState is
wired (the ledger-reader case). Before the fix, an unseeded reader tree fell
through to Tree.Root() == EmptyHash — a uselessly-empty, un-cosigned answer.

Resolution priority pinned here: RootState (live builder) → Horizon (cosigned,
PG-off read front) → Tree.Root() (dev/test legacy). Reuses fakeHorizon,
quietLogger, and singleLeafTree from the same package's tests.
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

// fakeRootState is an injectable SMTRootReader for the /v1/smt/root tests.
type fakeRootState struct {
	root [32]byte
	err  error
}

func (f fakeRootState) ReadRoot(context.Context) ([32]byte, error) { return f.root, f.err }

func doRoot(t *testing.T, deps *SMTDeps) *httptest.ResponseRecorder {
	t.Helper()
	h := NewSMTRootHandler(deps)
	req := httptest.NewRequest(http.MethodGet, "/v1/smt/root", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func decodeRoot(t *testing.T, rr *httptest.ResponseRecorder) [32]byte {
	t.Helper()
	var m struct {
		Root string `json:"root"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, rr.Body.String())
	}
	b, err := hex.DecodeString(m.Root)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad root hex %q: %v", m.Root, err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// emptyTreeDeps builds an SMTDeps over an unseeded in-memory tree (Root() ==
// EmptyHash) — the ledger-reader shape (no builder, no RootState).
func emptyTreeDeps() (*SMTDeps, *smt.InMemoryLeafStore) {
	leaves := smt.NewInMemoryLeafStore()
	tree := smt.NewTree(leaves, smt.NewInMemoryNodeStore())
	return &SMTDeps{Tree: tree, LeafStore: leaves, Logger: quietLogger()}, leaves
}

// TestSMTRoot_ServesCosignedRootFromHorizon is the +/- regression guard for the
// Phase-1 fix: a PG-off read front (no RootState, unseeded tree) must serve the
// cosigned horizon SMTRoot, NOT EmptyHash.
func TestSMTRoot_ServesCosignedRootFromHorizon(t *testing.T) {
	var cosigned [32]byte
	cosigned[0], cosigned[31] = 0xAB, 0xCD
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: cosigned, TreeSize: 9}}

	deps, _ := emptyTreeDeps()
	deps.Horizon = fakeHorizon{head: &head}

	rr := doRoot(t, deps)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	got := decodeRoot(t, rr)
	if got == smt.EmptyHash {
		t.Fatal("regressed: /v1/smt/root served EmptyHash instead of the cosigned horizon SMTRoot")
	}
	if got != cosigned {
		t.Fatalf("root = %x, want cosigned horizon SMTRoot %x", got, cosigned)
	}
}

// TestSMTRoot_RootStateTakesPrecedence pins the priority: a live RootState (the
// builder) wins over the horizon.
func TestSMTRoot_RootStateTakesPrecedence(t *testing.T) {
	var live, cosigned [32]byte
	live[0] = 0x11
	cosigned[0] = 0xAB
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: cosigned, TreeSize: 9}}

	deps, _ := emptyTreeDeps()
	deps.RootState = fakeRootState{root: live}
	deps.Horizon = fakeHorizon{head: &head}

	rr := doRoot(t, deps)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if got := decodeRoot(t, rr); got != live {
		t.Fatalf("root = %x, want live RootState %x (RootState must win over horizon)", got, live)
	}
}

// TestSMTRoot_HorizonNotYetPublished_503 — pre-genesis: the horizon read returns
// os.ErrNotExist ⇒ 503, never a bogus root.
func TestSMTRoot_HorizonNotYetPublished_503(t *testing.T) {
	deps, _ := emptyTreeDeps()
	deps.Horizon = fakeHorizon{err: os.ErrNotExist}

	rr := doRoot(t, deps)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (pre-genesis horizon)", rr.Code)
	}
}

// TestSMTRoot_LegacyTreeRoot_NoHorizon — dev/test with neither RootState nor
// Horizon still serves the live tree root (legacy path unchanged).
func TestSMTRoot_LegacyTreeRoot_NoHorizon(t *testing.T) {
	key := [32]byte{0x07}
	tree, leaves, root := singleLeafTree(t, key)
	deps := &SMTDeps{Tree: tree, LeafStore: leaves, Logger: quietLogger()}

	rr := doRoot(t, deps)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if got := decodeRoot(t, rr); got != root {
		t.Fatalf("root = %x, want live tree root %x", got, root)
	}
}
