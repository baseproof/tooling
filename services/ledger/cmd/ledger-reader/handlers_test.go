package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/api"
)

// fakeReaderHorizon is a minimal HorizonReader serving a fixed published head.
type fakeReaderHorizon struct {
	head *types.CosignedTreeHead
	raw  []byte
	err  error
}

func (f fakeReaderHorizon) ReadHorizon(context.Context) (*types.CosignedTreeHead, []byte, error) {
	return f.head, f.raw, f.err
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestReaderHandlers_WiresCosignedHorizonRoute is the +/- regression guard for
// 1.3b: a PG-off read front MUST mount GET /v1/tree/horizon. Before the fix,
// run() built api.Handlers{} with no Horizon, and server.go mounts that route
// iff handlers.Horizon != nil — so it was silently unmounted, leaving offline
// clients with no cosigned anchor to fetch (every v2 proof binds to it).
func TestReaderHandlers_WiresCosignedHorizonRoute(t *testing.T) {
	head := &types.CosignedTreeHead{TreeHead: types.TreeHead{SMTRoot: [32]byte{0xAB}, TreeSize: 7}}
	h := readerHandlers(
		&api.TreeDeps{Logger: discardLogger()},
		&api.SMTDeps{Logger: discardLogger()},
		&api.QueryDeps{Logger: discardLogger()},
		&api.EntryReadDeps{Logger: discardLogger()},
		&api.DerivationCommitmentDeps{Logger: discardLogger()},
		fakeReaderHorizon{head: head, raw: []byte(`{"tree_size":7}`)},
		&api.ReceiptDeps{Logger: discardLogger()},
		"did:baseproof:test",
		discardLogger(),
	)

	if h.Horizon == nil {
		t.Fatal("regressed: reader Handlers.Horizon is nil → GET /v1/tree/horizon would be unmounted")
	}

	// Functional: the wired handler actually serves the published cosigned head.
	req := httptest.NewRequest(http.MethodGet, "/v1/tree/horizon", nil)
	rr := httptest.NewRecorder()
	h.Horizon(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/tree/horizon = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
}

// TestReaderHandlers_HorizonPreGenesis_503 — the wired route fails closed (503)
// before the first cosigned checkpoint is published, never a bogus 200.
func TestReaderHandlers_HorizonPreGenesis_503(t *testing.T) {
	h := readerHandlers(
		&api.TreeDeps{Logger: discardLogger()},
		&api.SMTDeps{Logger: discardLogger()},
		&api.QueryDeps{Logger: discardLogger()},
		&api.EntryReadDeps{Logger: discardLogger()},
		&api.DerivationCommitmentDeps{Logger: discardLogger()},
		fakeReaderHorizon{err: os.ErrNotExist},
		&api.ReceiptDeps{Logger: discardLogger()},
		"did:baseproof:test",
		discardLogger(),
	)
	req := httptest.NewRequest(http.MethodGet, "/v1/tree/horizon", nil)
	rr := httptest.NewRecorder()
	h.Horizon(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-genesis GET /v1/tree/horizon = %d, want 503", rr.Code)
	}
}

// TestReaderHandlers_WiresReceiptAndBurnRoutes is the +/- regression guard for the
// PG-off receipt closure — the absolute source of the cold-proof failure. A read
// front MUST mount GET /v1/receipt/proof/{seq} AND GET /v1/burn: server.go mounts each
// iff the handler is non-nil, and the v2 proof's gather fetches BOTH unconditionally
// and fails closed on a 404 (log/bundle/v2_build.go). An unmounted route silently
// breaks every full offline proof against the reader. Burn observes no gossip here, so
// it must serve is_burned=false (NewGossipBurnSource handles the nil store).
func TestReaderHandlers_WiresReceiptAndBurnRoutes(t *testing.T) {
	h := readerHandlers(
		&api.TreeDeps{Logger: discardLogger()},
		&api.SMTDeps{Logger: discardLogger()},
		&api.QueryDeps{Logger: discardLogger()},
		&api.EntryReadDeps{Logger: discardLogger()},
		&api.DerivationCommitmentDeps{Logger: discardLogger()},
		fakeReaderHorizon{head: &types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 7}}},
		&api.ReceiptDeps{Logger: discardLogger()},
		"did:baseproof:test",
		discardLogger(),
	)
	if h.ReceiptProof == nil {
		t.Fatal("regressed: Handlers.ReceiptProof is nil → GET /v1/receipt/proof/{seq} unmounted → BuildStandalone fails on receipt_proof")
	}
	if h.Burn == nil {
		t.Fatal("regressed: Handlers.Burn is nil → GET /v1/burn unmounted → BuildStandalone fails on burn_attestation")
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/burn", nil)
	rr := httptest.NewRecorder()
	h.Burn(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/burn = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); !strings.Contains(body, "false") {
		t.Fatalf("GET /v1/burn body = %s, want is_burned=false", body)
	}
}
