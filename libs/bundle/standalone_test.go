package bundle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
)

// newTestGather points a gather at srv with a fixed seq + smt key.
func newTestGather(t *testing.T, srv *httptest.Server, seq uint64) *StandaloneLedgerGather {
	t.Helper()
	client, err := clitools.NewLedgerClient(srv.URL, "did:web:gather.test")
	if err != nil {
		t.Fatalf("NewLedgerClient: %v", err)
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	g, err := NewStandaloneLedgerGather(client, srv.URL, srv.Client(),
		&network.BootstrapDocument{NetworkName: "gather-test"}, 2, seq, key)
	if err != nil {
		t.Fatalf("NewStandaloneLedgerGather: %v", err)
	}
	return g
}

// FetchSMTProof hits /v1/smt/proof/{key}?smt_root= and returns the parsed
// membership proof; a non-membership response is rejected (the entry must be present).
func TestGather_FetchSMTProof(t *testing.T) {
	want := types.SMTProof{
		TerminalKind: types.SMTTerminalLeaf,
		TerminalLeaf: &types.SMTLeaf{Key: [32]byte{0xAB}},
	}
	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "membership", "proof": want})
	}))
	defer srv.Close()

	g := newTestGather(t, srv, 7)
	var root [32]byte
	root[0] = 0xEE
	got, err := g.FetchSMTProof(context.Background(), 7, root)
	if err != nil {
		t.Fatalf("FetchSMTProof: %v", err)
	}
	if got.TerminalLeaf == nil || got.TerminalLeaf.Key != [32]byte{0xAB} {
		t.Errorf("parsed proof mismatch: %+v", got)
	}
	// The request carries the entry's SMT key and the as-of smt_root.
	if !strings.Contains(gotURL, "/v1/smt/proof/0102030405") || !strings.Contains(gotURL, "smt_root=ee00") {
		t.Errorf("URL = %q, want key + smt_root anchored", gotURL)
	}
}

// A non-membership SMT response is rejected (the target entry must be present).
func TestGather_FetchSMTProof_NonMembership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "non_membership", "proof": types.SMTProof{}})
	}))
	defer srv.Close()
	g := newTestGather(t, srv, 7)
	if _, err := g.FetchSMTProof(context.Background(), 7, [32]byte{}); err == nil {
		t.Fatal("non-membership proof must be rejected")
	}
}

// FetchSection("receipt_proof") hits /v1/receipt/proof/{seq} and returns the
// receipt_proof section verbatim.
func TestGather_FetchSection_Receipt(t *testing.T) {
	section := json.RawMessage(`{"position":{"log_did":"did:web:gather.test","sequence":7},"receipt_hash":"ab","leaf_index":0,"leaf_count":1,"audit_path":[]}`)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"receipt_proof": section})
	}))
	defer srv.Close()

	g := newTestGather(t, srv, 7)
	got, err := g.FetchSection(context.Background(), "receipt_proof", 100)
	if err != nil {
		t.Fatalf("FetchSection: %v", err)
	}
	if gotPath != "/v1/receipt/proof/7" {
		t.Errorf("path = %q, want /v1/receipt/proof/7", gotPath)
	}
	var pos struct {
		Position struct {
			Sequence uint64 `json:"sequence"`
		} `json:"position"`
	}
	if err := json.Unmarshal(got, &pos); err != nil || pos.Position.Sequence != 7 {
		t.Errorf("receipt_proof section not returned verbatim: %s (%v)", got, err)
	}
}

// Sections that are null without any HTTP in a default (unconfigured, genesis-only)
// gather: a still-unimplemented section, an unconfigured governance chain, and the
// signer-rotation chain with no rotation schema set. (schema_chain and
// burn_attestation are excluded — they always fetch from the ledger, so they are
// exercised by their own tests / the e2e, not here.)
func TestGather_FetchSection_UnsupportedNull(t *testing.T) {
	g := newTestGather(t, httptest.NewServer(http.NotFoundHandler()), 7)
	for _, name := range []string{"signature_policy_chain", "cross_log_anchors", "signer_rotation_chain"} {
		got, err := g.FetchSection(context.Background(), name, 100)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if got != nil {
			t.Errorf("%s: want null, got %s", name, got)
		}
	}
}

// FetchGenesisBootstrap returns the configured doc + quorum, never the SDK's
// mutated copy.
func TestGather_FetchGenesisBootstrap(t *testing.T) {
	g := newTestGather(t, httptest.NewServer(http.NotFoundHandler()), 7)
	doc, k, err := g.FetchGenesisBootstrap(context.Background())
	if err != nil || doc == nil {
		t.Fatalf("FetchGenesisBootstrap: %v", err)
	}
	if k != 2 || doc.NetworkName != "gather-test" {
		t.Errorf("got K=%d name=%q, want 2 / gather-test", k, doc.NetworkName)
	}
	doc.NetworkName = "mutated" // must not affect the gather's configured doc
	doc2, _, _ := g.FetchGenesisBootstrap(context.Background())
	if doc2.NetworkName != "gather-test" {
		t.Error("FetchGenesisBootstrap returned a shared (mutable) document")
	}
}
