// FILE PATH: libs/clitools/ledger_client_proofs_test.go
//
// Tests for the proof + horizon wrappers (ledger_client.go scan-rebuild
// foundation): InclusionProof, ConsistencyProof, Horizon. Each serves the exact
// ledger endpoint JSON from an httptest server and asserts correct decode +
// fail-closed error handling.
package clitools

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/types"
)

func hex32(b byte) string { return strings.Repeat(hexByte(b), 32) }
func hexByte(b byte) string {
	return hex.EncodeToString([]byte{b})
}

// TestLedgerClient_InclusionProof_Decodes serves a {leaf_index,tree_size,hashes}
// body and checks the MerkleProof is decoded with LeafHash left zero (the caller
// binds it) and siblings hex-decoded to [32]byte.
func TestLedgerClient_InclusionProof_Decodes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", func(w http.ResponseWriter, r *http.Request) {
		// echo the requested tree_size so the test can assert pinning too
		ts := r.URL.Query().Get("tree_size")
		if ts == "" {
			ts = "1000"
		}
		_, _ = w.Write([]byte(`{"leaf_index":42,"tree_size":` + ts + `,"hashes":["` +
			hex32(0xAA) + `","` + hex32(0xBB) + `"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustLedgerClient(t, srv.URL, testLogDID)
	proof, err := c.InclusionProof(42)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if proof.LeafPosition != 42 {
		t.Errorf("LeafPosition = %d, want 42", proof.LeafPosition)
	}
	if proof.TreeSize != 1000 {
		t.Errorf("TreeSize = %d, want 1000", proof.TreeSize)
	}
	if len(proof.Siblings) != 2 {
		t.Fatalf("Siblings = %d, want 2", len(proof.Siblings))
	}
	if proof.Siblings[0][0] != 0xAA || proof.Siblings[1][0] != 0xBB {
		t.Errorf("siblings decoded wrong: %x %x", proof.Siblings[0][:2], proof.Siblings[1][:2])
	}
	var zero [32]byte
	if proof.LeafHash != zero {
		t.Error("LeafHash must be left zero (caller binds it)")
	}
}

// TestLedgerClient_InclusionProof_RejectsBadSibling: a non-32-byte / non-hex
// sibling fails closed.
func TestLedgerClient_InclusionProof_RejectsBadSibling(t *testing.T) {
	for _, bad := range []string{`"zz"`, `"` + hex32(0xAA) + hexByte(0x01) + `"`} { // non-hex, 33-byte
		mux := http.NewServeMux()
		mux.HandleFunc("GET /v1/tree/inclusion/{seq}", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"leaf_index":1,"tree_size":10,"hashes":[` + bad + `]}`))
		})
		srv := httptest.NewServer(mux)
		c := mustLedgerClient(t, srv.URL, testLogDID)
		if _, err := c.InclusionProof(1); err == nil {
			t.Errorf("bad sibling %s accepted; want error", bad)
		}
		srv.Close()
	}
}

// TestLedgerClient_InclusionProof_HTTPError: non-200 fails closed.
func TestLedgerClient_InclusionProof_HTTPError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := mustLedgerClient(t, srv.URL, testLogDID)
	if _, err := c.InclusionProof(1); err == nil {
		t.Error("HTTP 404 accepted; want error")
	}
}

// TestLedgerClient_ConsistencyProof_Decodes serves {hashes} and checks decode.
func TestLedgerClient_ConsistencyProof_Decodes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/consistency/{old}/{new}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"hashes":["` + hex32(0xCC) + `"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := mustLedgerClient(t, srv.URL, testLogDID)
	hashes, err := c.ConsistencyProof(100, 200)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}
	if len(hashes) != 1 || hashes[0][0] != 0xCC {
		t.Errorf("consistency hashes decoded wrong: %v", hashes)
	}
}

// TestLedgerClient_ConsistencyProof_EmptyOK: an empty hashes list (trivially
// consistent) decodes to an empty slice, not an error.
func TestLedgerClient_ConsistencyProof_EmptyOK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/consistency/{old}/{new}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"hashes":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := mustLedgerClient(t, srv.URL, testLogDID)
	hashes, err := c.ConsistencyProof(0, 200)
	if err != nil {
		t.Fatalf("ConsistencyProof(empty): %v", err)
	}
	if len(hashes) != 0 {
		t.Errorf("want empty consistency proof, got %d", len(hashes))
	}
}

// TestLedgerClient_Horizon_Decodes serves a real WireCosignedTreeHead (built via
// the SDK's own encoder) and checks Horizon() round-trips it to a
// CosignedTreeHead. Using FromCosignedTreeHead avoids hand-writing fragile wire
// JSON (which would test the test, not the client).
func TestLedgerClient_Horizon_Decodes(t *testing.T) {
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash:    fill32(0x11),
			SMTRoot:     fill32(0x22),
			ReceiptRoot: fill32(0x33),
			TreeSize:    777,
		},
		// no signatures needed: Horizon() only transports; the caller verifies.
	}
	wireBytes, err := json.Marshal(types.FromCosignedTreeHead(head))
	if err != nil {
		t.Fatalf("marshal wire head: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/horizon", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(wireBytes)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := mustLedgerClient(t, srv.URL, testLogDID)
	got, err := c.Horizon()
	if err != nil {
		t.Fatalf("Horizon: %v", err)
	}
	if got.TreeSize != 777 || got.RootHash != fill32(0x11) || got.SMTRoot != fill32(0x22) {
		t.Errorf("horizon decoded wrong: size=%d root=%x smt=%x", got.TreeSize, got.RootHash[:2], got.SMTRoot[:2])
	}
}

func fill32(b byte) [32]byte {
	var r [32]byte
	for i := range r {
		r[i] = b
	}
	return r
}

// TestLedgerClient_InclusionProofAtSize_SendsTreeSizeParam verifies the
// horizon-aligned variant passes ?tree_size=N (the param the scan-rebuild needs).
func TestLedgerClient_InclusionProofAtSize_SendsTreeSizeParam(t *testing.T) {
	var gotTreeSize string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", func(w http.ResponseWriter, r *http.Request) {
		gotTreeSize = r.URL.Query().Get("tree_size")
		_, _ = w.Write([]byte(`{"leaf_index":7,"tree_size":` + gotTreeSize + `,"hashes":["` + hex32(0xAA) + `"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := mustLedgerClient(t, srv.URL, testLogDID)
	proof, err := c.InclusionProofAtSize(7, 500)
	if err != nil {
		t.Fatalf("InclusionProofAtSize: %v", err)
	}
	if gotTreeSize != "500" {
		t.Errorf("server saw tree_size=%q, want 500", gotTreeSize)
	}
	if proof.TreeSize != 500 || proof.LeafPosition != 7 {
		t.Errorf("proof = {pos:%d size:%d}, want {7 500}", proof.LeafPosition, proof.TreeSize)
	}
}
