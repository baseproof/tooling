/*
FILE PATH: gossipnet/consistency_fetcher_test.go

Tests for FetchConsistencyProof — the narrow HTTP client that
retrieves a peer ledger's GET /v1/tree/consistency/{old}/{new}
and decodes it into [][]byte for sdkwitness.DetectHistoryRewrite.

Coverage:
  - Happy path: well-formed JSON + 32-byte hex hashes → [][]byte.
  - Non-200 status → error includes URL + status.
  - Malformed JSON → error.
  - Malformed hex in hashes → error with index.
  - Wrong-length hash (not 32 bytes) → error with index.
  - Oversized response body (DoS guard at MaxConsistencyProofBytes).
  - Nil client → error.
  - Empty baseURL → error.
  - URL composition correctness (path includes old + new sizes).
*/
package gossipnet

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubConsistencyServer returns an httptest.Server that responds
// to /v1/tree/consistency/{old}/{new} with the supplied body and
// status. capturedPath captures the request path so the test can
// assert URL composition.
func stubConsistencyServer(t *testing.T, body string, status int, capturedPath *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
}

// ─────────────────────────────────────────────────────────────────────
// Happy path
// ─────────────────────────────────────────────────────────────────────

func TestFetchConsistencyProof_HappyPath(t *testing.T) {
	// 32-byte hex hashes (two of them).
	h1 := strings.Repeat("aa", 32)
	h2 := strings.Repeat("bb", 32)
	body := fmt.Sprintf(`{"old_size":3,"new_size":7,"hashes":[%q,%q]}`, h1, h2)

	var capturedPath string
	srv := stubConsistencyServer(t, body, http.StatusOK, &capturedPath)
	defer srv.Close()

	got, err := FetchConsistencyProof(context.Background(),
		http.DefaultClient, srv.URL, 3, 7)
	if err != nil {
		t.Fatalf("FetchConsistencyProof: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(proof) = %d, want 2", len(got))
	}
	wantH1, _ := hex.DecodeString(h1)
	wantH2, _ := hex.DecodeString(h2)
	if !equalBytes(got[0], wantH1) || !equalBytes(got[1], wantH2) {
		t.Errorf("hash drift: got [%x %x]", got[0], got[1])
	}
	if capturedPath != "/v1/tree/consistency/3/7" {
		t.Errorf("captured path = %q, want /v1/tree/consistency/3/7", capturedPath)
	}
}

func TestFetchConsistencyProof_EmptyHashesIsValid(t *testing.T) {
	// Trivially-consistent case (old==new or old==0) → empty hashes
	// slice. The fetcher returns an empty [][]byte without error;
	// DetectHistoryRewrite then surfaces ErrSameTreeSize / etc.
	body := `{"old_size":5,"new_size":5,"hashes":[]}`
	srv := stubConsistencyServer(t, body, http.StatusOK, nil)
	defer srv.Close()

	got, err := FetchConsistencyProof(context.Background(),
		http.DefaultClient, srv.URL, 5, 5)
	if err != nil {
		t.Fatalf("FetchConsistencyProof: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len(proof) = %d, want 0", len(got))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Negative paths
// ─────────────────────────────────────────────────────────────────────

func TestFetchConsistencyProof_Non200Status(t *testing.T) {
	srv := stubConsistencyServer(t, "not found", http.StatusNotFound, nil)
	defer srv.Close()
	_, err := FetchConsistencyProof(context.Background(),
		http.DefaultClient, srv.URL, 1, 2)
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error %q should reference HTTP 404", err)
	}
}

func TestFetchConsistencyProof_MalformedJSON(t *testing.T) {
	srv := stubConsistencyServer(t, `{not json}`, http.StatusOK, nil)
	defer srv.Close()
	_, err := FetchConsistencyProof(context.Background(),
		http.DefaultClient, srv.URL, 1, 2)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFetchConsistencyProof_MalformedHexInHash(t *testing.T) {
	body := `{"old_size":1,"new_size":2,"hashes":["not_hex_zz" ,"aabb"]}`
	srv := stubConsistencyServer(t, body, http.StatusOK, nil)
	defer srv.Close()
	_, err := FetchConsistencyProof(context.Background(),
		http.DefaultClient, srv.URL, 1, 2)
	if err == nil {
		t.Fatal("expected hex decode error")
	}
	if !strings.Contains(err.Error(), "hash[0]") {
		t.Errorf("error %q should reference hash[0]", err)
	}
}

func TestFetchConsistencyProof_WrongLengthHash(t *testing.T) {
	// 16-byte hash, not 32.
	body := fmt.Sprintf(`{"old_size":1,"new_size":2,"hashes":[%q]}`,
		strings.Repeat("ab", 16))
	srv := stubConsistencyServer(t, body, http.StatusOK, nil)
	defer srv.Close()
	_, err := FetchConsistencyProof(context.Background(),
		http.DefaultClient, srv.URL, 1, 2)
	if err == nil {
		t.Fatal("expected length error")
	}
	if !strings.Contains(err.Error(), "hash[0]") ||
		!strings.Contains(err.Error(), "want 32") {
		t.Errorf("error %q should reference hash[0] + want 32", err)
	}
}

func TestFetchConsistencyProof_OversizedBody(t *testing.T) {
	// Construct a response that exceeds MaxConsistencyProofBytes.
	// Two megabyte body; the fetcher's LimitReader caps it at
	// MaxConsistencyProofBytes+1 → > cap → error.
	big := strings.Repeat("X", MaxConsistencyProofBytes+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()
	_, err := FetchConsistencyProof(context.Background(),
		http.DefaultClient, srv.URL, 1, 2)
	if err == nil {
		t.Fatal("expected DoS-guard error")
	}
	if !strings.Contains(err.Error(), "DoS guard") {
		t.Errorf("error %q should reference DoS guard", err)
	}
}

func TestFetchConsistencyProof_NilClient(t *testing.T) {
	_, err := FetchConsistencyProof(context.Background(), nil, "http://x", 1, 2)
	if err == nil {
		t.Fatal("expected nil client error")
	}
}

func TestFetchConsistencyProof_EmptyBaseURL(t *testing.T) {
	_, err := FetchConsistencyProof(context.Background(), http.DefaultClient, "", 1, 2)
	if err == nil {
		t.Fatal("expected empty baseURL error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
