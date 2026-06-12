package cli

// submit_primitive_test.go — SubmitWireAndWait is the agnostic transport
// primitive (J7): POST /v1/entries → poll /v1/entries-hash/{hash} → sequence.
// The test drives it against a bare httptest ledger with only (client, URL,
// wire, token) — no bundle, no network identity, no domain type — which is the
// whole point: every direct-to-ledger tool composes THIS.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSubmitWireAndWait_PostThenPoll(t *testing.T) {
	const wantHash = "ab12"
	var gotAuth string
	var gotBody []byte
	pollCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/entries":
			gotAuth = r.Header.Get("Authorization")
			gotBody, _ = readAll(r)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"canonical_hash": wantHash})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/entries-hash/"+wantHash:
			pollCalls++
			if pollCalls < 2 { // first poll: still pending (no sequence_number)
				_ = json.NewEncoder(w).Encode(map[string]any{"state": "pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sequence_number": 42})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	seq, err := SubmitWireAndWait(context.Background(), srv.Client(), srv.URL, "tok-1",
		[]byte("signed-wire-bytes"), 5*time.Second)
	if err != nil {
		t.Fatalf("SubmitWireAndWait: %v", err)
	}
	if seq != 42 {
		t.Fatalf("seq = %d, want 42 (polled past the pending state)", seq)
	}
	if gotAuth != "Bearer tok-1" {
		t.Fatalf("token not sent as Bearer: %q", gotAuth)
	}
	if string(gotBody) != "signed-wire-bytes" {
		t.Fatalf("wire bytes altered in transit: %q", gotBody)
	}

	// The split halves compose to the same result: SubmitWire returns the
	// hash, WaitForSequence polls it to the sequence.
	pollCalls = 0
	gotHash, err := SubmitWire(context.Background(), srv.Client(), srv.URL, "tok-1", []byte("w"))
	if err != nil || gotHash != wantHash {
		t.Fatalf("SubmitWire: hash=%q err=%v", gotHash, err)
	}
	seq2, err := WaitForSequence(context.Background(), srv.Client(), srv.URL, gotHash, 5*time.Second)
	if err != nil || seq2 != 42 {
		t.Fatalf("WaitForSequence: seq=%d err=%v", seq2, err)
	}
	// trailing-slash URLs normalize (no //v1/entries).
	if _, err := SubmitWireAndWait(context.Background(), srv.Client(), srv.URL+"/", "",
		[]byte("x"), 5*time.Second); err != nil {
		t.Fatalf("trailing-slash base URL: %v", err)
	}
}

func TestSubmitWireAndWait_LedgerRejectionSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("admission gate-5 refusal"))
	}))
	defer srv.Close()

	_, err := SubmitWireAndWait(context.Background(), srv.Client(), srv.URL, "",
		[]byte("wire"), time.Second)
	if err == nil || !strings.Contains(err.Error(), "admission gate-5 refusal") {
		t.Fatalf("a non-202 must surface the ledger's verdict verbatim, got: %v", err)
	}
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}
