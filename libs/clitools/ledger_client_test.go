/*
FILE PATH: libs/clitools/ledger_client_test.go

DESCRIPTION:

	Wire-contract tests for the SDK-backed LedgerClient shim. Stands
	up an httptest server, exercises FetchEntry (→ /raw) and ScanFrom
	(→ /v1/query/scan + per-row /raw), and asserts:

	  - FetchEntry hits /v1/entries/{seq}/raw and reads X-Sequence /
	    X-Log-Time headers per the SDK's HTTPEntryFetcher contract.
	  - ScanFrom hits /v1/query/scan, parses the SDK-canonical
	    EntryResponse JSON, and back-fills CanonicalBytes via /raw.
	  - 404 from /raw returns (nil, nil) — the standard "not found" signal.
	  - ScanFrom without a logDID returns a clear error.
*/
package clitools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mustLedgerClient is a t.Helper wrapper around NewLedgerClient that
// fails the test on construction error. Used uniformly across this
// file so each test focuses on its actual assertion (the v1.26.0+
// (client, err) return shape is irrelevant to what we're verifying
// here).
func mustLedgerClient(t *testing.T, baseURL string, optionalLogDID ...string) *LedgerClient {
	t.Helper()
	c, err := NewLedgerClient(baseURL, optionalLogDID...)
	if err != nil {
		t.Fatalf("NewLedgerClient(%q): %v", baseURL, err)
	}
	return c
}

const testLogDID = "did:web:test.log"

// fakeLedger is an in-process httptest server that serves /raw and
// /v1/query/scan with the SDK-canonical wire shapes.
type fakeLedger struct {
	t           *testing.T
	rawCalls    int
	scanCalls   int
	storedBytes map[uint64][]byte
	storedTime  map[uint64]time.Time
}

func newFakeLedger(t *testing.T) (*httptest.Server, *fakeLedger) {
	t.Helper()
	op := &fakeLedger{
		t:           t,
		storedBytes: make(map[uint64][]byte),
		storedTime:  make(map[uint64]time.Time),
	}
	mux := http.NewServeMux()

	// SDK v0.7.75: HTTPEntryFetcher targets /v1/entries/{seq}/raw.
	// Response: 200 + application/octet-stream + raw wire bytes.
	// Headers: X-Sequence (uint64 decimal), X-Log-Time (RFC-3339Nano UTC).
	// The ledger stamps both per commit 8afc27b.
	mux.HandleFunc("GET /v1/entries/{seq}/raw", func(w http.ResponseWriter, r *http.Request) {
		op.rawCalls++
		var seq uint64
		if _, err := fmt.Sscanf(r.PathValue("seq"), "%d", &seq); err != nil {
			http.Error(w, "bad seq", http.StatusBadRequest)
			return
		}
		bytes, ok := op.storedBytes[seq]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Sequence", fmt.Sprintf("%d", seq))
		if t, ok := op.storedTime[seq]; ok && !t.IsZero() {
			w.Header().Set("X-Log-Time", t.UTC().Format(time.RFC3339Nano))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes)
	})

	mux.HandleFunc("GET /v1/query/scan", func(w http.ResponseWriter, r *http.Request) {
		op.scanCalls++
		var entries []scanEntryResponse
		for seq := range op.storedBytes {
			entries = append(entries, scanEntryResponse{
				SequenceNumber: seq,
				LogTime:        op.storedTime[seq].Format(time.RFC3339Nano),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanListResponse{Entries: entries, Count: len(entries)})
	})

	mux.HandleFunc("GET /v1/tree/head", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"size":42,"root":"abc"}`))
	})

	return httptest.NewServer(mux), op
}

// -------------------------------------------------------------------------
// 1) FetchEntry round-trip
// -------------------------------------------------------------------------

func TestLedgerClient_FetchEntry_HitsRawEndpoint(t *testing.T) {
	ctx := context.Background()
	srv, op := newFakeLedger(t)
	defer srv.Close()

	op.storedBytes[42] = []byte{0x01, 0x02, 0x03, 0x04}
	op.storedTime[42] = time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)

	c := mustLedgerClient(t, srv.URL, testLogDID)
	got, err := c.FetchEntry(ctx, 42)
	if err != nil {
		t.Fatalf("FetchEntry: %v", err)
	}
	if got == nil {
		t.Fatal("FetchEntry returned nil for present entry")
	}
	if got.Sequence != 42 {
		t.Errorf("Sequence = %d, want 42", got.Sequence)
	}
	wantHex := hex.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04})
	if got.CanonicalHex != wantHex {
		t.Errorf("CanonicalHex = %q, want %q", got.CanonicalHex, wantHex)
	}
	if got.LogTimeUnixMicro == 0 {
		t.Error("LogTimeUnixMicro should be populated from X-Log-Time")
	}
	if op.rawCalls != 1 {
		t.Errorf("/raw calls = %d, want 1", op.rawCalls)
	}
}

// -------------------------------------------------------------------------
// 2) FetchEntry 404 → (nil, nil)
// -------------------------------------------------------------------------

func TestLedgerClient_FetchEntry_NotFound_ReturnsNilNil(t *testing.T) {
	ctx := context.Background()
	srv, _ := newFakeLedger(t)
	defer srv.Close()

	c := mustLedgerClient(t, srv.URL, testLogDID)
	got, err := c.FetchEntry(ctx, 999)
	if err != nil {
		t.Fatalf("FetchEntry: %v", err)
	}
	if got != nil {
		t.Errorf("FetchEntry on missing seq = %+v, want nil", got)
	}
}

// -------------------------------------------------------------------------
// 3) ScanFrom hits /v1/query/scan + back-fills bytes per row
// -------------------------------------------------------------------------

func TestLedgerClient_ScanFrom_BackFillsCanonicalBytes(t *testing.T) {
	ctx := context.Background()
	srv, op := newFakeLedger(t)
	defer srv.Close()

	for seq, bytes := range map[uint64][]byte{
		10: {0xaa, 0xbb},
		11: {0xcc, 0xdd},
	} {
		op.storedBytes[seq] = bytes
		op.storedTime[seq] = time.Now().UTC()
	}

	c := mustLedgerClient(t, srv.URL, testLogDID)
	rows, err := c.ScanFrom(ctx, 0, 100)
	if err != nil {
		t.Fatalf("ScanFrom: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ScanFrom rows = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.CanonicalHex == "" {
			t.Errorf("seq %d has empty CanonicalHex (back-fill failed)", r.Sequence)
		}
	}
	if op.scanCalls != 1 {
		t.Errorf("scan calls = %d, want 1", op.scanCalls)
	}
	if op.rawCalls != 2 {
		t.Errorf("per-row /raw calls = %d, want 2", op.rawCalls)
	}
}

// -------------------------------------------------------------------------
// 4) ScanFrom without a logDID fails clearly
// -------------------------------------------------------------------------

func TestLedgerClient_ScanFrom_RequiresLogDID(t *testing.T) {
	ctx := context.Background()
	srv, _ := newFakeLedger(t)
	defer srv.Close()

	c := mustLedgerClient(t, srv.URL) // no logDID
	_, err := c.ScanFrom(ctx, 0, 10)
	if err == nil {
		t.Fatal("expected error for ScanFrom without logDID")
	}
	if !strings.Contains(err.Error(), "logDID") {
		t.Errorf("error %q should mention logDID", err.Error())
	}
}

// -------------------------------------------------------------------------
// 5) TreeHead passthrough
// -------------------------------------------------------------------------

func TestLedgerClient_TreeHead_Passthrough(t *testing.T) {
	srv, _ := newFakeLedger(t)
	defer srv.Close()

	c := mustLedgerClient(t, srv.URL, testLogDID)
	head, err := c.TreeHead()
	if err != nil {
		t.Fatalf("TreeHead: %v", err)
	}
	if head["size"] != float64(42) {
		t.Errorf("TreeHead size = %v, want 42", head["size"])
	}
}

// -------------------------------------------------------------------------
// 6) BUG #3 mirror: oversize tree-head + scan responses error out
// -------------------------------------------------------------------------

// TestLedgerClient_TreeHead_OversizeErrors pins the cap+1 overflow
// detection added .2. A 64 KiB+1024 tree-head response
// (ledger misbehavior — legitimate tree heads are ~hundreds of
// bytes) surfaces a typed error instead of being silently truncated
// to a parse failure with no attribution.
func TestLedgerClient_TreeHead_OversizeErrors(t *testing.T) {
	huge := make([]byte, (64<<10)+1024)
	for i := range huge {
		huge[i] = '"'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(huge)
	}))
	defer srv.Close()

	c := mustLedgerClient(t, srv.URL, testLogDID)
	_, err := c.TreeHead()
	if err == nil {
		t.Fatal("expected error for oversize tree-head response")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should mention size cap: %v", err)
	}
}

// TestLedgerClient_ScanFrom_OversizeErrors mirrors the same
// contract for /v1/query/scan. The cap matches the SDK's
// maxQueryResponseBytes (16 MiB). Build a small fake that returns
// junk past the cap; ScanFrom must surface "exceeds" error rather
// than truncate-and-parse-fail.
func TestLedgerClient_ScanFrom_OversizeErrors(t *testing.T) {
	ctx := context.Background()
	huge := make([]byte, maxScanResponseBytes+1024)
	for i := range huge {
		huge[i] = '"'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query/scan" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(huge)
	}))
	defer srv.Close()

	c := mustLedgerClient(t, srv.URL, testLogDID)
	_, err := c.ScanFrom(ctx, 0, 100)
	if err == nil {
		t.Fatal("expected error for oversize scan response")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error should mention size cap: %v", err)
	}
}
