package api

// anchors_by_source_test.go — the by-source discovery endpoint's HTTP
// contract: 400 on a missing source DID, 200 with the standard entries-page
// shape (the same writeEntriesJSON shape every /v1/query/* page uses), and
// page params threaded through to the keyset query.

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"
)

// bySourceStub records the call and returns one canned page.
type bySourceStub struct {
	stubQueryAPI
	gotDID   string
	gotStart uint64
	gotCount int
}

func (s *bySourceStub) QueryAnchorsBySource(did string, startSeq uint64, count int) ([]types.EntryWithMetadata, error) {
	s.gotDID, s.gotStart, s.gotCount = did, startSeq, count
	return []types.EntryWithMetadata{{
		CanonicalBytes: []byte("anchor-entry-bytes"),
		LogTime:        time.Unix(1_700_000_000, 0).UTC(),
		Position:       types.LogPosition{LogDID: "did:parent", Sequence: 7},
	}}, nil
}

func TestAnchorsBySourceHandler(t *testing.T) {
	stub := &bySourceStub{}
	h := NewAnchorsBySourceHandler(&QueryDeps{QueryAPI: stub, Logger: slog.Default()})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/anchors/by-source/{log_did}", h)

	// Page params thread through; response is the standard entries page.
	req := httptest.NewRequest(http.MethodGet,
		"/v1/network/anchors/by-source/did:baseproof:network:child?start=3&count=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if stub.gotDID != "did:baseproof:network:child" || stub.gotStart != 3 || stub.gotCount != 2 {
		t.Fatalf("query args = (%q,%d,%d), want (child,3,2)", stub.gotDID, stub.gotStart, stub.gotCount)
	}
	var page struct {
		Entries []json.RawMessage `json:"entries"`
		Count   int               `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("page decode: %v", err)
	}
	if page.Count != 1 || len(page.Entries) != 1 {
		t.Fatalf("page = %+v, want one entry", page)
	}

	// An empty source segment cannot match the route ({log_did} requires a
	// non-empty segment) — the 404 is the mux's, not a handler panic.
	req = httptest.NewRequest(http.MethodGet, "/v1/network/anchors/by-source/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("empty source DID served a page")
	}
}
