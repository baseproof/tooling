/*
FILE PATH: api/witness_endpoints_test.go

v1.32.0 SDK adoption — Tier C tests for the L3 convenience
endpoint serving the materialized WitnessEndpointDeclarationV1
walker projection.

# WHAT THIS LOCKS

NewNetworkWitnessEndpointsHandler dispatches:

  - Nil fetcher → 404.
  - ErrWitnessEndpointsNotConfigured from the fetcher → 404.
  - Other errors → 500.
  - Success → 200 with the JCS-aligned WitnessEndpointsView
    shape, Cache-Control "public, max-age=60".

# WHY L3 MATTERS FOR L1

This endpoint serves the same records that drive L1's
HeadSync witness-URL snapshot. A consumer (JN's witness-
endpoint resolver, the CLI) can verify what the ledger
itself is consuming for cosignature collection. The wire-
shape lock here protects both surfaces.

Pure unit tests; uses httptest.NewRecorder.
*/
package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/tooling/services/ledger/api"
)

type stubEndpointFetcher struct {
	view *api.WitnessEndpointsView
	err  error
}

func (s *stubEndpointFetcher) LoadCurrentWitnessEndpoints(_ context.Context) (*api.WitnessEndpointsView, error) {
	return s.view, s.err
}

// TestNetworkWitnessEndpointsHandler_NilFetcherReturns404 mirrors
// the nil-fetcher posture across all three L3 endpoints.
func TestNetworkWitnessEndpointsHandler_NilFetcherReturns404(t *testing.T) {
	h := api.NewNetworkWitnessEndpointsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/witness-endpoints", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}

// TestNetworkWitnessEndpointsHandler_NotConfiguredErrorReturns404
// pins the typed-sentinel dispatch.
func TestNetworkWitnessEndpointsHandler_NotConfiguredErrorReturns404(t *testing.T) {
	f := &stubEndpointFetcher{err: api.ErrWitnessEndpointsNotConfigured}
	h := api.NewNetworkWitnessEndpointsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/witness-endpoints", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}

// TestNetworkWitnessEndpointsHandler_OtherErrorReturns500 covers
// the broken-walker path.
func TestNetworkWitnessEndpointsHandler_OtherErrorReturns500(t *testing.T) {
	f := &stubEndpointFetcher{err: errors.New("walker exploded")}
	h := api.NewNetworkWitnessEndpointsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/witness-endpoints", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", rec.Code)
	}
}

// TestNetworkWitnessEndpointsHandler_SuccessShape locks the wire
// contract. The map[string]string endpoints field must be a
// service-type → URL map keyed by W3C DID Core service types
// ("BaseproofWitness", "BaseproofGossip", etc.). A regression that
// flattened the structure or renamed keys would break every
// consumer's parser.
func TestNetworkWitnessEndpointsHandler_SuccessShape(t *testing.T) {
	view := &api.WitnessEndpointsView{
		AsOfSeq: 7,
		Witnesses: []api.WitnessEndpointEntry{
			{
				PubKeyID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Endpoints: map[string]string{
					"BaseproofWitness": "https://witness-a.example.org/v1/cosign",
					"BaseproofGossip":  "https://witness-a.example.org/v1/gossip",
				},
			},
		},
	}
	f := &stubEndpointFetcher{view: view}
	h := api.NewNetworkWitnessEndpointsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/witness-endpoints", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type: got %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control: got %q", cc)
	}

	var got api.WitnessEndpointsView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AsOfSeq != 7 {
		t.Errorf("as_of_seq: got %d", got.AsOfSeq)
	}
	if len(got.Witnesses) != 1 {
		t.Fatalf("witnesses: got %d rows, want 1", len(got.Witnesses))
	}
	w := got.Witnesses[0]
	if w.PubKeyID != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("pub_key_id: got %q", w.PubKeyID)
	}
	if w.Endpoints["BaseproofWitness"] != "https://witness-a.example.org/v1/cosign" {
		t.Errorf("BaseproofWitness endpoint: got %q",
			w.Endpoints["BaseproofWitness"])
	}
	if w.Endpoints["BaseproofGossip"] != "https://witness-a.example.org/v1/gossip" {
		t.Errorf("BaseproofGossip endpoint: got %q",
			w.Endpoints["BaseproofGossip"])
	}
}

// TestNetworkWitnessEndpointsHandler_EmptyProjectionStillOK mirrors
// the labels/auditors edge: 200 with empty Witnesses slice when
// no declarations have been admitted yet.
func TestNetworkWitnessEndpointsHandler_EmptyProjectionStillOK(t *testing.T) {
	f := &stubEndpointFetcher{view: &api.WitnessEndpointsView{AsOfSeq: 0}}
	h := api.NewNetworkWitnessEndpointsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/witness-endpoints", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}
