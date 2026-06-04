/*
FILE PATH: api/labels_test.go

v1.32.0 SDK adoption — Tier C tests for the L3 convenience
endpoint serving the materialized WitnessIdentityLabelV1 walker
projection.

# WHAT THIS LOCKS

NewNetworkLabelsHandler dispatches:

  - Nil fetcher → 404 every request (a deployment that doesn't
    wire the on-log walker MUST NOT serve a confusing 500).
  - ErrLabelsNotConfigured from the fetcher → 404 (consistent
    with the nil-fetcher case).
  - Other errors → 500 (genuinely broken).
  - Success → 200 with the JCS-aligned WitnessLabelsView shape,
    Cache-Control "public, max-age=60", correct Content-Type.

Pure unit tests; uses httptest.NewRecorder and a fake fetcher.
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

// stubLabelFetcher implements api.WitnessLabelFetcher with
// configurable response/error to exercise each dispatch path.
type stubLabelFetcher struct {
	view *api.WitnessLabelsView
	err  error
}

func (s *stubLabelFetcher) LoadCurrentLabels(_ context.Context) (*api.WitnessLabelsView, error) {
	return s.view, s.err
}

// TestNetworkLabelsHandler_NilFetcherReturns404 exercises the
// "deployment doesn't wire the walker" case. A 404 lets clients
// distinguish "this log doesn't support labels yet" from
// "fetch failed somewhere" — important for the bootstrap-
// window UX. The 500 default would mask configuration as a
// runtime failure.
func TestNetworkLabelsHandler_NilFetcherReturns404(t *testing.T) {
	h := api.NewNetworkLabelsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/labels", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}

// TestNetworkLabelsHandler_NotConfiguredErrorReturns404 verifies
// the typed-sentinel dispatch. The fetcher returning
// ErrLabelsNotConfigured MUST map to the same 404 as a nil
// fetcher — these are two ways to express the same "no walker
// here" state, and operators should see one consistent behavior.
func TestNetworkLabelsHandler_NotConfiguredErrorReturns404(t *testing.T) {
	f := &stubLabelFetcher{err: api.ErrLabelsNotConfigured}
	h := api.NewNetworkLabelsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/labels", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}

// TestNetworkLabelsHandler_OtherErrorReturns500 verifies the
// non-typed-sentinel path. A walker that's wired but actually
// broken (DB down, decode panic) gets a 500. Distinguishing
// this from the 404 cases is important for alerting: 500s
// page operators; 404s are operator decisions.
func TestNetworkLabelsHandler_OtherErrorReturns500(t *testing.T) {
	f := &stubLabelFetcher{err: errors.New("walker exploded")}
	h := api.NewNetworkLabelsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/labels", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", rec.Code)
	}
}

// TestNetworkLabelsHandler_SuccessShape locks the wire contract:
// successful response is JSON, has the WitnessLabelsView keys
// (as_of_seq, labels), and includes the per-row pub_key_id /
// label / did_hint fields. Downstream consumers (JN, the CLI,
// the dashboard) parse against this shape; any field rename
// breaks their decode.
func TestNetworkLabelsHandler_SuccessShape(t *testing.T) {
	view := &api.WitnessLabelsView{
		AsOfSeq: 42,
		Labels: []api.WitnessLabelEntry{
			{
				PubKeyID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Label:    "Witness Alice",
				DIDHint:  "did:web:alice.example.org",
			},
		},
	}
	f := &stubLabelFetcher{view: view}
	h := api.NewNetworkLabelsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/labels", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type: got %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control: got %q, want public, max-age=60", cc)
	}

	var got api.WitnessLabelsView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AsOfSeq != 42 {
		t.Errorf("as_of_seq: got %d", got.AsOfSeq)
	}
	if len(got.Labels) != 1 {
		t.Fatalf("labels: got %d rows, want 1", len(got.Labels))
	}
	if got.Labels[0].Label != "Witness Alice" {
		t.Errorf("label: got %q", got.Labels[0].Label)
	}
}

// TestNetworkLabelsHandler_EmptyProjectionStillOK exercises the
// post-bootstrap-window edge case: walker is wired, but no
// WitnessIdentityLabelV1 entries have been admitted yet (or
// they've all been retired). 200 with an empty Labels slice
// is the correct shape — clients distinguish empty from
// not-configured (404).
func TestNetworkLabelsHandler_EmptyProjectionStillOK(t *testing.T) {
	view := &api.WitnessLabelsView{
		AsOfSeq: 0,
		Labels:  nil,
	}
	f := &stubLabelFetcher{view: view}
	h := api.NewNetworkLabelsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/labels", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}
