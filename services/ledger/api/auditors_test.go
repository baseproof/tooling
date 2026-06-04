/*
FILE PATH: api/auditors_test.go

v1.32.0 SDK adoption — Tier C tests for the L3 convenience
endpoint serving the materialized AuditorRegistrationV1 walker
projection.

# WHAT THIS LOCKS

NewNetworkAuditorsHandler dispatches:

  - Nil fetcher → 404 every request.
  - ErrAuditorsNotConfigured from the fetcher → 404.
  - Other errors → 500.
  - Success → 200 with the JCS-aligned AuditorsView shape,
    Cache-Control "public, max-age=60", correct Content-Type.

EncodeAuditorPublicKey is a tiny pure-function helper whose
output is the wire format — the test pins it independently.

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

// stubAuditorFetcher implements api.AuditorRegistryFetcher with
// configurable response/error.
type stubAuditorFetcher struct {
	view *api.AuditorsView
	err  error
}

func (s *stubAuditorFetcher) LoadCurrentAuditors(_ context.Context) (*api.AuditorsView, error) {
	return s.view, s.err
}

// TestNetworkAuditorsHandler_NilFetcherReturns404 mirrors the
// labels-handler nil-fetcher contract. 404 is the deployment-
// not-wired signal; 500 would mask config as failure.
func TestNetworkAuditorsHandler_NilFetcherReturns404(t *testing.T) {
	h := api.NewNetworkAuditorsHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/auditors", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}

// TestNetworkAuditorsHandler_NotConfiguredErrorReturns404 exercises
// the typed-sentinel dispatch — ErrAuditorsNotConfigured collapses
// to the same 404 as a nil fetcher.
func TestNetworkAuditorsHandler_NotConfiguredErrorReturns404(t *testing.T) {
	f := &stubAuditorFetcher{err: api.ErrAuditorsNotConfigured}
	h := api.NewNetworkAuditorsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/auditors", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", rec.Code)
	}
}

// TestNetworkAuditorsHandler_OtherErrorReturns500 covers the
// genuinely-broken-walker path.
func TestNetworkAuditorsHandler_OtherErrorReturns500(t *testing.T) {
	f := &stubAuditorFetcher{err: errors.New("walker exploded")}
	h := api.NewNetworkAuditorsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/auditors", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", rec.Code)
	}
}

// TestNetworkAuditorsHandler_SuccessShape locks the wire contract.
// The auditor entry must contain auditor_did, public_key (hex),
// scheme_tag, findings_url, scope (comma-separated label form),
// and the response carries as_of_seq + auditors[]. Consumers
// (JN's auditor reconciler, the CLI) depend on this shape.
func TestNetworkAuditorsHandler_SuccessShape(t *testing.T) {
	view := &api.AuditorsView{
		AsOfSeq: 99,
		Auditors: []api.AuditorEntry{
			{
				AuditorDID:  "did:web:auditor-a.example.org",
				PublicKey:   "020000000000000000000000000000000000000000000000000000000000000000",
				SchemeTag:   1,
				FindingsURL: "https://auditor-a.example.org/v1/findings",
				Scope:       "equivocation,smt_replay",
			},
		},
	}
	f := &stubAuditorFetcher{view: view}
	h := api.NewNetworkAuditorsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/auditors", nil)
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

	var got api.AuditorsView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AsOfSeq != 99 {
		t.Errorf("as_of_seq: got %d", got.AsOfSeq)
	}
	if len(got.Auditors) != 1 {
		t.Fatalf("auditors: got %d rows, want 1", len(got.Auditors))
	}
	if got.Auditors[0].AuditorDID != "did:web:auditor-a.example.org" {
		t.Errorf("auditor_did: got %q", got.Auditors[0].AuditorDID)
	}
	if got.Auditors[0].Scope != "equivocation,smt_replay" {
		t.Errorf("scope: got %q, want comma-separated label form", got.Auditors[0].Scope)
	}
}

// TestEncodeAuditorPublicKey verifies the hex-encoding wire
// rule. Production callers in wire/wire.go's adapter depend on
// this function emitting the same encoding the SDK consumer
// expects. A regression to base64 / base58 would silently break
// every downstream auditor decode.
func TestEncodeAuditorPublicKey(t *testing.T) {
	got := api.EncodeAuditorPublicKey([]byte{0x02, 0xab, 0xcd})
	if got != "02abcd" {
		t.Errorf("EncodeAuditorPublicKey: got %q, want 02abcd", got)
	}
}

// TestEncodeAuditorPublicKey_Empty pins the zero-input behavior:
// empty bytes → empty string. Hex's encoding for nil is "" which
// matches; a regression that switched to a different encoder
// might surface a different empty representation.
func TestEncodeAuditorPublicKey_Empty(t *testing.T) {
	if got := api.EncodeAuditorPublicKey(nil); got != "" {
		t.Errorf("empty pub: got %q, want \"\"", got)
	}
}

// TestNetworkAuditorsHandler_EmptyProjectionStillOK mirrors the
// labels-handler edge: walker is wired, no auditors registered.
// 200 with empty Auditors slice — distinct from 404.
func TestNetworkAuditorsHandler_EmptyProjectionStillOK(t *testing.T) {
	f := &stubAuditorFetcher{view: &api.AuditorsView{AsOfSeq: 0}}
	h := api.NewNetworkAuditorsHandler(f)
	req := httptest.NewRequest(http.MethodGet, "/v1/network/auditors", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}
