/*
FILE PATH: api/anchors_test.go

Tests for the Part II.1 /v1/network/anchors handler.
*/
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// staticChain wraps a fixed chain as the provider the re-rooted handler takes.
func staticChain(c WireAnchorChain) func(context.Context) (WireAnchorChain, error) {
	return func(context.Context) (WireAnchorChain, error) { return c, nil }
}

func TestNetworkAnchorsHandler_ServesChain(t *testing.T) {
	chain := WireAnchorChain{
		LogDID: "did:web:leaf.example",
		Hops: []WireAnchorChainEntry{
			{
				ParentLogDID:         "did:web:current-parent.example",
				WitnessSetHash:       strings.Repeat("ab", 32),
				LatestAnchorSeq:      42,
				LatestAnchorTreeSize: 1000,
			},
			{
				ParentLogDID:   "did:web:former-parent.example",
				WitnessSetHash: strings.Repeat("cd", 32),
				// LatestAnchorSeq + LatestAnchorTreeSize omitempty —
				// a former parent retired before the metadata was
				// captured.
			},
		},
	}
	h := NewNetworkAnchorsHandler(staticChain(chain))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/anchors", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var got WireAnchorChain
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.LogDID != chain.LogDID {
		t.Errorf("LogDID drift")
	}
	if len(got.Hops) != 2 {
		t.Fatalf("Hops len = %d, want 2", len(got.Hops))
	}
	if got.Hops[0].LatestAnchorSeq != 42 || got.Hops[0].LatestAnchorTreeSize != 1000 {
		t.Errorf("Hops[0] anchor metadata drift: %+v", got.Hops[0])
	}
	// Former-parent row carries zero anchor metadata — omitempty
	// must elide both fields from the JSON.
	bs, _ := json.Marshal(got.Hops[1])
	if strings.Contains(string(bs), `"latest_anchor_seq"`) ||
		strings.Contains(string(bs), `"latest_anchor_tree_size"`) {
		t.Errorf("former-parent row leaked zero anchor metadata: %s", bs)
	}
}

func TestNetworkAnchorsHandler_UnwiredReturns404(t *testing.T) {
	// nil provider = the handler is structurally unwired (read-only binary
	// with no confirmation store) — the only 404 left. An EMPTY chain is a
	// 200 now (RootEmptyHopsConfigured below): never-anchored is a state,
	// not a misconfiguration.
	h := NewNetworkAnchorsHandler(nil)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/anchors", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestNetworkAnchorsHandler_ProviderErrorReturns500(t *testing.T) {
	h := NewNetworkAnchorsHandler(func(context.Context) (WireAnchorChain, error) {
		return WireAnchorChain{}, errors.New("store down")
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/anchors", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (the chain is live state, not a file)", rec.Code)
	}
}

// A federation-root deployment with no parents serves an
// empty-hops chain — distinct from "not configured". The
// presence of LogDID toggles the configured/unconfigured branch.
func TestNetworkAnchorsHandler_RootEmptyHopsConfigured(t *testing.T) {
	chain := WireAnchorChain{LogDID: "did:web:root.example"}
	h := NewNetworkAnchorsHandler(staticChain(chain))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/anchors", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (root with empty hops is configured)", rec.Code)
	}
	body := rec.Body.String()
	// omitempty on Hops elides the empty slice from JSON.
	if strings.Contains(body, `"hops"`) {
		t.Errorf("empty hops slice should be omitted; body=%s", body)
	}
}
