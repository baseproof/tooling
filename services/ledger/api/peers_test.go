/*
FILE PATH: api/peers_test.go

Tests for the Part II.10 /v1/network/peers handler.

Scope:
  - Configured graph: handler returns 200 + JSON body matching the
    captured graph (round-trip).
  - Empty graph (no LEDGER_NETWORK_PEERS_FILE at boot): 404 with
    "not configured" — the endpoint is structurally unavailable
    rather than emitting a misleading empty document.
  - JSON shape: snake_case keys, hex-encoded byte arrays,
    omitempty on Parent/Root/HistoricalParents.
  - Cache-Control: public, max-age=300.
*/
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkPeersHandler_ServesConfiguredGraph(t *testing.T) {
	graph := WireFederationGraph{
		ThisLog: WireLogNode{
			LogDID:         "did:web:source.example",
			NetworkID:      strings.Repeat("aa", 32),
			WitnessSetHash: strings.Repeat("bb", 32),
			AdmissionURL:   "https://source.example/v1/entries",
		},
		Parent: &WireLogNode{
			LogDID:         "did:web:parent.example",
			NetworkID:      strings.Repeat("cc", 32),
			WitnessSetHash: strings.Repeat("dd", 32),
			AdmissionURL:   "https://parent.example/v1/entries",
		},
		Siblings: []WireLogNode{
			{
				LogDID:         "did:web:sibling.example",
				NetworkID:      strings.Repeat("ee", 32),
				WitnessSetHash: strings.Repeat("ff", 32),
			},
		},
		Root: &WireLogNode{
			LogDID:         "did:web:root.example",
			NetworkID:      strings.Repeat("11", 32),
			WitnessSetHash: strings.Repeat("22", 32),
		},
	}
	h := NewNetworkPeersHandler(graph)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/peers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want public, max-age=300", cc)
	}
	var got WireFederationGraph
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.ThisLog.LogDID != graph.ThisLog.LogDID {
		t.Errorf("ThisLog.LogDID = %q, want %q", got.ThisLog.LogDID, graph.ThisLog.LogDID)
	}
	if got.Parent == nil || got.Parent.LogDID != graph.Parent.LogDID {
		t.Errorf("Parent drift: %+v", got.Parent)
	}
	if len(got.Siblings) != 1 || got.Siblings[0].LogDID != graph.Siblings[0].LogDID {
		t.Errorf("Siblings drift: %+v", got.Siblings)
	}
	if got.Root == nil || got.Root.LogDID != graph.Root.LogDID {
		t.Errorf("Root drift: %+v", got.Root)
	}
}

func TestNetworkPeersHandler_UnconfiguredReturns404(t *testing.T) {
	// Empty graph → "federation graph not configured", 404.
	h := NewNetworkPeersHandler(WireFederationGraph{})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/peers", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "not configured") {
		t.Errorf("body = %q, want 'not configured'", body)
	}
}

func TestNetworkPeersHandler_OmitsEmptyOptionalFields(t *testing.T) {
	// A leaf log with no siblings, no historical parents — only
	// ThisLog + Parent + Root populated. The omitempty fields must
	// be absent from the JSON output.
	graph := WireFederationGraph{
		ThisLog: WireLogNode{
			LogDID:         "did:web:leaf.example",
			NetworkID:      strings.Repeat("00", 32),
			WitnessSetHash: strings.Repeat("00", 32),
		},
	}
	h := NewNetworkPeersHandler(graph)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/peers", nil))
	body := rec.Body.String()
	for _, absent := range []string{
		`"parent"`, `"siblings"`, `"root"`, `"historical_parents"`,
	} {
		if strings.Contains(body, absent) {
			t.Errorf("body unexpectedly contains %s; want omitempty: %s", absent, body)
		}
	}
}

func TestNetworkPeersHandler_HistoricalParentsEncoded(t *testing.T) {
	// A re-parented log emits its previous-parent history with
	// ActiveUntilSeq populated.
	graph := WireFederationGraph{
		ThisLog: WireLogNode{
			LogDID:         "did:web:re-parented.example",
			NetworkID:      strings.Repeat("00", 32),
			WitnessSetHash: strings.Repeat("00", 32),
		},
		HistoricalParents: []WireHistoricalParent{
			{
				ParentLogDID:   "did:web:old-parent.example",
				ActiveFromSeq:  0,
				ActiveUntilSeq: 12345,
				WitnessSetHash: strings.Repeat("ab", 32),
			},
		},
	}
	h := NewNetworkPeersHandler(graph)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/peers", nil))
	var got WireFederationGraph
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.HistoricalParents) != 1 {
		t.Fatalf("HistoricalParents len = %d, want 1", len(got.HistoricalParents))
	}
	if got.HistoricalParents[0].ActiveUntilSeq != 12345 {
		t.Errorf("ActiveUntilSeq = %d, want 12345", got.HistoricalParents[0].ActiveUntilSeq)
	}
}
