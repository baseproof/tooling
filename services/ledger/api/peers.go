/*
FILE PATH:

	api/peers.go

DESCRIPTION:

	Part II.10 — GET /v1/network/peers.

	Returns the CURRENT-STATE federation index (this log's parent,
	siblings, root + historical parents). Consumed by the SDK's
	log/discover.FetchFederationGraph (plan §I.20a); the temporal
	walker uses the index to seed candidate paths between logs
	BEFORE confirming each hop against on-log anchor entries.

	The wire shape mirrors discover.FederationGraph but uses
	snake_case JSON keys + hex-encoded [32]byte fields — the same
	convention as /v1/tree/head, /v1/network/witnesses/*. The SDK's
	I.20 fetcher decodes either shape (the discover package owns
	the structured form; this file owns the wire form).

KEY ARCHITECTURAL DECISIONS:
  - PUBLIC, no auth. Same posture as /v1/log-info / /version.
  - CACHE: max-age=300. The federation topology changes on the
    timescale of re-parenting events (plan §I.20a's
    HistoricalParentEntry surface), which are rare but not
    indefinite. Five minutes is the staleness floor a consumer
    accepts; sub-five-minute changes propagate via the live
    fetch path of the SDK's I.20 walker.
  - CONFIG-DRIVEN. The federation graph is operator-supplied at
    boot via LEDGER_NETWORK_PEERS_FILE (JSON file with the wire
    shape). Future versions may project the graph from on-log
    federation_topology_v1 amendment entries; the handler signature
    stays the same.
  - SERVED VERBATIM. The handler does NOT recompute set_hash /
    network_id from authoritative sources at request time —
    the file is the authoritative wire shape, operator-validated
    at boot. Callers verify against on-log anchor entries (the
    walker's job), so a stale or stale-but-correct response is
    detectable downstream.
*/
package api

import (
	"encoding/json"
	"net/http"
)

// WireLogNode is the JSON wire shape for one log in the
// federation graph. Mirrors log/discover.LogNode but with
// snake_case keys + hex-encoded byte arrays (same convention as
// /v1/tree/head). The SDK's discover.LogNode embeds the
// structured Go types; this is the over-the-wire form.
type WireLogNode struct {
	LogDID         string `json:"log_did"`
	NetworkID      string `json:"network_id"`              // 64-char lowercase hex
	WitnessSetHash string `json:"witness_set_hash"`        // 64-char lowercase hex
	AdmissionURL   string `json:"admission_url,omitempty"` // optional
}

// WireHistoricalParent is the JSON wire shape for one historical
// parent entry. Mirrors log/discover.HistoricalParentEntry.
//
// ActiveUntilSeq == 0 means "still active" — encoded as omitempty
// so the absence is JCS-canonical (a re-parented network would
// emit a positive value, distinct from the still-active case).
type WireHistoricalParent struct {
	ParentLogDID   string `json:"parent_log_did"`
	ActiveFromSeq  uint64 `json:"active_from_seq"`
	ActiveUntilSeq uint64 `json:"active_until_seq,omitempty"`
	WitnessSetHash string `json:"witness_set_hash"`
}

// WireFederationGraph is the wire shape of the
// /v1/network/peers response. Mirrors
// log/discover.FederationGraph.
type WireFederationGraph struct {
	ThisLog           WireLogNode            `json:"this_log"`
	Parent            *WireLogNode           `json:"parent,omitempty"`
	Siblings          []WireLogNode          `json:"siblings,omitempty"`
	Root              *WireLogNode           `json:"root,omitempty"`
	HistoricalParents []WireHistoricalParent `json:"historical_parents,omitempty"`
}

// NewNetworkPeersHandler returns the GET /v1/network/peers handler.
// graph is captured at boot from LEDGER_NETWORK_PEERS_FILE; cmd/ledger
// is responsible for loading + validating the file before calling
// this constructor. A zero WireFederationGraph (graph.ThisLog.LogDID
// == "") triggers a 404 — the binary was not configured with a
// federation graph and the endpoint is structurally unavailable
// rather than emitting a misleading empty document.
//
// Cache-Control: public, max-age=300 — five-minute staleness floor
// (re-parenting events are rare; live verification of each hop
// happens at the I.20 walker side).
func NewNetworkPeersHandler(graph WireFederationGraph) http.HandlerFunc {
	configured := graph.ThisLog.LogDID != ""
	return func(w http.ResponseWriter, r *http.Request) {
		if !configured {
			http.Error(w, "federation graph not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(graph)
	}
}
