/*
FILE PATH:

	api/anchors.go

DESCRIPTION:

	Part II.1 — GET /v1/network/anchors. Serves the
	log/discover.AnchorChain wire shape: the chain of parent
	logs onto which THIS log's tree heads have been anchored
	(plan §I.4 / §II.9 federation-upward direction).

	Operator-supplied via LEDGER_NETWORK_ANCHORS_FILE (JSON
	matching api.WireAnchorChain). The information is genuinely
	cross-log — LatestAnchorSeq + LatestAnchorTreeSize point at
	the anchor entry's position on the PARENT's log, which THIS
	ledger does not authoritatively know without querying the
	parent. Operator-curated metadata closes the gap; SDK
	consumers re-verify each hop against on-log anchor entries
	(the FindCrossLogPath walker's responsibility).

	Empty path / zero LogDID → handler 404 ("not configured").
	The SDK's I.4 FetchAnchorChain treats 404 as "no chain
	available" and falls through to its archive-fallback path.

KEY ARCHITECTURAL DECISIONS:

  - Cache-Control: public, max-age=300. The anchor chain is
    operationally stable (a new anchor lands at the parent's
    cadence, on the order of minutes/hours), so the cache window
    matches /v1/network/peers + /v1/network/mirrors.

  - HISTORICAL anchors are part of the chain. A re-parented log
    carries entries for both former + current parents; the SDK's
    temporal walker uses HistoricalParents (from peers) plus the
    per-parent anchor metadata here to resolve cross-network
    references made under former parents.

    Plan §I.4 / §II.1.
*/
package api

import (
	"encoding/json"
	"net/http"
)

// WireAnchorChainEntry mirrors log/discover.AnchorChainEntry with
// explicit JSON tags + hex-encoded witness_set_hash. ParentLogDID
// identifies the parent log; WitnessSetHash is the parent's set
// hash at the moment the most recent anchor was admitted (the
// content-addressable identity a consumer uses to fetch the
// parent's witness set via /v1/network/witnesses/{set_hash}).
//
// LatestAnchorSeq is the position of the most recent anchor entry
// on the PARENT'S log (not this log). LatestAnchorTreeSize is THIS
// log's tree size at the moment that anchor was created.
type WireAnchorChainEntry struct {
	ParentLogDID         string `json:"parent_log_did"`
	WitnessSetHash       string `json:"witness_set_hash"`                  // 64-char lowercase hex
	LatestAnchorSeq      uint64 `json:"latest_anchor_seq,omitempty"`       // on parent's log
	LatestAnchorTreeSize uint64 `json:"latest_anchor_tree_size,omitempty"` // on THIS log
}

// WireAnchorChain is the wire shape of GET /v1/network/anchors.
// Mirrors log/discover.AnchorChain. LogDID is THIS log (the
// anchored log); Hops carries one entry per parent in the chain,
// ordered from most recent at index 0 → oldest at index N-1.
//
// A federation root with no parents serves an empty Hops slice —
// distinct from "not configured" which 404s.
type WireAnchorChain struct {
	LogDID string                 `json:"log_did"`
	Hops   []WireAnchorChainEntry `json:"hops,omitempty"`
}

// NewNetworkAnchorsHandler returns the GET /v1/network/anchors
// handler. The captured chain is loaded at boot from
// LEDGER_NETWORK_ANCHORS_FILE. Empty LogDID (no file configured)
// triggers a 404 — the chain is structurally unavailable.
//
// Cache-Control: public, max-age=300 — same staleness floor as
// /v1/network/peers + /v1/network/mirrors. Anchor cadence is
// operationally measured in minutes/hours; live confirmation of
// each hop is the SDK I.4 walker's job.
func NewNetworkAnchorsHandler(chain WireAnchorChain) http.HandlerFunc {
	configured := chain.LogDID != ""
	return func(w http.ResponseWriter, r *http.Request) {
		if !configured {
			http.Error(w, "anchor chain not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(chain)
	}
}
