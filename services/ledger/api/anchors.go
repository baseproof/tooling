/*
FILE PATH:

	api/anchors.go

DESCRIPTION:

	Part II.1 — GET /v1/network/anchors. Serves the
	log/discover.AnchorChain wire shape: the chain of parent
	logs onto which THIS log's tree heads have been anchored
	(plan §I.4 / §II.9 federation-upward direction).

	RE-ROOTED FROM CONFIRMATIONS (PR-4b): the chain is served from the
	durable anchor_confirmations rows the publisher's READ-BACK writes —
	LatestAnchorSeq is the position the parent ACTUALLY assigned, learned
	by reading our anchor back through the parent's by-source page, never
	operator-curated. The hand-edited LEDGER_NETWORK_ANCHORS_FILE is
	deleted: a chain file nobody verifies is exactly the
	env-as-authority pattern the WHERE design demotes.

	An EMPTY chain (no confirmations yet) serves Hops: [] with 200 — a
	log that has never anchored anywhere is a valid state, not a
	misconfiguration. 404 only when the handler itself is unwired (a
	read-only binary with no confirmation store).

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
	"context"
	"encoding/json"
	"net/http"

	"github.com/baseproof/tooling/services/ledger/apitypes"
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
// handler, serving the chain the provider derives from the durable
// anchor_confirmations rows (one hop per parent, freshest first-seen). A
// provider error is a 500 — the chain is real state, not a static file.
//
// Cache-Control: public, max-age=300 — same staleness floor as
// /v1/network/peers + /v1/network/mirrors. Anchor cadence is
// operationally measured in minutes/hours; live confirmation of
// each hop is the SDK I.4 walker's job.
func NewNetworkAnchorsHandler(provider func(ctx context.Context) (WireAnchorChain, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if provider == nil {
			http.Error(w, "anchor chain not configured", http.StatusNotFound)
			return
		}
		chain, err := provider(r.Context())
		if err != nil {
			http.Error(w, "anchor chain unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(chain)
	}
}

// NewAnchorsBySourceHandler — GET /v1/network/anchors/by-source/{log_did}.
//
// One read-page of the cosigned-anchor entries (the only ANCHOR entry kind)
// whose projected SourceLogDID equals {log_did}: how a CHILD finds its own
// anchors here (the publisher read-back) and how an auditor's forensic feed
// enumerates them. Same page params as /v1/query/* (?start_seq, ?count;
// count clamped server-side to the hard ceiling).
//
// CONTRACT — DISCOVERY, NOT AUTHORITY. The page is served from the 0020
// source_log_did projection, which is extracted from the publisher's own
// payload at sequencing. Nothing trust-bearing rides on it: a consumer
// re-establishes inclusion (this log's tree), this log's K-of-N quorum, and
// the child-lineage binding from the returned entry bytes. An anchor the
// projection misses is therefore an OMISSION that fails toward alarm — the
// child's read-back records no confirmation and the auditor's monitor
// degrades toward stale/Critical — never toward false compliance. An empty
// page is a valid answer (a child that has never anchored here), not an
// error.
func NewAnchorsBySourceHandler(deps *QueryDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logDID := r.PathValue("log_did")
		if logDID == "" {
			writeTypedError(ctx, w, apitypes.ErrorClassMissingPathParam,
				http.StatusBadRequest, "source log DID required")
			return
		}
		startSeq, count := parsePageParams(r)
		entries, err := deps.QueryAPI.QueryAnchorsBySource(logDID, startSeq, count)
		if err != nil {
			deps.Logger.Error("query anchors by-source", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "query failed")
			return
		}
		writeEntriesJSON(w, entries)
	}
}
