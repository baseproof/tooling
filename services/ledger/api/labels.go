/*
FILE PATH:

	api/labels.go

DESCRIPTION:

	v1.32.0 SDK adoption — convenience HTTP endpoint serving the
	materialized WitnessIdentityLabelV1 walker projection:

	    GET /v1/network/labels   — current per-PubKeyID witness labels

	Mirrors the api/witnesses.go pattern: pure CQRS (a closure-
	captured payload + a fetcher seam; api/ stays pgx + ledger-
	shape-free, L-8). cmd/ledger/boot/wire/wire.go constructs an
	adapter that closes over the on-log WitnessIdentityLabelV1
	walker source — same plumbing as the SignaturePolicy +
	AdmissionPolicy resolvers (see
	admission/onlog_signature_policy.go).

	NOT AUTHORITATIVE. The on-log walk is canonical; this endpoint
	is a CACHING CONVENIENCE so downstream consumers (JN, the CLI,
	peer auditors) don't rebuild the projection by scanning the log
	for every lookup. Operators with strict zero-trust posture
	SHOULD walk the log directly via the SDK's
	network.ResolveWitnessLabelAt.
*/
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// WitnessLabelEntry is one row in the GET /v1/network/labels
// response. Mirrors the SDK's
// network.WitnessIdentityLabel payload type with explicit JSON
// tags + hex-encoded PubKeyID. Retired entries are EXCLUDED
// from the wire shape — the endpoint serves the materialized
// CURRENT projection (retirement is conveyed by absence, same
// as witness rotations).
type WitnessLabelEntry struct {
	PubKeyID string `json:"pub_key_id"` // 64-char lowercase hex
	Label    string `json:"label"`      // ≤256-byte UTF-8
	DIDHint  string `json:"did_hint,omitempty"`
}

// WitnessLabelsView is the GET /v1/network/labels response
// shape. Labels is the per-PubKeyID projection at the AsOfSeq
// log position; consumers verify against the on-log walker by
// re-resolving AsOfSeq via network.ResolveWitnessLabelAt.
type WitnessLabelsView struct {
	AsOfSeq uint64              `json:"as_of_seq"`
	Labels  []WitnessLabelEntry `json:"labels"`
}

// WitnessLabelFetcher is the api/ → on-log walker seam. The
// implementation closes over a QueryAPI-backed
// WitnessIdentityLabelV1 source (mirroring
// admission.SignaturePolicyAmendmentSource) and the TreeSizeProvider;
// it materializes the current projection and returns it.
//
// Errors that mean "not configured" route to 404; all other
// errors route to 500.
type WitnessLabelFetcher interface {
	LoadCurrentLabels(ctx context.Context) (*WitnessLabelsView, error)
}

// ErrLabelsNotConfigured is the typed sentinel implementations
// return when no walker source is wired (e.g., the deployment
// hasn't published any WitnessIdentityLabelV1 entries yet).
// Routed to 404 by the handler.
var ErrLabelsNotConfigured = errors.New("api/labels: labels walker not configured")

// NewNetworkLabelsHandler returns the GET /v1/network/labels
// handler. Nil fetcher → 404 every request (test / read-only
// ledger configurations that don't wire the on-log walker).
//
// Cache-Control: public, max-age=60 — labels rotate on
// human/operational timescales (a witness operator renames
// itself); one minute is the staleness floor that mirrors
// /v1/network/witnesses/current.
func NewNetworkLabelsHandler(fetcher WitnessLabelFetcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if fetcher == nil {
			http.Error(w, "witness labels walker not configured", http.StatusNotFound)
			return
		}
		view, err := fetcher.LoadCurrentLabels(r.Context())
		if errors.Is(err, ErrLabelsNotConfigured) {
			http.Error(w, "witness labels walker not configured", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "witness labels fetch failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
	}
}
