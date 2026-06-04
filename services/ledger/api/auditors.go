/*
FILE PATH:

	api/auditors.go

DESCRIPTION:

	v1.32.0 SDK adoption — convenience HTTP endpoint serving the
	materialized AuditorRegistrationV1 walker projection:

	    GET /v1/network/auditors   — currently-active auditor registry

	Mirrors the api/witnesses.go pattern: pure CQRS (a fetcher
	seam; api/ stays pgx + ledger-shape-free, L-8). The fetcher
	implementation in cmd/ledger/boot/wire/wire.go closes over an
	on-log AuditorRegistrationV1 walker source — same plumbing as
	the SignaturePolicy + AdmissionPolicy resolvers (see
	admission/onlog_signature_policy.go).

	NOT AUTHORITATIVE. The on-log walk is canonical; this endpoint
	is a CACHING CONVENIENCE so downstream consumers (JN's
	gossip_reconciler.go, peer ledgers, the CLI) don't rebuild the
	projection by scanning the log for every authorization check.
	Operators with strict zero-trust posture SHOULD walk the log
	directly via the SDK's network.ResolveAuditorAt.

	Scope is rendered as the comma-separated label form
	(network.AuditorScope.String) so the wire shape is human-
	readable AND parseable. The numeric mask is NOT exposed — the
	label form is the source of truth at this layer (consumers
	parse via the SDK's per-bit string mapping).
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
)

// AuditorEntry is one row in the GET /v1/network/auditors
// response. Mirrors the SDK's network.AuditorRegistration
// payload with explicit JSON tags + hex-encoded byte fields.
// Retired auditors are EXCLUDED from the wire shape — the
// endpoint serves the materialized CURRENT projection.
type AuditorEntry struct {
	AuditorDID  string `json:"auditor_did"`
	PublicKey   string `json:"public_key"` // hex
	SchemeTag   uint8  `json:"scheme_tag"` // 1=ECDSA, 2=BLS
	FindingsURL string `json:"findings_url"`
	// Scope is the comma-separated label form
	// (e.g. "equivocation,smt_replay,history_rewrite").
	Scope string `json:"scope"`
}

// AuditorsView is the GET /v1/network/auditors response. The
// AsOfSeq is the log position the projection materialized at;
// consumers re-resolve via network.ResolveAuditorAt(records,
// amendments, did, types.LogPosition{Sequence: AsOfSeq}) to
// verify against on-log (v1.33.0 Gap 2: amendments merge with
// the registration stream).
type AuditorsView struct {
	AsOfSeq  uint64         `json:"as_of_seq"`
	Auditors []AuditorEntry `json:"auditors"`
}

// AuditorRegistryFetcher is the api/ → on-log walker seam.
// Implementations close over a QueryAPI-backed
// AuditorRegistrationV1 source and materialize the current
// projection.
type AuditorRegistryFetcher interface {
	LoadCurrentAuditors(ctx context.Context) (*AuditorsView, error)
}

// ErrAuditorsNotConfigured is the typed sentinel for "no
// walker source wired" — routed to 404 by the handler.
var ErrAuditorsNotConfigured = errors.New("api/auditors: auditor registry walker not configured")

// NewNetworkAuditorsHandler returns the GET /v1/network/auditors
// handler. Nil fetcher → 404 every request.
//
// Cache-Control: public, max-age=60 — auditor registrations
// rotate on operational timescales (a new auditor being added,
// a scope being expanded); one minute is the staleness floor.
// Matches the /v1/network/witnesses/current convention.
func NewNetworkAuditorsHandler(fetcher AuditorRegistryFetcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if fetcher == nil {
			http.Error(w, "auditor registry walker not configured", http.StatusNotFound)
			return
		}
		view, err := fetcher.LoadCurrentAuditors(r.Context())
		if errors.Is(err, ErrAuditorsNotConfigured) {
			http.Error(w, "auditor registry walker not configured", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "auditor registry fetch failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
	}
}

// EncodeAuditorPublicKey is a tiny helper for the wire shape:
// the SDK stores PublicKey as []byte; the JSON wire form is
// lowercase hex. Exported so the wire-layer adapter can call
// it without duplicating the encoding rule.
func EncodeAuditorPublicKey(pub []byte) string {
	return hex.EncodeToString(pub)
}
