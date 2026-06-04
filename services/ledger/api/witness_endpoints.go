/*
FILE PATH:

	api/witness_endpoints.go

DESCRIPTION:

	v1.32.0 SDK adoption — convenience HTTP endpoint serving the
	materialized WitnessEndpointDeclarationV1 walker projection:

	    GET /v1/network/witness-endpoints   — current per-PubKeyID
	                                          witness endpoint map

	Mirrors the api/witnesses.go pattern: pure CQRS (a fetcher
	seam; api/ stays pgx + ledger-shape-free, L-8). The fetcher
	implementation in cmd/ledger/boot/wire/wire.go closes over an
	on-log WitnessEndpointDeclarationV1 walker source — same
	plumbing as the SignaturePolicy + AdmissionPolicy resolvers.

	NOT AUTHORITATIVE. The on-log walk is canonical; this endpoint
	is a CACHING CONVENIENCE so downstream consumers (JN's
	witness-endpoint resolver, the CLI, peer auditors) don't
	rebuild the projection by scanning the log for every URL
	lookup. Operators with strict zero-trust posture SHOULD
	resolve via the SDK's
	*discover.DefaultAuthoritativeResolver with a populated
	WitnessEndpointRecords slice.

	# RELATIONSHIP TO L1

	This endpoint serves the SAME records that wireWitnessCosigner
	consumes through the DefaultAuthoritativeResolver to populate
	HeadSync's witness URLs (L1 backdoor closure). One walker
	output, two consumers: the LEDGER itself uses it to drive
	cosignature collection; downstream consumers fetch it here.
*/
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// WitnessEndpointEntry is one row in the GET
// /v1/network/witness-endpoints response. Endpoints is keyed by
// W3C DID Core service-type ("BaseproofWitness", "BaseproofGossip",
// "BaseproofAuditor", etc.). Retired declarations are EXCLUDED.
type WitnessEndpointEntry struct {
	PubKeyID  string            `json:"pub_key_id"` // 64-char lowercase hex
	Endpoints map[string]string `json:"endpoints"`
}

// WitnessEndpointsView is the GET /v1/network/witness-endpoints
// response. AsOfSeq is the log position the projection
// materialized at; consumers re-verify by walking the log up
// to AsOfSeq via network.ResolveWitnessEndpointsAt.
type WitnessEndpointsView struct {
	AsOfSeq   uint64                 `json:"as_of_seq"`
	Witnesses []WitnessEndpointEntry `json:"witnesses"`
}

// WitnessEndpointsFetcher is the api/ → on-log walker seam.
// Implementations close over a QueryAPI-backed
// WitnessEndpointDeclarationV1 source and materialize the
// current projection.
type WitnessEndpointsFetcher interface {
	LoadCurrentWitnessEndpoints(ctx context.Context) (*WitnessEndpointsView, error)
}

// ErrWitnessEndpointsNotConfigured is the typed sentinel for
// "no walker source wired" — routed to 404 by the handler.
var ErrWitnessEndpointsNotConfigured = errors.New("api/witness_endpoints: witness endpoint walker not configured")

// NewNetworkWitnessEndpointsHandler returns the GET
// /v1/network/witness-endpoints handler. Nil fetcher → 404
// every request.
//
// Cache-Control: public, max-age=60 — witness URLs change on
// operational timescales (a witness operator migrating its
// service URL). One minute is the staleness floor; matches
// /v1/network/witnesses/current.
func NewNetworkWitnessEndpointsHandler(fetcher WitnessEndpointsFetcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if fetcher == nil {
			http.Error(w, "witness endpoint walker not configured", http.StatusNotFound)
			return
		}
		view, err := fetcher.LoadCurrentWitnessEndpoints(r.Context())
		if errors.Is(err, ErrWitnessEndpointsNotConfigured) {
			http.Error(w, "witness endpoint walker not configured", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "witness endpoint fetch failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
	}
}
