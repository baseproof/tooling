/*
FILE PATH:

	api/witnesses.go

DESCRIPTION:

	Part II.1 — witness-set history endpoints:

	    GET /v1/network/witnesses/current        — currently-active set
	    GET /v1/network/witnesses/{set_hash}     — content-addressable lookup
	    GET /v1/network/witnesses/at/{seq}       — time-travel by tree_size

	Backed by the Part II.2 witness_sets history table (rows
	carry set_hash + keys_json + scheme_tag + effective_seq +
	retired_seq). The three endpoints share a single
	WitnessHistoryFetcher seam so api/ stays pgx + witnessclient-
	free (L-8 pure CQRS); cmd/ledger/boot/wire constructs an
	adapter that closes over the *pgxpool.Pool.

KEY ARCHITECTURAL DECISIONS:

  - {set_hash} is content-addressable → max-age=31536000,
    immutable (same posture as /v1/network/bootstrap). Returning
    different bytes for the same hash would be a hash collision,
    not a stale cache.

  - /current uses max-age=60. A witness rotation is rare but
    observable on a minute timescale — the same staleness floor
    we accept on /v1/log-info's witness_quorum_k field.

  - /at/{seq} uses max-age=31536000, immutable. A historical
    query at a specific seq has a stable answer once the seq
    is committed (the witness set at log position N never
    changes retroactively).

  - 404 routing:

  - /current: no active set → "no active witness set" 404.
    This indicates the witness_sets table is empty (pre-
    launch or DB-restore-without-history); operator must
    seed the active row before serving.

  - /{set_hash}: hash not found → "witness set not found" 404.

  - /at/{seq}: no set covers seq → "no witness set in effect
    at this sequence" 404. Typically: seq predates the first
    rotation AND no genesis row has been persisted.
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// WitnessSetView is the JSON wire shape served by every
// /v1/network/witnesses/* endpoint. Mirrors the witness_sets row
// shape (Part II.2) with hex-encoded set_hash + retired_seq as a
// nullable uint64 (omitempty for currently-active rows).
//
// Keys is the parsed witness key roster — surface-typed
// []WitnessPublicKey rather than the raw keys_json blob so
// consumers don't need to know the row's internal representation.
// Order matches the row's keys_json (the SDK's
// types.WitnessPublicKey carrying DID + SchemeTag + PubKey bytes).
type WitnessSetView struct {
	SetHash      string             `json:"set_hash"` // 64-char lowercase hex
	SchemeTag    uint8              `json:"scheme_tag"`
	EffectiveSeq uint64             `json:"effective_seq"`
	RetiredSeq   *uint64            `json:"retired_seq,omitempty"`
	Keys         []WitnessPublicKey `json:"keys"`
}

// WitnessPublicKey is the JSON wire shape for one witness in a
// WitnessSetView. Mirrors types.WitnessPublicKey from the SDK
// with explicit JSON tags + hex-encoded byte fields. ID is the
// 32-byte content-addressable witness identifier; PublicKey is
// the per-scheme key bytes (33 for ECDSA secp256k1, 96 for
// BLS12-381 G2); ProofOfPossession is REQUIRED for BLS keys
// (48-byte compressed G1) and MUST be empty for ECDSA.
type WitnessPublicKey struct {
	ID                string `json:"id"`         // 64-char lowercase hex
	PublicKey         string `json:"public_key"` // hex
	SchemeTag         uint8  `json:"scheme_tag"`
	ProofOfPossession string `json:"proof_of_possession,omitempty"` // hex, BLS only
}

// WitnessHistoryFetcher is the api/ → witness-history surface.
// Implementations close over a *pgxpool.Pool; api/ stays pg-free.
//
// Errors that mean "not found" (pgx.ErrNoRows) are routed to
// 404 by the handlers; all other errors → 500.
type WitnessHistoryFetcher interface {
	// LoadCurrentSet returns the currently-active witness set
	// (the row where retired_seq IS NULL). Returns
	// (nil, ErrWitnessSetNotFound) when the table is empty.
	LoadCurrentSet(ctx context.Context) (*WitnessSetView, error)

	// LoadSetByHash returns the witness set with the supplied
	// content-addressable set hash. Returns
	// (nil, ErrWitnessSetNotFound) when no row matches.
	LoadSetByHash(ctx context.Context, setHash [32]byte) (*WitnessSetView, error)

	// LoadSetAtSeq returns the witness set active at the supplied
	// log tree size — i.e., the row where effective_seq ≤ seq
	// AND (retired_seq IS NULL OR retired_seq > seq). Returns
	// (nil, ErrWitnessSetNotFound) when no row covers seq.
	LoadSetAtSeq(ctx context.Context, seq uint64) (*WitnessSetView, error)
}

// ErrWitnessSetNotFound is the typed sentinel for "no witness set
// matches this lookup". Implementations of WitnessHistoryFetcher
// return this (joined with the underlying pgx.ErrNoRows where
// applicable) so the handlers route to 404 without leaking the
// pg error surface.
var ErrWitnessSetNotFound = errors.New("api/witnesses: witness set not found")

// ─────────────────────────────────────────────────────────────────────
// GET /v1/network/witnesses/current
// ─────────────────────────────────────────────────────────────────────

// NewWitnessesCurrentHandler returns the GET /v1/network/witnesses/
// current handler. Nil fetcher → handler 404s every request
// (test / read-only ledger configurations that don't wire
// witness history).
//
// Cache-Control: public, max-age=60.
func NewWitnessesCurrentHandler(fetcher WitnessHistoryFetcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if fetcher == nil {
			http.Error(w, "witness history not configured", http.StatusNotFound)
			return
		}
		view, err := fetcher.LoadCurrentSet(r.Context())
		if errors.Is(err, ErrWitnessSetNotFound) ||
			errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "no active witness set", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "witness history fetch failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/network/witnesses/{set_hash}
// ─────────────────────────────────────────────────────────────────────

// NewWitnessesBySetHashHandler returns the GET /v1/network/witnesses/
// {set_hash} handler. Content-addressable lookup; the {set_hash}
// path segment is a 64-character lowercase hex string. Malformed
// hash → 400; not-found → 404.
//
// Cache-Control: public, max-age=31536000, immutable — the lookup
// is content-addressable, so the response either exists forever
// or never existed.
func NewWitnessesBySetHashHandler(fetcher WitnessHistoryFetcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if fetcher == nil {
			http.Error(w, "witness history not configured", http.StatusNotFound)
			return
		}
		raw := strings.TrimSpace(r.PathValue("set_hash"))
		hashBytes, err := hex.DecodeString(raw)
		if err != nil || len(hashBytes) != 32 {
			http.Error(w, "set_hash must be 64-char lowercase hex", http.StatusBadRequest)
			return
		}
		var setHash [32]byte
		copy(setHash[:], hashBytes)
		view, err := fetcher.LoadSetByHash(r.Context(), setHash)
		if errors.Is(err, ErrWitnessSetNotFound) ||
			errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "witness set not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "witness history fetch failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/network/witnesses/at/{seq}
// ─────────────────────────────────────────────────────────────────────

// NewWitnessesAtSeqHandler returns the GET /v1/network/witnesses/at/
// {seq} handler. {seq} is the log tree size at which to resolve
// the active witness set.
//
// Cache-Control: public, max-age=31536000, immutable — a historical
// "set active at log position N" query has a stable answer once
// the seq is committed (witness sets never retroactively change).
func NewWitnessesAtSeqHandler(fetcher WitnessHistoryFetcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if fetcher == nil {
			http.Error(w, "witness history not configured", http.StatusNotFound)
			return
		}
		raw := strings.TrimSpace(r.PathValue("seq"))
		seq, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, fmt.Sprintf("seq must be a non-negative integer (got %q)", raw),
				http.StatusBadRequest)
			return
		}
		view, err := fetcher.LoadSetAtSeq(r.Context(), seq)
		if errors.Is(err, ErrWitnessSetNotFound) ||
			errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "no witness set in effect at this sequence", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "witness history fetch failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
	}
}
