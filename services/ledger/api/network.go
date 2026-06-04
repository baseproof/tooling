/*
FILE PATH:

	api/network.go

DESCRIPTION:

	Part II.1 — public network introspection endpoints:

	    GET /v1/network/bootstrap   — JCS-canonical BootstrapDocument
	    GET /v1/network/identity    — {network_id, network_uuid,
	                                   network_did, bootstrap_hash}
	    GET /v1/network/mirrors     — log/discover.MirrorManifest

	The /v1/network/peers + /v1/network/witnesses/* endpoints live
	in api/peers.go and api/witnesses.go respectively. Each endpoint
	follows the same template: payload constructed once at boot from
	Config + captured by closure + served verbatim with explicit
	Cache-Control. cmd/ledger owns the construction; api/ stays
	pgx + ledger-shape-free (L-8 pure CQRS).

KEY ARCHITECTURAL DECISIONS:
  - PUBLIC, no auth. Same posture as /v1/log-info / /version /
    /v1/network/peers. The bootstrap document + identity are
    cryptographically content-addressed; serving them publicly is
    REQUIRED for the SDK's TOFU pin-on-first-contact discipline
    (log/discover/tofu.go).
  - IMMUTABLE caching on bootstrap + identity. The bytes BIND the
    NetworkID at genesis (T-9 cryptographic domain separation);
    mutating them would change the NetworkID, which is the whole
    point of network identity. max-age=31536000 (1 year),
    immutable.
  - mirrors uses max-age=300 — mirror operators come and go on
    operational timescales (a CDN being added, a community mirror
    rotating); five minutes is the staleness floor a consumer
    accepts.
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/baseproof/baseproof/network"
)

// ─────────────────────────────────────────────────────────────────────
// GET /v1/network/bootstrap
// ─────────────────────────────────────────────────────────────────────

// NewNetworkBootstrapHandler returns the GET /v1/network/bootstrap
// handler. The captured canonicalBytes are the JCS-canonical bytes
// produced by network.BootstrapDocument.CanonicalBytes — the SAME
// bytes that hashed to produce the NetworkID. A consumer holding
// these bytes can recompute the NetworkID via SHA-256 and confirm
// it matches the network's identity. The shape is the wire form;
// json.Decoder consumes it directly.
//
// Empty bytes (no bootstrap document loaded — test / dev paths)
// trigger a 404 "not configured" — the network is not in
// bootstrap-document mode and the endpoint is structurally
// unavailable.
//
// Cache-Control: public, max-age=31536000, immutable. The bytes
// are content-addressed (a change would change the NetworkID,
// i.e., the network's identity); aggressive caching is safe.
func NewNetworkBootstrapHandler(canonicalBytes []byte) http.HandlerFunc {
	configured := len(canonicalBytes) > 0
	// Defensive copy — the captured slice's bytes MUST NOT be mutated
	// across requests (a Cache-Control: immutable lie would be a
	// trust violation). The closure owns the only reference.
	buf := append([]byte(nil), canonicalBytes...)
	return func(w http.ResponseWriter, r *http.Request) {
		if !configured {
			http.Error(w, "bootstrap document not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf)
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/network/identity
// ─────────────────────────────────────────────────────────────────────

// NetworkIdentity is the wire shape of GET /v1/network/identity.
// Carries the four identifiers a consumer derives from a
// BootstrapDocument: NetworkID (cosign-domain), UUID (RFC 9562),
// DID (did:baseproof:network:<crockford>), and BootstrapHash (the
// SHA-256 of the JCS-canonical bootstrap bytes, identical to
// NetworkID — surfaced separately so consumers comparing against
// a "bootstrap-hash" field in a bundle have a direct match).
//
// JCS-canonical shape: keys snake_case, byte arrays hex-encoded
// (same convention as /v1/tree/head, /v1/network/peers).
type NetworkIdentity struct {
	NetworkID     string `json:"network_id"`     // 64-char lowercase hex
	NetworkUUID   string `json:"network_uuid"`   // RFC 9562 dashed form
	NetworkDID    string `json:"network_did"`    // did:baseproof:network:<crockford>
	BootstrapHash string `json:"bootstrap_hash"` // = NetworkID; surfaced separately
}

// NewNetworkIdentityHandler returns the GET /v1/network/identity
// handler. The Identity struct's three fields + the BootstrapHash
// alias are constructed once at boot via
// network.BootstrapDocument.IDs(); the handler serves the cached
// JSON.
//
// Empty NetworkID (no bootstrap document loaded) triggers a 404.
//
// Cache-Control: public, max-age=31536000, immutable — same
// rationale as /v1/network/bootstrap.
func NewNetworkIdentityHandler(id NetworkIdentity) http.HandlerFunc {
	configured := id.NetworkID != ""
	return func(w http.ResponseWriter, r *http.Request) {
		if !configured {
			http.Error(w, "network identity not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(id)
	}
}

// BuildNetworkIdentity computes the NetworkIdentity wire shape from
// a network.BootstrapDocument. Used at boot to populate the cached
// payload the handler serves. Returns an empty NetworkIdentity if
// the doc is the zero value (no AllowedEntrySigSchemes, no
// witnesses, etc. — pre-bootstrap state); the handler then 404s.
//
// Returns an error if the BootstrapDocument is malformed (IDs()
// surfaces ErrBootstrapMissingField / ErrBootstrapJCS); cmd/ledger
// surfaces that at boot rather than at the first request.
func BuildNetworkIdentity(doc network.BootstrapDocument) (NetworkIdentity, error) {
	if len(doc.GenesisAdmissionAuthorities) == 0 &&
		len(doc.GenesisWitnessSet) == 0 &&
		doc.NetworkName == "" {
		return NetworkIdentity{}, nil
	}
	ids, err := doc.IDs()
	if err != nil {
		return NetworkIdentity{}, err
	}
	return NetworkIdentity{
		NetworkID:     hex.EncodeToString(ids.NetworkID[:]),
		NetworkUUID:   ids.UUID.String(),
		NetworkDID:    ids.DID,
		BootstrapHash: hex.EncodeToString(ids.NetworkID[:]),
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/network/mirrors
// ─────────────────────────────────────────────────────────────────────

// WireMirrorEntry mirrors log/discover.MirrorEntry with explicit
// JSON tags. The SDK ships discover.MirrorEntry as a structured Go
// type; this is the over-the-wire form. Kind values match
// log/discover.MirrorKind constants ("entries", "tiles", "bundles").
type WireMirrorEntry struct {
	URL    string `json:"url"`
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"`
}

// WireMirrorManifest mirrors log/discover.MirrorManifest. The
// LogDID identifies which log these mirrors serve — usually THIS
// log, but a manifest may also reference upstream-canonical
// mirrors for the same log (a federation-root cached at a
// well-known archive).
type WireMirrorManifest struct {
	LogDID  string            `json:"log_did"`
	Mirrors []WireMirrorEntry `json:"mirrors,omitempty"`
}

// NewNetworkMirrorsHandler returns the GET /v1/network/mirrors
// handler. The captured manifest is loaded at boot from
// LEDGER_NETWORK_MIRRORS_FILE. Empty LogDID (no file configured)
// triggers a 404 — the manifest is structurally unavailable.
//
// Cache-Control: public, max-age=300 — mirrors come and go on
// operational timescales; five minutes is the staleness floor.
func NewNetworkMirrorsHandler(manifest WireMirrorManifest) http.HandlerFunc {
	configured := manifest.LogDID != ""
	return func(w http.ResponseWriter, r *http.Request) {
		if !configured {
			http.Error(w, "mirror manifest not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(manifest)
	}
}
