/*
FILE PATH:

	artifactstore/token.go

DESCRIPTION:

	Phase 4 — the upload token: a ledger-signed bearer credential authorizing one
	upload, issued at RESERVE after PoW/credit accounting clears and presented on
	the UPLOAD POST. The token format lives here (the module owns it); the ledger
	admission calls SignUploadToken with its signing key, and the store's upload
	handler calls ParseAndVerifyUploadToken with the ledger's PUBLIC key —
	injected, never an imported ledger package, so the module stays portable.

KEY ARCHITECTURAL DECISIONS:
  - Ed25519 (stdlib): a compact, fast, deterministic signature; no cloud / no
    ledger-internal dependency.
  - Network-scoped authority (relay defense): the token carries the NetworkID.
    A token minted on network A cannot authorize an upload on B — B's store is
    configured with B's verification key, and the NetworkID is in the signed
    bytes.
  - Sign over the exact payload bytes that are transmitted: the bearer string
    is "<b64url(payload)>.<b64url(sig)>"; verification re-checks the signature
    over the decoded payload bytes, with no re-marshal ambiguity.
  - Verify checks ONLY the signature. Expiry, CID match, size cap, and network
    scope are request-specific and checked by the upload handler.
*/
package artifactstore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrTokenInvalid is returned when an upload token's signature does not verify.
var ErrTokenInvalid = errors.New("artifactstore/token: signature verification failed")

// UploadToken authorizes one upload. Issued at RESERVE, presented at UPLOAD.
// It is scoped to the content address (ArtifactCID), which is also the
// reservation's key — the genesis entry's sequence is not known at RESERVE.
type UploadToken struct {
	NetworkID   string `json:"network_id"`   // hex of the 32-byte NetworkID (relay defense)
	ArtifactCID string `json:"artifact_cid"` // the CID the uploaded bytes must match
	MaxSize     int64  `json:"max_size"`     // upload byte cap (the reserved / paid size)
	ExpiresAt   int64  `json:"expires_at"`   // UnixMicro expiry
}

// Expired reports whether the token is past its expiry as of now.
func (t UploadToken) Expired(now time.Time) bool { return now.UnixMicro() > t.ExpiresAt }

// SignUploadToken canonically serializes tok and signs it with priv, returning a
// compact "<b64url(payload)>.<b64url(sig)>" bearer string for the HTTP
// Authorization header.
func SignUploadToken(tok UploadToken, priv ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(tok)
	if err != nil {
		return "", fmt.Errorf("artifactstore/token: marshal: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return tokenEncode(payload) + "." + tokenEncode(sig), nil
}

// ParseAndVerifyUploadToken splits a bearer string and verifies its signature
// against pub, returning the decoded token. Signature only — the caller checks
// expiry / CID / size / network.
func ParseAndVerifyUploadToken(bearer string, pub ed25519.PublicKey) (UploadToken, error) {
	payloadB64, sigB64, ok := strings.Cut(bearer, ".")
	if !ok {
		return UploadToken{}, fmt.Errorf("artifactstore/token: malformed (want payload.sig)")
	}
	payload, err := tokenDecode(payloadB64)
	if err != nil {
		return UploadToken{}, fmt.Errorf("artifactstore/token: payload base64: %w", err)
	}
	sig, err := tokenDecode(sigB64)
	if err != nil {
		return UploadToken{}, fmt.Errorf("artifactstore/token: sig base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, payload, sig) {
		return UploadToken{}, ErrTokenInvalid
	}
	var tok UploadToken
	if err := json.Unmarshal(payload, &tok); err != nil {
		return UploadToken{}, fmt.Errorf("artifactstore/token: decode payload: %w", err)
	}
	return tok, nil
}

func tokenEncode(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func tokenDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
