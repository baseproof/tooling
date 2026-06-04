/*
FILE PATH: libs/httpmw/jwt.go

DESCRIPTION:

	JWT Authenticator. Verifies Bearer tokens against a JWKS endpoint
	and lifts the verified `sub` claim into the request context as
	callerDID.

	Wire format pinned:

	  Authorization: Bearer <jwt>

	  <jwt> = base64url(header) "." base64url(payload) "." base64url(sig)

	  Header MUST carry: { "alg": "RS256"|"ES256", "kid": "..." }
	  Payload MUST carry: { "iss": <expected issuer>, "sub": <DID>,
	                        "exp": <unix sec>, [optional "nbf"] }

	Verification steps (every step's failure → 401, no body):

	  1. Header parses + alg ∈ {RS256, ES256}.
	  2. Header carries a kid.
	  3. JWKS cache has a key with that kid; refresh once on miss.
	  4. Signature verifies against that key over header.payload.
	  5. iss == cfg.Issuer.
	  6. exp > now (with cfg.Leeway tolerance).
	  7. nbf <= now (when present, with cfg.Leeway tolerance).
	  8. sub != "".

	Stdlib-only by design — no external JWT library, no JWKS client
	library. The verifier is ~250 lines of explicit Go; the JWKS
	cache holds the JWK set in memory and refreshes on kid miss
	(cooldown-gated to prevent denial via crafted-kid spam).

	Algorithms supported:

	  RS256: RSA-PKCS#1 v1.5 over SHA-256 (RFC 7518 §3.3)
	  ES256: ECDSA P-256 over SHA-256 (RFC 7518 §3.4) — IETF-canonical
	         r || s concatenation (raw 64 bytes), NOT DER-encoded

	Adding HS256 (HMAC) is intentionally NOT supported: HS256 requires
	the verifier and signer to share a symmetric secret, which
	contradicts "verify against a public JWKS." Only asymmetric
	signing fits the deployment model.

	Concurrency: jwksCache is safe for concurrent Get + Refresh.
	Multiple in-flight requests during a refresh share one network
	fetch (sync.Once-protected per refresh window).
*/
package httpmw

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

// JWTConfig configures JWTAuth.
type JWTConfig struct {
	// Issuer is the expected `iss` claim. Tokens with any other iss
	// are rejected. Required.
	Issuer string

	// JWKSURL is the URL serving the JWKS document (RFC 7517).
	// Required. The middleware fetches lazily (first auth attempt
	// triggers the first fetch) and caches indefinitely; mismatched
	// kids trigger a single re-fetch (cooldown-gated).
	JWKSURL string

	// Client is the HTTP client used to fetch the JWKS. REQUIRED:
	// thread the binary's hoisted outbound client (see
	// libs/clienttls.BuildFromEnv or libs/outbound.HoistFromEnv) so
	// the JWKS fetch shares the operator-chosen mTLS posture. A nil
	// client is a startup-fatal error — the legacy 10s-timeout
	// plaintext-fallback path is gone (v1.27.x: no silent demotion).
	// Tests pass an httptest.Server's client.
	Client *http.Client

	// Leeway is the clock-skew tolerance for exp / nbf checks.
	// Empty/zero defaults to 30s.
	Leeway time.Duration

	// RefreshCooldown caps how often kid-miss triggers a JWKS refresh.
	// Empty/zero defaults to 30s.
	RefreshCooldown time.Duration

	// nowFn returns the current time. Tests inject a fixed clock so
	// exp / nbf checks are deterministic. nil → time.Now.
	nowFn func() time.Time
}

// ─────────────────────────────────────────────────────────────────────
// JWTAuth
// ─────────────────────────────────────────────────────────────────────

// JWTAuth verifies JWTs against a JWKS endpoint.
type JWTAuth struct {
	cfg   JWTConfig
	cache *jwksCache
}

// NewJWTAuth constructs a JWTAuth. Returns ErrInvalidConfig wrapped
// with a descriptive message when required fields are missing.
func NewJWTAuth(cfg JWTConfig) (*JWTAuth, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("middleware/jwt: Issuer required")
	}
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("middleware/jwt: JWKSURL required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("middleware/jwt: Client required (thread the binary's hoisted outbound client; see libs/clienttls.BuildFromEnv or libs/outbound.HoistFromEnv)")
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.RefreshCooldown <= 0 {
		cfg.RefreshCooldown = 30 * time.Second
	}
	if cfg.nowFn == nil {
		cfg.nowFn = time.Now
	}
	return &JWTAuth{
		cfg:   cfg,
		cache: newJWKSCache(cfg.Client, cfg.JWKSURL, cfg.RefreshCooldown),
	}, nil
}

// Wrap implements Authenticator.Wrap.
func (a *JWTAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		did, err := a.verify(r)
		if err != nil {
			writeUnauth(w)
			return
		}
		ctx := WithCallerDID(r.Context(), did)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Compile-time interface check.
var _ Authenticator = (*JWTAuth)(nil)

// ─────────────────────────────────────────────────────────────────────
// Verification pipeline (private — exposed only for testing in-package)
// ─────────────────────────────────────────────────────────────────────

func (a *JWTAuth) verify(r *http.Request) (string, error) {
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return "", ErrUnauthenticated
	}
	token := strings.TrimSpace(authz[len(prefix):])
	if token == "" {
		return "", ErrUnauthenticated
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrUnauthenticated
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	header, err := decodeHeader(headerB64)
	if err != nil {
		return "", err
	}
	if header.Alg != "RS256" && header.Alg != "ES256" {
		return "", ErrUnauthenticated
	}
	if header.Kid == "" {
		return "", ErrUnauthenticated
	}

	pubKey, err := a.cache.Get(r.Context(), header.Kid)
	if err != nil {
		return "", err
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", ErrUnauthenticated
	}
	signedInput := []byte(headerB64 + "." + payloadB64)
	if err := verifySig(header.Alg, pubKey, signedInput, sig); err != nil {
		return "", ErrUnauthenticated
	}

	claims, err := decodeClaims(payloadB64)
	if err != nil {
		return "", err
	}
	if claims.Iss != a.cfg.Issuer {
		return "", ErrUnauthenticated
	}
	now := a.cfg.nowFn()
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Add(a.cfg.Leeway).Before(now) {
		return "", ErrUnauthenticated
	}
	if claims.Nbf != 0 && time.Unix(claims.Nbf, 0).Add(-a.cfg.Leeway).After(now) {
		return "", ErrUnauthenticated
	}
	if claims.Sub == "" {
		return "", ErrUnauthenticated
	}
	return claims.Sub, nil
}

// ─────────────────────────────────────────────────────────────────────
// JWT structures
// ─────────────────────────────────────────────────────────────────────

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud any    `json:"aud,omitempty"` // string or []string per RFC 7519
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf,omitempty"`
	Iat int64  `json:"iat,omitempty"`
}

func decodeHeader(b64 string) (*jwtHeader, error) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var h jwtHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, ErrUnauthenticated
	}
	return &h, nil
}

func decodeClaims(b64 string) (*jwtClaims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var c jwtClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, ErrUnauthenticated
	}
	return &c, nil
}

// verifySig dispatches to the right alg verifier. Returns nil on
// success, ErrUnauthenticated on any verification failure.
func verifySig(alg string, pub crypto.PublicKey, signed, sig []byte) error {
	switch alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrUnauthenticated
		}
		hashed := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], sig); err != nil {
			return ErrUnauthenticated
		}
		return nil
	case "ES256":
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrUnauthenticated
		}
		// IETF ES256 sig is r || s, each 32 bytes (P-256 coord size).
		if len(sig) != 64 {
			return ErrUnauthenticated
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		hashed := sha256.Sum256(signed)
		if !ecdsa.Verify(ecdsaPub, hashed[:], r, s) {
			return ErrUnauthenticated
		}
		return nil
	default:
		return ErrUnauthenticated
	}
}

// ─────────────────────────────────────────────────────────────────────
// JWKS cache
// ─────────────────────────────────────────────────────────────────────

// jwksCache loads and caches a JWK set from a JWKSURL. Concurrency-safe.
// Refresh on kid miss is cooldown-gated to prevent attackers from
// triggering unbounded JWKS fetches via crafted-kid spam.
type jwksCache struct {
	client    *http.Client
	url       string
	cooldown  time.Duration
	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey // kid → public key
	lastFetch time.Time
}

func newJWKSCache(client *http.Client, url string, cooldown time.Duration) *jwksCache {
	return &jwksCache{
		client:   client,
		url:      url,
		cooldown: cooldown,
		keys:     make(map[string]crypto.PublicKey),
	}
}

// Get returns the public key for kid. On miss, triggers a refresh
// (cooldown-gated) and tries once more. Returns ErrUnauthenticated
// if the kid is still unknown after refresh.
func (c *jwksCache) Get(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	if k, ok := c.keys[kid]; ok {
		c.mu.RUnlock()
		return k, nil
	}
	c.mu.RUnlock()

	if err := c.refresh(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnauthenticated
}

// refresh fetches the JWKS. Cooldown-gated: if a refresh succeeded
// within cfg.RefreshCooldown, this call is a no-op (so kid-miss spam
// can't drive infinite fetches).
func (c *jwksCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.lastFetch) < c.cooldown {
		return nil
	}
	keys, err := fetchJWKS(ctx, c.client, c.url)
	if err != nil {
		// Infrastructure failure: keep the existing cache (might be
		// stale but functional) and surface ErrUnauthenticated to the
		// caller. We deliberately do NOT differentiate
		// infra-unavailable from kid-miss in the response so attackers
		// can't probe JWKS health via auth-failure timing/content.
		return ErrUnauthenticated
	}
	c.keys = keys
	c.lastFetch = time.Now()
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// JWKS fetch + parse
// ─────────────────────────────────────────────────────────────────────

// jwksDoc is the JSON shape served by JWKS endpoints (RFC 7517).
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// jwk is one entry in a JWKS document. Fields cover RSA (n, e) and
// EC (crv, x, y); other key types are unsupported and silently
// skipped.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func fetchJWKS(ctx context.Context, client *http.Client, url string) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("middleware/jwt: JWKS fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, err
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	out := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		switch k.Kty {
		case "RSA":
			pub, err := jwkToRSA(k)
			if err == nil {
				out[k.Kid] = pub
			}
		case "EC":
			pub, err := jwkToECDSA(k)
			if err == nil {
				out[k.Kid] = pub
			}
		default:
			// kty=oct (HMAC) and unknown types silently skipped —
			// see package comment for the no-symmetric rule.
		}
	}
	if len(out) == 0 {
		return nil, errors.New("middleware/jwt: JWKS contained no usable keys")
	}
	return out, nil
}

func jwkToRSA(k jwk) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	if len(n) == 0 || len(e) == 0 {
		return nil, errors.New("missing RSA modulus or exponent")
	}
	eInt := new(big.Int).SetBytes(e).Int64()
	if eInt < 3 || eInt > (1<<31-1) {
		return nil, errors.New("RSA exponent out of range")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(eInt),
	}, nil
}

func jwkToECDSA(k jwk) (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve %q (only P-256)", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
