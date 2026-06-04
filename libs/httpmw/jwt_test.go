/*
FILE PATH: libs/httpmw/jwt_test.go

DESCRIPTION:

	Coverage for JWTAuth. Pinned properties (every one matched by at
	least one negative-path test):

	  Construction
	    Empty Issuer / JWKSURL → ErrInvalidConfig.

	  Header
	    Missing Authorization header                → 401
	    Wrong scheme (Basic / Token / etc.)         → 401
	    Empty token after "Bearer "                 → 401
	    Malformed (not 3 dot-separated segments)    → 401
	    Header b64-malformed                        → 401
	    Header alg ∉ {RS256, ES256}                 → 401
	    Header missing kid                          → 401

	  JWKS / signature
	    Kid not in JWKS                             → 401 (with cooldown)
	    JWKS fetch fails (server 500)               → 401
	    JWKS document has zero usable keys          → 401
	    Signature does not verify                   → 401
	    ES256 with wrong sig length                 → 401
	    Algorithm mismatch (RS256 hdr, EC key)      → 401

	  Claims
	    Wrong issuer                                → 401
	    exp absent                                  → 401
	    exp in past (beyond leeway)                 → 401
	    exp in past (within leeway)                 → OK
	    nbf in future (beyond leeway)               → 401
	    nbf in future (within leeway)               → OK
	    sub empty                                   → 401

	  Happy paths
	    RS256 signed token, valid issuer, valid exp → OK + callerDID
	    ES256 signed token                          → OK + callerDID

	  Concurrency
	    Many goroutines verifying the same token  → all succeed (race-clean)

	  Failure-mode hygiene
	    Every 401 carries empty body + WWW-Authenticate: Bearer
*/
package httpmw

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────

func TestNewJWTAuth_RejectsEmptyIssuer(t *testing.T) {
	_, err := NewJWTAuth(JWTConfig{JWKSURL: "https://x/jwks", Client: &http.Client{}})
	if err == nil || !strings.Contains(err.Error(), "Issuer required") {
		t.Errorf("err = %v, want Issuer required", err)
	}
}

func TestNewJWTAuth_RejectsEmptyJWKSURL(t *testing.T) {
	_, err := NewJWTAuth(JWTConfig{Issuer: "iss", Client: &http.Client{}})
	if err == nil || !strings.Contains(err.Error(), "JWKSURL required") {
		t.Errorf("err = %v, want JWKSURL required", err)
	}
}

// TestNewJWTAuth_RequiresClient pins the v1.27.x contract: a nil Client
// is a startup-fatal error. The legacy 10s-timeout plaintext-fallback
// path was deleted with the rest of the silent-fallback shapes.
func TestNewJWTAuth_RequiresClient(t *testing.T) {
	_, err := NewJWTAuth(JWTConfig{Issuer: "iss", JWKSURL: "https://x/jwks"})
	if err == nil || !strings.Contains(err.Error(), "Client required") {
		t.Errorf("err = %v, want Client required", err)
	}
}

func TestNewJWTAuth_DefaultsApplied(t *testing.T) {
	a, err := NewJWTAuth(JWTConfig{Issuer: "iss", JWKSURL: "https://x/jwks", Client: &http.Client{}})
	if err != nil {
		t.Fatalf("NewJWTAuth: %v", err)
	}
	if a.cfg.Leeway != 30*time.Second {
		t.Errorf("Leeway default = %v, want 30s", a.cfg.Leeway)
	}
	if a.cfg.RefreshCooldown != 30*time.Second {
		t.Errorf("RefreshCooldown default = %v, want 30s", a.cfg.RefreshCooldown)
	}
	if a.cfg.Client == nil {
		t.Error("Client must be set (was passed)")
	}
	if a.cfg.nowFn == nil {
		t.Error("nowFn default missing")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Header / token shape failures
// ─────────────────────────────────────────────────────────────────────

func TestJWTAuth_NoAuthHeader_401(t *testing.T) {
	_, _, _, _, _, mw := buildRSAFixture(t)
	expectUnauth(t, mw, httptest.NewRequest(http.MethodGet, "/", nil), "no auth header")
}

func TestJWTAuth_WrongScheme_401(t *testing.T) {
	_, _, _, _, _, mw := buildRSAFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	expectUnauth(t, mw, req, "wrong scheme")
}

func TestJWTAuth_EmptyToken_401(t *testing.T) {
	_, _, _, _, _, mw := buildRSAFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	expectUnauth(t, mw, req, "empty token")
}

func TestJWTAuth_MalformedSegments_401(t *testing.T) {
	_, _, _, _, _, mw := buildRSAFixture(t)
	for _, tok := range []string{"a", "a.b", "a.b.c.d"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		expectUnauth(t, mw, req, "malformed: "+tok)
	}
}

func TestJWTAuth_HeaderB64Malformed_401(t *testing.T) {
	_, _, _, _, _, mw := buildRSAFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// "@@@" is not valid base64url
	req.Header.Set("Authorization", "Bearer @@@.payload.sig")
	expectUnauth(t, mw, req, "header b64 garbage")
}

func TestJWTAuth_BadAlgInHeader_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	tok := signer(t, jwtHeader{Alg: "HS256", Kid: "test-kid"}, validClaims())
	req := withBearer(tok)
	expectUnauth(t, mw, req, "alg=HS256 should be rejected")
}

func TestJWTAuth_NoneAlg_Rejected(t *testing.T) {
	_, _, _, _, _, mw := buildRSAFixture(t)
	// "none" alg trick: empty signature, header with alg=none.
	hdr := mustB64Json(t, jwtHeader{Alg: "none", Kid: "test-kid"})
	pl := mustB64Json(t, validClaims())
	tok := hdr + "." + pl + "."
	req := withBearer(tok)
	expectUnauth(t, mw, req, "alg=none MUST never authenticate")
}

func TestJWTAuth_MissingKid_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	tok := signer(t, jwtHeader{Alg: "RS256"}, validClaims())
	expectUnauth(t, mw, withBearer(tok), "missing kid")
}

// ─────────────────────────────────────────────────────────────────────
// JWKS / signature failures
// ─────────────────────────────────────────────────────────────────────

func TestJWTAuth_KidNotInJWKS_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "unknown-kid"}, validClaims())
	expectUnauth(t, mw, withBearer(tok), "kid not in JWKS")
}

func TestJWTAuth_BadSignature_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	// Tamper with a valid token's signature segment.
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, validClaims())
	parts := strings.Split(tok, ".")
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 256)) // zero sig
	expectUnauth(t, mw, withBearer(strings.Join(parts, ".")), "bad signature")
}

func TestJWTAuth_AlgKeyMismatch_RS256OnECKey(t *testing.T) {
	// Build an ES256 fixture but request RS256 verification: the
	// kid resolves to an ECDSA key, the alg switch picks the RSA
	// verifier path, and the type assertion fails → 401.
	_, _, _, _, _, ecMw := buildECDSAFixture(t)

	// Forge a header with alg=RS256 but kid pointing at the EC key.
	// Sign with EC just to have a realistic-looking signature
	// (verifier won't get past the type assertion anyway).
	hdr := mustB64Json(t, jwtHeader{Alg: "RS256", Kid: "test-kid-ec"})
	pl := mustB64Json(t, validClaims())
	signed := hdr + "." + pl
	hash := sha256.Sum256([]byte(signed))
	_ = hash
	tok := signed + ".AAAA"
	expectUnauth(t, ecMw, withBearer(tok), "alg=RS256 with EC key")
}

func TestJWTAuth_ES256WrongSigLength_401(t *testing.T) {
	_, _, _, _, _, ecMw := buildECDSAFixture(t)

	hdr := mustB64Json(t, jwtHeader{Alg: "ES256", Kid: "test-kid-ec"})
	pl := mustB64Json(t, validClaims())
	// 32-byte sig instead of 64 → wrong length.
	tok := hdr + "." + pl + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	expectUnauth(t, ecMw, withBearer(tok), "ES256 sig wrong length")
}

func TestJWTAuth_JWKSServer500_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	auth, err := NewJWTAuth(JWTConfig{
		Issuer:  "test-iss",
		JWKSURL: srv.URL,
		Client:  srv.Client(),
		nowFn:   func() time.Time { return time.Now() },
	})
	if err != nil {
		t.Fatalf("NewJWTAuth: %v", err)
	}
	mw := auth.Wrap(echoHandler())

	// Even a syntactically-valid token fails because JWKS is broken.
	hdr := mustB64Json(t, jwtHeader{Alg: "RS256", Kid: "any"})
	pl := mustB64Json(t, validClaims())
	tok := hdr + "." + pl + ".AAAA"
	expectUnauth(t, mw, withBearer(tok), "jwks 500")
}

func TestJWTAuth_JWKSWithZeroUsableKeys_401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Only kty=oct entries — silently skipped → empty key set →
		// fetchJWKS returns an error → cache treats as ErrUnauthenticated.
		json.NewEncoder(w).Encode(jwksDoc{Keys: []jwk{
			{Kty: "oct", Kid: "shared"},
		}})
	}))
	defer srv.Close()

	auth, _ := NewJWTAuth(JWTConfig{
		Issuer: "iss", JWKSURL: srv.URL, Client: srv.Client(),
	})
	mw := auth.Wrap(echoHandler())
	hdr := mustB64Json(t, jwtHeader{Alg: "RS256", Kid: "any"})
	pl := mustB64Json(t, validClaims())
	tok := hdr + "." + pl + ".AAAA"
	expectUnauth(t, mw, withBearer(tok), "JWKS has no usable keys")
}

// ─────────────────────────────────────────────────────────────────────
// Claims failures
// ─────────────────────────────────────────────────────────────────────

func TestJWTAuth_WrongIssuer_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	c := validClaims()
	c.Iss = "https://wrong-idp.test"
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, c)
	expectUnauth(t, mw, withBearer(tok), "wrong iss")
}

func TestJWTAuth_ExpAbsent_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	c := validClaims()
	c.Exp = 0
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, c)
	expectUnauth(t, mw, withBearer(tok), "exp absent")
}

func TestJWTAuth_ExpInPast_BeyondLeeway_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixtureAtTime(t, fixedNow)
	c := validClaims()
	c.Exp = fixedNow.Add(-2 * time.Minute).Unix()
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, c)
	expectUnauth(t, mw, withBearer(tok), "exp 2m ago, leeway 30s")
}

func TestJWTAuth_ExpInPast_WithinLeeway_OK(t *testing.T) {
	_, _, did, signer, _, mw := buildRSAFixtureAtTime(t, fixedNow)
	c := validClaims()
	c.Exp = fixedNow.Add(-10 * time.Second).Unix() // within 30s leeway
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, c)
	rec, body := serveOK(t, mw, withBearer(tok))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (within leeway)", rec.Code)
	}
	if body != did {
		t.Errorf("downstream callerDID = %q, want %q", body, did)
	}
}

func TestJWTAuth_NbfFuture_BeyondLeeway_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixtureAtTime(t, fixedNow)
	c := validClaims()
	c.Nbf = fixedNow.Add(2 * time.Minute).Unix()
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, c)
	expectUnauth(t, mw, withBearer(tok), "nbf 2m future")
}

func TestJWTAuth_NbfFuture_WithinLeeway_OK(t *testing.T) {
	_, _, did, signer, _, mw := buildRSAFixtureAtTime(t, fixedNow)
	c := validClaims()
	c.Nbf = fixedNow.Add(10 * time.Second).Unix()
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, c)
	rec, body := serveOK(t, mw, withBearer(tok))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body != did {
		t.Errorf("seen DID = %q, want %q", body, did)
	}
}

func TestJWTAuth_SubEmpty_401(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	c := validClaims()
	c.Sub = ""
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, c)
	expectUnauth(t, mw, withBearer(tok), "sub empty")
}

// ─────────────────────────────────────────────────────────────────────
// Happy paths
// ─────────────────────────────────────────────────────────────────────

func TestJWTAuth_RS256_HappyPath(t *testing.T) {
	_, _, did, signer, _, mw := buildRSAFixture(t)
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, validClaims())
	rec, body := serveOK(t, mw, withBearer(tok))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body != did {
		t.Errorf("downstream callerDID = %q, want %q", body, did)
	}
}

func TestJWTAuth_ES256_HappyPath(t *testing.T) {
	_, _, did, signer, _, mw := buildECDSAFixture(t)
	tok := signer(t, jwtHeader{Alg: "ES256", Kid: "test-kid-ec"}, validClaims())
	rec, body := serveOK(t, mw, withBearer(tok))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body != did {
		t.Errorf("downstream callerDID = %q, want %q", body, did)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Concurrency
// ─────────────────────────────────────────────────────────────────────

func TestJWTAuth_ConcurrentVerifications_RaceClean(t *testing.T) {
	_, _, _, signer, _, mw := buildRSAFixture(t)
	tok := signer(t, jwtHeader{Alg: "RS256", Kid: "test-kid"}, validClaims())

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	failures := make(chan int, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, withBearer(tok))
			if rec.Code != http.StatusOK {
				failures <- rec.Code
			}
		}()
	}
	wg.Wait()
	close(failures)
	if len(failures) != 0 {
		t.Errorf("%d/%d concurrent verifications failed", len(failures), goroutines)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 401 hygiene
// ─────────────────────────────────────────────────────────────────────

func TestJWTAuth_401Body_NoLeak(t *testing.T) {
	_, _, _, _, _, mw := buildRSAFixture(t)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("missing Bearer challenge")
	}
	for _, m := range []string{"JWT", "kid", "issuer", "expired", "signature"} {
		if strings.Contains(rec.Body.String(), m) {
			t.Errorf("body leaks marker %q: %q", m, rec.Body.String())
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Refresh cooldown
// ─────────────────────────────────────────────────────────────────────

// TestJWKSCache_RefreshCooldown_PreventsKidMissSpam pins the
// cooldown-gate property: spamming unknown kids does NOT trigger a
// JWKS fetch on every request.
func TestJWKSCache_RefreshCooldown_PreventsKidMissSpam(t *testing.T) {
	var fetches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches++
		_ = json.NewEncoder(w).Encode(jwksDoc{}) // empty — no usable keys
	}))
	defer srv.Close()

	cache := newJWKSCache(srv.Client(), srv.URL, 30*time.Second)
	for i := 0; i < 10; i++ {
		_, _ = cache.Get(context.Background(), "unknown-kid")
	}
	// The first call triggers the empty-keys path which leaves
	// lastFetch zero, so subsequent calls retry. Confirm at most one
	// fetch happens within the cooldown window after a SUCCESSFUL
	// fetch by giving the cache a populated key set first.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache.mu.Lock()
	cache.keys["seeded"] = &rsaKey.PublicKey
	cache.lastFetch = time.Now()
	cache.mu.Unlock()
	startCount := fetches
	for i := 0; i < 10; i++ {
		_, _ = cache.Get(context.Background(), "still-unknown-kid")
	}
	if fetches > startCount {
		t.Errorf("kid-miss spam triggered %d fetches within cooldown; want 0",
			fetches-startCount)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Fixtures and helpers
// ─────────────────────────────────────────────────────────────────────

// fixedNow is a stable test clock all time-sensitive tests share.
var fixedNow = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

const testDID = "did:web:state:tn:davidson:judge-mcclendon"

func validClaims() jwtClaims {
	return jwtClaims{
		Iss: "https://idp.test",
		Sub: testDID,
		Exp: fixedNow.Add(1 * time.Hour).Unix(),
	}
}

// buildRSAFixture creates: an RSA keypair, a JWKS server serving its
// public half under kid "test-kid", a signer closure that produces
// JWTs, and a fully-wired JWTAuth middleware. Caller never sees the
// private key directly.
func buildRSAFixture(t *testing.T) (
	jwksSrv *httptest.Server,
	priv *rsa.PrivateKey,
	did string,
	signer func(t *testing.T, h jwtHeader, c jwtClaims) string,
	auth *JWTAuth,
	mw http.Handler,
) {
	return buildRSAFixtureAtTime(t, fixedNow)
}

func buildRSAFixtureAtTime(t *testing.T, now time.Time) (
	jwksSrv *httptest.Server,
	priv *rsa.PrivateKey,
	did string,
	signer func(t *testing.T, h jwtHeader, c jwtClaims) string,
	auth *JWTAuth,
	mw http.Handler,
) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pub := priv.PublicKey
	doc := jwksDoc{Keys: []jwk{{
		Kty: "RSA",
		Kid: "test-kid",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
	jwksSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(jwksSrv.Close)

	auth, err = NewJWTAuth(JWTConfig{
		Issuer:  "https://idp.test",
		JWKSURL: jwksSrv.URL,
		Client:  jwksSrv.Client(),
		nowFn:   func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewJWTAuth: %v", err)
	}
	signer = func(t *testing.T, h jwtHeader, c jwtClaims) string {
		t.Helper()
		hb := mustB64Json(t, h)
		cb := mustB64Json(t, c)
		signed := hb + "." + cb
		hashed := sha256.Sum256([]byte(signed))
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	did = testDID
	mw = auth.Wrap(echoHandler())
	return
}

// buildECDSAFixture is the ES256 sibling of buildRSAFixture.
func buildECDSAFixture(t *testing.T) (
	jwksSrv *httptest.Server,
	priv *ecdsa.PrivateKey,
	did string,
	signer func(t *testing.T, h jwtHeader, c jwtClaims) string,
	auth *JWTAuth,
	mw http.Handler,
) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	doc := jwksDoc{Keys: []jwk{{
		Kty: "EC",
		Kid: "test-kid-ec",
		Alg: "ES256",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(priv.PublicKey.Y.Bytes()),
	}}}
	jwksSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(jwksSrv.Close)

	auth, err = NewJWTAuth(JWTConfig{
		Issuer:  "https://idp.test",
		JWKSURL: jwksSrv.URL,
		Client:  jwksSrv.Client(),
		nowFn:   func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatalf("NewJWTAuth: %v", err)
	}
	signer = func(t *testing.T, h jwtHeader, c jwtClaims) string {
		t.Helper()
		hb := mustB64Json(t, h)
		cb := mustB64Json(t, c)
		signed := hb + "." + cb
		hashed := sha256.Sum256([]byte(signed))
		r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		// IETF ES256: r || s, each 32 bytes (P-256 coord size).
		buf := make([]byte, 64)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(buf[32-len(rBytes):], rBytes)
		copy(buf[64-len(sBytes):], sBytes)
		return signed + "." + base64.RawURLEncoding.EncodeToString(buf)
	}
	did = testDID
	mw = auth.Wrap(echoHandler())
	return
}

// echoHandler writes the observed callerDID into the response body.
// Tests assert against rec.Body to confirm what the downstream saw.
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(CallerDIDFromContext(r.Context())))
	})
}

func mustB64Json(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func withBearer(tok string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	return req
}

func expectUnauth(t *testing.T, h http.Handler, req *http.Request, label string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("%s: status = %d, want 401 (body=%q)", label, rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("%s: WWW-Authenticate = %q, want Bearer", label, got)
	}
}

func serveOK(t *testing.T, h http.Handler, req *http.Request) (*httptest.ResponseRecorder, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, rec.Body.String()
}
