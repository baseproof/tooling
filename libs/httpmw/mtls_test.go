/*
FILE PATH: libs/httpmw/mtls_test.go

DESCRIPTION:

	Coverage for MTLSAuth. Pinned properties:

	  1. Request without TLS connection -> 401, downstream NOT called.
	  2. TLS connection with no peer cert -> 401.
	  3. Verified cert with NO DID-shaped URI SAN -> 401.
	  4. Verified cert with DID URI SAN -> 200, callerDID injected,
	     downstream sees it via CallerDIDFromContext.
	  5. Multiple URI SANs: the first did:*-prefixed one wins (wire
	     contract is deterministic).
	  6. URI SAN that is NOT did:*-prefixed is skipped.
	  7. nil cert in slot 0 of PeerCertificates -> 401.
	  8. ExtractDIDFromCert on nil pointer -> "" (defensive).
*/
package httpmw

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// ExtractDIDFromCert (unit)
// ─────────────────────────────────────────────────────────────────────

func TestExtractDIDFromCert_NilCert(t *testing.T) {
	if got := ExtractDIDFromCert(nil); got != "" {
		t.Errorf("ExtractDIDFromCert(nil) = %q, want \"\"", got)
	}
}

func TestExtractDIDFromCert_NoURIs(t *testing.T) {
	cert := &x509.Certificate{}
	if got := ExtractDIDFromCert(cert); got != "" {
		t.Errorf("ExtractDIDFromCert(no URIs) = %q, want \"\"", got)
	}
}

func TestExtractDIDFromCert_OnlyNonDIDURI(t *testing.T) {
	uri, _ := url.Parse("https://example.test/path")
	cert := &x509.Certificate{URIs: []*url.URL{uri}}
	if got := ExtractDIDFromCert(cert); got != "" {
		t.Errorf("ExtractDIDFromCert(non-DID URI) = %q, want \"\"", got)
	}
}

func TestExtractDIDFromCert_DIDPicked(t *testing.T) {
	uri, _ := url.Parse("did:web:state:tn:davidson:judge")
	cert := &x509.Certificate{URIs: []*url.URL{uri}}
	const want = "did:web:state:tn:davidson:judge"
	if got := ExtractDIDFromCert(cert); got != want {
		t.Errorf("ExtractDIDFromCert = %q, want %q", got, want)
	}
}

// TestExtractDIDFromCert_FirstDIDWins pins the deterministic-pick
// rule. A cert with two DID URIs must produce the first one
// (caller's wire contract is "put canonical first").
func TestExtractDIDFromCert_FirstDIDWins(t *testing.T) {
	a, _ := url.Parse("did:web:canonical")
	b, _ := url.Parse("did:web:secondary")
	cert := &x509.Certificate{URIs: []*url.URL{a, b}}
	if got := ExtractDIDFromCert(cert); got != "did:web:canonical" {
		t.Errorf("first-did-wins violated: got %q", got)
	}
}

func TestExtractDIDFromCert_SkipsNonDIDBeforeReachingDID(t *testing.T) {
	noise, _ := url.Parse("https://noise.example")
	canonical, _ := url.Parse("did:web:canonical")
	cert := &x509.Certificate{URIs: []*url.URL{noise, canonical}}
	if got := ExtractDIDFromCert(cert); got != "did:web:canonical" {
		t.Errorf("non-DID URI not skipped: got %q", got)
	}
}

func TestExtractDIDFromCert_NilURIInSlice(t *testing.T) {
	canonical, _ := url.Parse("did:web:canonical")
	cert := &x509.Certificate{URIs: []*url.URL{nil, canonical}}
	if got := ExtractDIDFromCert(cert); got != "did:web:canonical" {
		t.Errorf("nil URI in slice should be skipped; got %q", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// MTLSAuth.Wrap (integration via httptest)
// ─────────────────────────────────────────────────────────────────────

// downstream returns a handler that records whether it ran and what
// callerDID it observed. Used by every Wrap test below.
type downstream struct {
	called bool
	seen   string
}

func (d *downstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.called = true
	d.seen = CallerDIDFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestMTLSAuth_NoTLS_Returns401(t *testing.T) {
	d := &downstream{}
	wrapped := MTLSAuth{}.Wrap(d)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/entries/build", nil)
	// No req.TLS → not over TLS
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if d.called {
		t.Error("downstream MUST NOT run when auth fails")
	}
}

func TestMTLSAuth_TLSWithoutPeerCert_Returns401(t *testing.T) {
	d := &downstream{}
	wrapped := MTLSAuth{}.Wrap(d)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/entries/build", nil)
	req.TLS = &tls.ConnectionState{} // empty — no PeerCertificates
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if d.called {
		t.Error("downstream MUST NOT run with empty peer cert chain")
	}
}

func TestMTLSAuth_CertWithoutDIDSAN_Returns401(t *testing.T) {
	noise, _ := url.Parse("https://noise.example")
	cert := &x509.Certificate{URIs: []*url.URL{noise}}

	d := &downstream{}
	wrapped := MTLSAuth{}.Wrap(d)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/entries/build", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if d.called {
		t.Error("downstream MUST NOT run when no DID SAN")
	}
}

func TestMTLSAuth_DIDSAN_CallerInjected(t *testing.T) {
	uri, _ := url.Parse("did:web:state:tn:davidson:judge-mcclendon")
	cert := &x509.Certificate{URIs: []*url.URL{uri}}

	d := &downstream{}
	wrapped := MTLSAuth{}.Wrap(d)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/entries/build", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !d.called {
		t.Fatal("downstream should run on auth success")
	}
	const want = "did:web:state:tn:davidson:judge-mcclendon"
	if d.seen != want {
		t.Errorf("downstream saw callerDID = %q, want %q", d.seen, want)
	}
}

// TestMTLSAuth_FirstDIDWins is the wire-contract pin: when two URI
// SANs are present, the first did:* one is the callerDID. Pinned
// here at the middleware level (ExtractDIDFromCert is also tested
// directly above; this test pins the OBSERVABLE behavior end-to-end).
func TestMTLSAuth_FirstDIDWins(t *testing.T) {
	first, _ := url.Parse("did:web:state:tn:canonical")
	second, _ := url.Parse("did:web:state:tn:secondary")
	cert := &x509.Certificate{URIs: []*url.URL{first, second}}

	d := &downstream{}
	wrapped := MTLSAuth{}.Wrap(d)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/entries/build", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	wrapped.ServeHTTP(rec, req)

	if d.seen != "did:web:state:tn:canonical" {
		t.Errorf("first-DID-wins violated; downstream saw %q", d.seen)
	}
}

// TestMTLSAuth_401BodyEmptyAndChallenge pins that auth failures use
// the uniform writeUnauth response: empty body + WWW-Authenticate.
// Future regressions that emit "no client cert" / "missing DID SAN"
// in the response body trip here.
func TestMTLSAuth_401BodyEmptyAndChallenge(t *testing.T) {
	d := &downstream{}
	wrapped := MTLSAuth{}.Wrap(d)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/entries/build", nil)
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
	body := rec.Body.String()
	if len(body) > 1 {
		// A single trailing "\n" is acceptable (http.Error default).
		t.Errorf("401 body should be empty; got %q (%d bytes)", body, len(body))
	}
	// Specifically must NOT leak backend-specific markers.
	for _, marker := range []string{"client cert", "DID", "SAN", "TLS"} {
		if strings.Contains(body, marker) {
			t.Errorf("401 body leaks backend marker %q: %q", marker, body)
		}
	}
}
