/*
FILE PATH: libs/httpmw/mtls.go

DESCRIPTION:

	mTLS Authenticator. Reads the verified peer certificate from the
	TLS connection and extracts the callerDID from a SAN URI of the
	form did:*. The TLS handshake (already enforced by the listener
	when ClientCAFile is configured at the composer) proves control
	of the cert's private key; this middleware just lifts the proven
	identity into the request context.

	Wire format pinned: cert MUST have at least one URI SAN whose
	string starts with "did:". The first did:-prefixed URI wins. No
	other SAN type (DNS, email, IP) is consulted — DIDs are
	URI-shaped and the cert MUST encode them in the URI SAN per
	RFC 5280 §4.2.1.6.

	Failure modes (all → 401, no body):
	  - No TLS connection (running plain HTTP behind a TLS-terminating
	    proxy without forwarded cert headers)
	  - No verified peer cert (handshake didn't complete or
	    ClientAuth is not RequireAndVerifyClientCert)
	  - Verified cert has no DID-shaped URI SAN

	Composer responsibility: the listener MUST be TLS-enabled with
	tls.RequireAndVerifyClientCert. api/server.go's NewServer takes
	care of this when ClientCAFile is set on Config. Middleware here
	assumes the TLS layer already verified the cert chain.

	Today this middleware shares semantics with
	api/exchange/auth/mtls.ExtractDIDFromCert. We keep the two
	distinct because the existing function lives in a per-handler
	auth package whose lifecycle is tied to api/exchange specifically;
	 here is composer-level. They can converge in a future
	cleanup once api/exchange/auth.SignerAuth is fully retired.
*/
package httpmw

import (
	"crypto/x509"
	"net/http"
	"strings"
)

// MTLSAuth is the mTLS Authenticator. Construct directly via
// MTLSAuth{} (no fields today; future extensions can add e.g., a
// CallerDID extractor for non-SAN-URI cert shapes).
type MTLSAuth struct{}

// Wrap implements Authenticator.Wrap.
//
// Order:
//  1. Verify the request arrived over TLS with a verified peer cert.
//  2. Extract the first did:* URI SAN from the leaf cert.
//  3. Inject into context; fall through to next.
//
// Any failure → 401 Unauthorized with the uniform empty body.
func (m MTLSAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		did := extractDIDFromTLS(r)
		if did == "" {
			writeUnauth(w)
			return
		}
		ctx := WithCallerDID(r.Context(), did)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Compile-time interface check.
var _ Authenticator = MTLSAuth{}

// extractDIDFromTLS lifts the first did:* URI SAN out of the leaf
// peer cert. Returns empty string on any of the failure modes
// documented in the package comment. Exposed package-private so
// tests can drive it without standing up a real TLS listener.
func extractDIDFromTLS(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return ExtractDIDFromCert(r.TLS.PeerCertificates[0])
}

// ExtractDIDFromCert returns the first URI SAN of cert that begins
// with "did:", or empty string if none. Exported so cert-generation
// tooling and tests can reuse the exact extraction logic the
// middleware applies at request time.
//
// Per RFC 5280 §4.2.1.6, URI SANs are full URIs; we accept any URI
// with a "did:" scheme prefix as a callerDID candidate. The first
// match wins to keep the wire contract deterministic — callers that
// embed multiple URI SANs MUST place the canonical DID first.
func ExtractDIDFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		if s := uri.String(); strings.HasPrefix(s, "did:") {
			return s
		}
	}
	return ""
}
