/*
Package middleware provides composer-level HTTP middleware for the
api/ surface. The two responsibilities split into separate files:

  - identity.go  the canonical context key for "the authenticated
    callerDID" + the Authenticator interface every
    auth backend implements.
  - mtls.go      mTLS authenticator: extracts callerDID from the
    client cert's SAN URI.
  - jwt.go       JWT authenticator: verifies a Bearer token against
    a JWKS endpoint, extracts callerDID from the
    token's `sub` claim.

Composer-level vs handler-level: this package's middleware runs at
api/server.go's parent mux, BEFORE delegation to api/exchange or
api/verification. It establishes callerDID once per request; every
downstream handler reads the same context value via
CallerDIDFromContext.

Why a new package vs reusing api/exchange/auth: the existing package
is mTLS+signed-envelope auth wired per exchange handler, with on-log
delegation checks.  adds a thinner, composer-level layer that
only establishes identity. Per-handler authorization (e.g., scope
checking, delegation liveness) is a separate concern that runs after.
*/
package httpmw

import (
	"context"
	"errors"
	"net/http"
)

// ─────────────────────────────────────────────────────────────────────
// Context key
// ─────────────────────────────────────────────────────────────────────

// callerDIDKey is the unexported context key for the authenticated
// callerDID. Unexported so no external package can set it without
// going through WithCallerDID — preventing accidental DID injection
// via context.WithValue from unaudited code paths.
type callerDIDKey struct{}

// WithCallerDID attaches an authenticated callerDID to ctx and
// returns the augmented context. Every Authenticator calls this on
// success; downstream handlers read via CallerDIDFromContext.
//
// Empty did is a no-op (returns ctx unchanged) so middleware can
// blindly call WithCallerDID on whatever it extracted without first
// branching on emptiness.
func WithCallerDID(ctx context.Context, did string) context.Context {
	if did == "" {
		return ctx
	}
	return context.WithValue(ctx, callerDIDKey{}, did)
}

// CallerDIDFromContext returns the authenticated callerDID, or the
// empty string if no Authenticator has set one (request bypassed the
// auth middleware, e.g., /healthz, or the middleware was not wired).
func CallerDIDFromContext(ctx context.Context) string {
	did, _ := ctx.Value(callerDIDKey{}).(string)
	return did
}

// ─────────────────────────────────────────────────────────────────────
// Authenticator interface
// ─────────────────────────────────────────────────────────────────────

// Authenticator wraps an http.Handler with auth verification. On
// success the wrapped handler runs with WithCallerDID applied to
// the request context. On failure the response is 401 with no body
// — middlewares MUST NOT leak diagnostic information back to
// unauthenticated callers.
//
// Concrete impls in this package: MTLSAuth (mtls.go), JWTAuth (jwt.go).
type Authenticator interface {
	Wrap(next http.Handler) http.Handler
}

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrUnauthenticated is the canonical sentinel an Authenticator
// returns from its internal verify step when the request fails auth.
// The HTTP layer translates this to a 401 with no body. Other errors
// (e.g., infrastructure failure fetching JWKS) map to 500.
var ErrUnauthenticated = errors.New("middleware: unauthenticated")

// writeUnauth writes a uniform 401 response. Middlewares share this
// helper so the wire response is identical regardless of auth backend
// — preventing fingerprinting based on differing 401 body shapes.
func writeUnauth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "", http.StatusUnauthorized)
}
