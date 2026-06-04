// Package sdkguard installs a process-wide assertion that catches the
// recurring failure mode in v1.27.x binaries: a consumer COMPILES (the
// SDK constructor returned no error) but at RUNTIME ends up using the
// wrong client — a plaintext fallback inserted at a level the SDK
// signature can't see.
//
// # The two checks
//
// The v1.27.x contract has two independent verification layers:
//
//  1. The SDK / libs/* constructors return ErrInvalidConfig when their
//     required *http.Client field is nil. This catches "you should have
//     set it" at boot.
//
//  2. sdkguard.AssertMTLS panics (when env-gated to strict mode) if the
//     client a consumer threaded is not actually an mTLS client. This
//     catches "you actually did wire it AND it's the right posture" at
//     runtime — in tests, staging, and CI.
//
// One catches missing wiring; the other catches wrong wiring. Used
// together, the binary cannot enter production with a silent-plaintext
// surface.
//
// # Strict mode
//
// AssertMTLS is a no-op by default — local dev and unit tests run
// against plaintext fixtures and must continue to do so. Setting
//
//	BASEPROOF_FAIL_ON_PLAINTEXT_FALLBACK=true
//
// (or "1", or "yes") flips the package into strict mode: AssertMTLS
// panics on the first plaintext client it sees, naming the call-site
// file:line and the caller-supplied label so the offending wiring is
// trivial to find. The intended use is CI / staging — never production
// (a panic is louder than a config-validation error).
//
// # Detection
//
// "mTLS" here means "the client's Transport is an *http.Transport whose
// TLSClientConfig has at least one client certificate". This is the
// shape libs/clienttls and libs/httpmw/reliability produce.
//
// MIDDLEWARE-WRAPPED TRANSPORTS. Consumers commonly wrap
// the base *http.Transport in a custom RoundTripper for retry / Retry-
// After / tracing middleware. IsMTLSConfigured walks the Unwrap() chain
// (any RoundTripper implementing `Unwrap() http.RoundTripper`, the same
// shape errors.Unwrap uses) so a wrapped *http.Transport at the bottom
// of the chain still surfaces its TLS posture to the detector.
//
// To stay visible to AssertMTLS:
//
//   - Bottom of the chain MUST be an *http.Transport with
//     TLSClientConfig (libs/clienttls.BuildFromEnv produces this).
//   - Every wrapping middleware MUST implement
//     `Unwrap() http.RoundTripper` returning the inner RoundTripper.
//     The stdlib doesn't define this interface, but Go's errors.Unwrap
//     pattern is the convention; sdkguard adopts it for transport
//     introspection.
//
// A middleware that does NOT implement Unwrap is opaque to the
// detector — AssertMTLS sees it as "not mTLS" and panics in strict
// mode. The fix is to add `Unwrap()` to the middleware, not to lower
// the bar.
package sdkguard

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// EnvFailOnPlaintext is the env var that flips sdkguard into strict mode.
// Set to "true", "1", or "yes" (case-insensitive) to make AssertMTLS
// panic on plaintext clients. Unset or any other value → no-op.
const EnvFailOnPlaintext = "BASEPROOF_FAIL_ON_PLAINTEXT_FALLBACK"

// StrictMode reports whether sdkguard is currently in strict mode based
// on the EnvFailOnPlaintext env var. Read once per call (process env
// can change between checks; we honour the LIVE value so a test can
// flip the env mid-run with t.Setenv).
func StrictMode() bool {
	switch strings.ToLower(os.Getenv(EnvFailOnPlaintext)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}

// AssertMTLS panics if sdkguard is in strict mode AND the supplied
// client is not an mTLS client. No-op otherwise. Call this at every
// SDK construction site that REQUIRES mTLS in production — the panic
// message includes the caller's file:line and the supplied label so a
// CI failure points directly at the offending wiring.
//
// label is a short identifier for the call site (e.g. "ledger-submit",
// "horizon-audit", "did:web-resolver"). Required and used only in the
// panic message; pass anything that helps you find the call site.
//
// nil client always panics in strict mode (a nil client is "even more
// plaintext than plaintext" — it would crash with a nil-deref before
// any TLS).
func AssertMTLS(client *http.Client, label string) {
	if !StrictMode() {
		return
	}
	if IsMTLSConfigured(client) {
		return
	}
	_, file, line, _ := runtime.Caller(1)
	panic(fmt.Sprintf(
		"sdkguard: %s: client is not mTLS-configured at %s:%d (set %s=false to disable, "+
			"or wire libs/clienttls.BuildFromEnv with valid CLIENT_CERT_FILE+CLIENT_KEY_FILE)",
		label, file, line, EnvFailOnPlaintext))
}

// transportUnwrapper is the introspection convention sdkguard uses to
// see through middleware. Any RoundTripper wrapping another (retry,
// Retry-After, tracing, metrics, etc.) should implement this so
// AssertMTLS can reach the underlying *http.Transport.
//
// Matches the shape of errors.Unwrap (Go's stdlib convention for
// chain-walking) — a middleware that already implements
// `Unwrap() http.RoundTripper` for any other purpose works here too.
type transportUnwrapper interface {
	Unwrap() http.RoundTripper
}

// maxUnwrapDepth caps the Unwrap chain walk to avoid pathological
// loops in a misimplemented middleware (Unwrap → self, A↔B). 32 is
// deep enough for any realistic production stack (retry + 503 +
// tracing + metrics is 4 layers); a chain longer than this is a
// programming bug, and surfacing it as "not mTLS" forces the bug
// into visibility rather than hiding it behind an infinite loop.
const maxUnwrapDepth = 32

// IsMTLSConfigured returns true iff the client's Transport chain
// terminates in an *http.Transport whose TLSClientConfig carries at
// least one client certificate. Walks `Unwrap() http.RoundTripper`
// through middleware so a wrapped Transport's TLS posture is
// observable.
//
// Returns false for:
//   - nil client
//   - client with nil Transport
//   - chain terminates in something other than *http.Transport (a
//     RoundTripper without Unwrap, or one that returns nil from Unwrap)
//   - *http.Transport with nil TLSClientConfig or empty Certificates
//   - chain longer than maxUnwrapDepth (pathological middleware loop)
func IsMTLSConfigured(client *http.Client) bool {
	if client == nil || client.Transport == nil {
		return false
	}
	t := unwrapToHTTPTransport(client.Transport)
	if t == nil {
		return false
	}
	cfg := t.TLSClientConfig
	if cfg == nil {
		return false
	}
	return clientHasCert(cfg)
}

// unwrapToHTTPTransport walks `rt` through any Unwrap chain and
// returns the underlying *http.Transport if the chain terminates
// in one, or nil otherwise.
//
// The walk is bounded by maxUnwrapDepth so a middleware whose
// Unwrap returns itself (or two middlewares cycling) cannot hang
// the detector — exceeding the bound returns nil ("opaque chain"),
// which AssertMTLS treats identically to "not mTLS".
func unwrapToHTTPTransport(rt http.RoundTripper) *http.Transport {
	for i := 0; rt != nil && i < maxUnwrapDepth; i++ {
		if t, ok := rt.(*http.Transport); ok {
			return t
		}
		u, ok := rt.(transportUnwrapper)
		if !ok {
			return nil
		}
		rt = u.Unwrap()
	}
	return nil
}

// clientHasCert returns true iff cfg carries at least one usable client
// certificate — either an entry in Certificates or a callback that
// dynamically supplies one (GetClientCertificate). Either is enough for
// the server to demand+verify a client cert during the TLS handshake.
func clientHasCert(cfg *tls.Config) bool {
	if cfg == nil {
		return false
	}
	if len(cfg.Certificates) > 0 {
		return true
	}
	if cfg.GetClientCertificate != nil {
		return true
	}
	return false
}
