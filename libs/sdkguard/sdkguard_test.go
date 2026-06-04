// Package sdkguard tests pin the strict-mode contract:
//   - Off by default: AssertMTLS is a no-op for every client (including nil)
//   - Strict mode on (env=true/1/yes): AssertMTLS panics on plaintext / nil /
//     custom-Transport / no-client-cert clients
//   - Strict mode on + a real mTLS client: AssertMTLS is a no-op
//   - IsMTLSConfigured reports the same booleans the panic policy uses
package sdkguard

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeCert is a syntactically-valid tls.Certificate (empty cert chain
// allowed for detection purposes; the detector only cares that the
// Certificates slice is non-empty / GetClientCertificate is non-nil).
var fakeCert = tls.Certificate{}

// mtlsClient builds a client whose Transport carries a client certificate.
// Mirrors what libs/httpmw/reliability.NewMTLSClient produces.
func mtlsClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{fakeCert},
			},
		},
	}
}

// mtlsClientViaCallback builds a client whose Transport supplies a client
// cert dynamically. The detector must treat this as mTLS-configured (the
// SDK's ClientTLSConfig path uses a callback for hot-reload).
func mtlsClientViaCallback() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &fakeCert, nil
				},
			},
		},
	}
}

// plainClient is the anti-pattern — &http.Client{} with no transport.
// Detector must treat it as plaintext.
func plainClient() *http.Client {
	return &http.Client{}
}

// plainClientWithTLSConfigButNoCerts pins a subtle case: the Transport HAS
// a TLSClientConfig (the server might pin its own roots there) but carries
// no CLIENT certificate, so it cannot present one in the handshake. The
// detector must report this as NOT mTLS.
func plainClientWithTLSConfigButNoCerts() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// recordingRoundTripper is a custom Transport — the detector cannot see
// through it and must report it as NOT mTLS (it could be anything).
type recordingRoundTripper struct{}

func (recordingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

func customTransportClient() *http.Client {
	return &http.Client{Transport: recordingRoundTripper{}}
}

// TestStrictMode_EnvParsing pins the env truth table.
func TestStrictMode_EnvParsing(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", false},
		{"false", false},
		{"0", false},
		{"no", false},
		{"random", false},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"YES", true},
	}
	for _, tc := range cases {
		t.Setenv(EnvFailOnPlaintext, tc.env)
		if got := StrictMode(); got != tc.want {
			t.Errorf("env=%q: StrictMode() = %v, want %v", tc.env, got, tc.want)
		}
	}
}

// TestAssertMTLS_NoopWhenStrictOff pins that the detector is silent in
// the default mode — local dev and tests run against plaintext fixtures
// and must NEVER see a panic.
func TestAssertMTLS_NoopWhenStrictOff(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "")
	// nil and plaintext clients must both be tolerated.
	AssertMTLS(nil, "test-noop-nil")
	AssertMTLS(plainClient(), "test-noop-plain")
	AssertMTLS(customTransportClient(), "test-noop-custom")
}

// TestAssertMTLS_PanicOnPlaintext pins the core strict-mode behaviour.
func TestAssertMTLS_PanicOnPlaintext(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on plaintext client in strict mode")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "test-plain-label") {
			t.Errorf("panic message missing label: %q", msg)
		}
		if !strings.Contains(msg, EnvFailOnPlaintext) {
			t.Errorf("panic message missing env-var hint: %q", msg)
		}
	}()
	AssertMTLS(plainClient(), "test-plain-label")
}

// TestAssertMTLS_PanicOnNil pins that nil is treated as plaintext (in
// fact worse — it would nil-deref before TLS).
func TestAssertMTLS_PanicOnNil(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "1")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil client in strict mode")
		}
	}()
	AssertMTLS(nil, "test-nil-label")
}

// TestAssertMTLS_PanicOnTLSConfigWithoutCerts pins the subtle case: a
// TLSClientConfig without client certs still cannot present one in the
// handshake. Must panic.
func TestAssertMTLS_PanicOnTLSConfigWithoutCerts(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "yes")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on TLS-config-without-client-certs in strict mode")
		}
	}()
	AssertMTLS(plainClientWithTLSConfigButNoCerts(), "test-no-certs")
}

// TestAssertMTLS_PanicOnCustomTransport pins that an opaque RoundTripper
// is not auto-trusted — we can't see through it, so we panic.
func TestAssertMTLS_PanicOnCustomTransport(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on custom Transport in strict mode")
		}
	}()
	AssertMTLS(customTransportClient(), "test-custom-rt")
}

// TestAssertMTLS_OKWithCert pins that a real mTLS client passes — strict
// mode is not a blanket "panic on any client", it specifically catches
// the plaintext-fallback shape.
func TestAssertMTLS_OKWithCert(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	// Should NOT panic — both static and dynamic cert sources count.
	AssertMTLS(mtlsClient(), "test-ok-static")
	AssertMTLS(mtlsClientViaCallback(), "test-ok-dynamic")
}

// TestIsMTLSConfigured_TruthTable pins the boolean independently of the
// panic policy (so callers can use it for logging / metrics regardless of
// strict mode).
func TestIsMTLSConfigured_TruthTable(t *testing.T) {
	cases := []struct {
		name   string
		client *http.Client
		want   bool
	}{
		{"nil", nil, false},
		{"plain", plainClient(), false},
		{"tls-config-no-certs", plainClientWithTLSConfigButNoCerts(), false},
		{"custom-transport", customTransportClient(), false},
		{"mtls-static-cert", mtlsClient(), true},
		{"mtls-callback-cert", mtlsClientViaCallback(), true},
	}
	for _, tc := range cases {
		if got := IsMTLSConfigured(tc.client); got != tc.want {
			t.Errorf("%s: IsMTLSConfigured = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAssertMTLS_PanicIncludesCallerLocation pins that the panic message
// names the file:line of the AssertMTLS call site — that's the whole
// point of the package vs. an opaque error.
func TestAssertMTLS_PanicIncludesCallerLocation(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		msg, _ := r.(string)
		// The message must reference this test file so the operator
		// can find the offending call site.
		if !strings.Contains(msg, "sdkguard_test.go") {
			t.Errorf("panic missing caller file:line: %q", msg)
		}
	}()
	AssertMTLS(plainClient(), "test-caller-location")
}

// ─────────────────────────────────────────────────────────────────────
// Unwrap chain walking
// ─────────────────────────────────────────────────────────────────────

// unwrappingMiddleware wraps an inner RoundTripper and implements
// `Unwrap() http.RoundTripper`. Matches the convention sdkguard's
// transportUnwrapper looks for (same shape as errors.Unwrap).
type unwrappingMiddleware struct{ inner http.RoundTripper }

func (m unwrappingMiddleware) RoundTrip(r *http.Request) (*http.Response, error) {
	return m.inner.RoundTrip(r)
}
func (m unwrappingMiddleware) Unwrap() http.RoundTripper { return m.inner }

// TestIsMTLSConfigured_SeesThroughSingleUnwrap pins that a single
// middleware layer wrapping an mTLS *http.Transport surfaces as
// mTLS-configured.
func TestIsMTLSConfigured_SeesThroughSingleUnwrap(t *testing.T) {
	base := mtlsClient()
	wrapped := &http.Client{
		Transport: unwrappingMiddleware{inner: base.Transport},
	}
	if !IsMTLSConfigured(wrapped) {
		t.Error("single Unwrap layer should expose mTLS posture; got false")
	}
}

// TestIsMTLSConfigured_SeesThroughChainedUnwrap pins multi-layer
// middleware (e.g., retry → Retry-After → tracing). Each layer
// implements Unwrap; the chain terminates in the *http.Transport.
func TestIsMTLSConfigured_SeesThroughChainedUnwrap(t *testing.T) {
	base := mtlsClient()
	chained := &http.Client{
		Transport: unwrappingMiddleware{
			inner: unwrappingMiddleware{
				inner: unwrappingMiddleware{
					inner: base.Transport,
				},
			},
		},
	}
	if !IsMTLSConfigured(chained) {
		t.Error("3-layer Unwrap chain should expose mTLS posture; got false")
	}
}

// TestIsMTLSConfigured_UnwrapChainTerminatesInOpaqueRT pins that a
// chain terminating in a NON-Unwrap, non-*http.Transport surfaces
// as not-mTLS. The middleware is observable; what's underneath isn't,
// so the detector fails closed.
func TestIsMTLSConfigured_UnwrapChainTerminatesInOpaqueRT(t *testing.T) {
	opaque := recordingRoundTripper{}
	wrapped := &http.Client{
		Transport: unwrappingMiddleware{inner: opaque},
	}
	if IsMTLSConfigured(wrapped) {
		t.Error("chain terminating in opaque RT must NOT report mTLS; got true")
	}
}

// selfLoopRT returns itself from Unwrap — pathological middleware.
// The detector's depth cap (maxUnwrapDepth) MUST prevent an infinite
// loop and return false ("opaque chain").
type selfLoopRT struct{}

func (r selfLoopRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (r selfLoopRT) Unwrap() http.RoundTripper                       { return r }

// TestIsMTLSConfigured_UnwrapSelfLoopBoundedByDepth pins that a
// pathological self-loop is bounded by maxUnwrapDepth + returns false.
// Without the cap the detector would hang forever.
func TestIsMTLSConfigured_UnwrapSelfLoopBoundedByDepth(t *testing.T) {
	loop := &http.Client{Transport: selfLoopRT{}}
	// Use a channel + goroutine timeout to detect a hang regression.
	done := make(chan bool, 1)
	go func() {
		done <- IsMTLSConfigured(loop)
	}()
	select {
	case got := <-done:
		if got {
			t.Error("self-loop chain must NOT report mTLS")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IsMTLSConfigured hung on self-loop — depth cap not enforced")
	}
}

// TestAssertMTLS_PassesThroughUnwrappedMTLSInStrictMode pins the
// integration: AssertMTLS sees an mTLS Transport wrapped in middleware
// and does NOT panic in strict mode.
func TestAssertMTLS_PassesThroughUnwrappedMTLSInStrictMode(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	wrapped := &http.Client{
		Transport: unwrappingMiddleware{inner: mtlsClient().Transport},
	}
	// MUST NOT panic.
	AssertMTLS(wrapped, "test-wrapped-mtls")
}
