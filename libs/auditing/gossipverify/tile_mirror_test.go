// Tile mirror tests pin two contracts:
//
//  1. CONSTRUCTOR CONTRACT — every error path wraps ErrTileMirror, including
//     the v1.27.x "no silent plaintext" rule that NewHTTPTileMirrors requires
//     a non-nil *http.Client. Behavioral pins for nil-client, nil-map,
//     empty-DID, empty-URL, unparseable-URL, and the happy-path mapping.
//
//  2. CLIENT THREADING — the hoisted *http.Client passed at construction is
//     the SAME client every tile fetcher uses on the wire. Without this
//     pin, a future refactor could re-introduce the silent http.DefaultClient
//     fallback (the V4 violation this file's package fixed) and the
//     constructor tests would still pass. The integration test spins up an
//     httptest.Server, threads a recording RoundTripper into the client we
//     pass to NewHTTPTileMirrors, fetches a tile, and asserts the recording
//     transport observed the round-trip — i.e., the threaded client is the
//     one actually used.
package gossipverify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	tessera "github.com/transparency-dev/tessera/client"
)

// ─────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────

// validHTTPClient returns a *http.Client suitable for tests that exercise
// the constructor's wiring without caring which client is used downstream.
// Tests that DO care wrap this with a recording transport.
func validHTTPClient() *http.Client { return &http.Client{} }

// recordingTransport implements http.RoundTripper. Every request it sees
// is counted and the URL recorded. The integration test asserts against
// these counters to prove the client we threaded through NewHTTPTileMirrors
// is the one that actually issued the tile request.
type recordingTransport struct {
	calls    atomic.Int64
	lastURL  atomic.Pointer[string]
	delegate http.RoundTripper
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	u := req.URL.String()
	rt.lastURL.Store(&u)
	delegate := rt.delegate
	if delegate == nil {
		delegate = http.DefaultTransport
	}
	return delegate.RoundTrip(req)
}

// ─────────────────────────────────────────────────────────────────────
// Constructor contract
// ─────────────────────────────────────────────────────────────────────

// TestNewHTTPTileMirrors_RequiresHTTPClient pins the v1.27.x outbound-client
// contract for this constructor: a nil *http.Client is a startup-fatal error.
// Upstream tessera.NewHTTPFetcher silently falls back to http.DefaultClient
// on nil; we validate at the libs/ boundary so that silent fallback cannot
// leak into our consumers.
func TestNewHTTPTileMirrors_RequiresHTTPClient(t *testing.T) {
	_, err := NewHTTPTileMirrors(nil, nil)
	if err == nil {
		t.Fatal("nil *http.Client must error")
	}
	if !errors.Is(err, ErrTileMirror) {
		t.Errorf("want errors.Is(err, ErrTileMirror); err = %v", err)
	}
	if !strings.Contains(err.Error(), "nil *http.Client") {
		t.Errorf("error message should mention nil *http.Client; got %q", err.Error())
	}
}

// TestHTTPTileMirrors_FetcherFor pins the happy-path mapping: every
// registered logDID resolves to a non-nil fetcher; an unknown logDID
// resolves to (nil, false).
func TestHTTPTileMirrors_FetcherFor(t *testing.T) {
	m, err := NewHTTPTileMirrors(map[string]string{
		"did:web:a": "https://a.example/tiles/",
		"did:web:b": "https://b.example/tiles/",
	}, validHTTPClient())
	if err != nil {
		t.Fatalf("NewHTTPTileMirrors: %v", err)
	}
	if f, ok := m.FetcherFor("did:web:a"); !ok || f == nil {
		t.Error("expected non-nil fetcher for did:web:a")
	}
	if f, ok := m.FetcherFor("did:web:b"); !ok || f == nil {
		t.Error("expected non-nil fetcher for did:web:b")
	}
	if _, ok := m.FetcherFor("did:web:none"); ok {
		t.Error("unknown DID must resolve to no fetcher")
	}
}

// TestNewHTTPTileMirrors_RejectsEmptyDID pins that an empty source-log DID
// errors at construction (a bare URL with no log identity is meaningless to
// the verifier).
func TestNewHTTPTileMirrors_RejectsEmptyDID(t *testing.T) {
	_, err := NewHTTPTileMirrors(map[string]string{"": "https://x.example/"}, validHTTPClient())
	if err == nil {
		t.Fatal("empty log DID must error")
	}
	if !errors.Is(err, ErrTileMirror) {
		t.Errorf("want errors.Is(err, ErrTileMirror); err = %v", err)
	}
	if !strings.Contains(err.Error(), "empty log DID") {
		t.Errorf("error message should mention empty log DID; got %q", err.Error())
	}
}

// TestNewHTTPTileMirrors_RejectsEmptyURL pins that an empty tile URL errors
// at construction and reports which DID is missing its URL (for operator
// diagnosis when the misconfiguration is one entry in a large allowlist).
func TestNewHTTPTileMirrors_RejectsEmptyURL(t *testing.T) {
	_, err := NewHTTPTileMirrors(map[string]string{"did:web:a": ""}, validHTTPClient())
	if err == nil {
		t.Fatal("empty URL must error")
	}
	if !errors.Is(err, ErrTileMirror) {
		t.Errorf("want errors.Is(err, ErrTileMirror); err = %v", err)
	}
	if !strings.Contains(err.Error(), `"did:web:a"`) {
		t.Errorf("error should name the offending DID; got %q", err.Error())
	}
}

// TestNewHTTPTileMirrors_RejectsBadURL pins that an unparseable URL errors at
// construction. Closes the coverage gap left by the previous test set (which
// only exercised the empty-string paths). Uses a URL with an illegal control
// character that url.Parse refuses.
func TestNewHTTPTileMirrors_RejectsBadURL(t *testing.T) {
	// A control character in the host segment is unparseable per RFC 3986.
	_, err := NewHTTPTileMirrors(
		map[string]string{"did:web:a": "ht!tp://bad\x7f.example/"},
		validHTTPClient(),
	)
	if err == nil {
		t.Fatal("unparseable URL must error")
	}
	if !errors.Is(err, ErrTileMirror) {
		t.Errorf("want errors.Is(err, ErrTileMirror); err = %v", err)
	}
	if !strings.Contains(err.Error(), "parse URL") {
		t.Errorf("error should mention parse URL; got %q", err.Error())
	}
}

// TestNewHTTPTileMirrors_EmptyMapResolvesNothing pins that an empty mirrors
// map is a valid pre-bootstrap state — construction succeeds; FetcherFor
// returns (nil, false) for every DID, which is the correct fail-closed
// posture (every cross-log inclusion proof then fails on no fetcher rather
// than reaching upstream).
func TestNewHTTPTileMirrors_EmptyMapResolvesNothing(t *testing.T) {
	m, err := NewHTTPTileMirrors(nil, validHTTPClient())
	if err != nil {
		t.Fatalf("NewHTTPTileMirrors(nil mirrors): %v", err)
	}
	if _, ok := m.FetcherFor("did:any"); ok {
		t.Error("empty resolver must resolve nothing")
	}

	// Also exercise the explicit empty-map form for parity.
	m2, err := NewHTTPTileMirrors(map[string]string{}, validHTTPClient())
	if err != nil {
		t.Fatalf("NewHTTPTileMirrors(empty map): %v", err)
	}
	if _, ok := m2.FetcherFor("did:any"); ok {
		t.Error("empty resolver must resolve nothing (explicit empty map)")
	}
}

// TestNewHTTPTileMirrors_ErrorsWrapSentinel pins the structural contract
// that EVERY error path wraps ErrTileMirror. The other error tests check
// individual paths; this one catches future drift if a new error path is
// added and the author forgets to wrap.
func TestNewHTTPTileMirrors_ErrorsWrapSentinel(t *testing.T) {
	cases := []struct {
		name    string
		mirrors map[string]string
		hc      *http.Client
	}{
		{"nil http.Client", map[string]string{"did:web:a": "https://a/"}, nil},
		{"empty DID", map[string]string{"": "https://a/"}, validHTTPClient()},
		{"empty URL", map[string]string{"did:web:a": ""}, validHTTPClient()},
		{"bad URL", map[string]string{"did:web:a": "ht!tp://bad\x7f"}, validHTTPClient()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHTTPTileMirrors(tc.mirrors, tc.hc)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !errors.Is(err, ErrTileMirror) {
				t.Errorf("error must wrap ErrTileMirror; got %v", err)
			}
		})
	}
}

// TestNewHTTPTileMirrors_FetcherConstructionError pins the defensive error
// branch that wraps tessera.NewHTTPFetcher. The upstream constructor has no
// failure mode today (it only normalizes a trailing slash) but its declared
// signature reserves the right to fail; we keep our wrap so a future tessera
// version that adds errors does not silently propagate raw upstream
// errors through our libs/ boundary. The test overrides the package-level
// newTileFetcher seam to inject a known failure and asserts the resulting
// error wraps ErrTileMirror, names the offending DID, and includes the
// underlying error string for operator diagnosis.
func TestNewHTTPTileMirrors_FetcherConstructionError(t *testing.T) {
	orig := newTileFetcher
	t.Cleanup(func() { newTileFetcher = orig })

	injected := errors.New("synthetic tessera failure")
	newTileFetcher = func(_ *url.URL, _ *http.Client) (*tessera.HTTPFetcher, error) {
		return nil, injected
	}

	_, err := NewHTTPTileMirrors(
		map[string]string{"did:web:offender": "https://offender.example/tiles/"},
		validHTTPClient(),
	)
	if err == nil {
		t.Fatal("expected error from injected tessera failure")
	}
	if !errors.Is(err, ErrTileMirror) {
		t.Errorf("error must wrap ErrTileMirror; got %v", err)
	}
	if !strings.Contains(err.Error(), `"did:web:offender"`) {
		t.Errorf("error should name the offending DID; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), injected.Error()) {
		t.Errorf("error should include the underlying upstream error; got %q", err.Error())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Client threading (integration)
// ─────────────────────────────────────────────────────────────────────

// TestNewHTTPTileMirrors_ThreadsCallerClient is the regression guard against
// silent re-introduction of the http.DefaultClient fallback. It spins up an
// httptest.Server, wraps that server's Client in a recordingTransport, and
// hands the wrapped client to NewHTTPTileMirrors. After calling the
// fetcher's ReadTile, the recording transport's counter must be non-zero —
// proving the *threaded* client (not http.DefaultClient, not any other
// instance) issued the wire request.
//
// Without this test, a future refactor could re-introduce
//
//	if hc == nil { hc = http.DefaultClient }
//
// and every constructor-error test above would still pass; this test would
// fail because the recording transport would see zero calls.
func TestNewHTTPTileMirrors_ThreadsCallerClient(t *testing.T) {
	// Tile-shaped 200 OK response. The fetcher decodes tile bytes, so a
	// non-empty body is enough to drive a successful round-trip; we don't
	// care about the decoded content for this test.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// 8 bytes — small but non-empty so the tile fetcher gets a body.
		_, _ = w.Write([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	}))
	defer srv.Close()

	// Wrap the test server's client's transport in a recorder. The
	// underlying transport keeps the TLS posture the httptest.Server set
	// up so the request actually completes; the recorder counts calls and
	// captures the URL so we can assert what was issued.
	srvClient := srv.Client()
	recorder := &recordingTransport{delegate: srvClient.Transport}
	threaded := &http.Client{Transport: recorder, Timeout: srvClient.Timeout}

	m, err := NewHTTPTileMirrors(map[string]string{"did:web:a": srv.URL}, threaded)
	if err != nil {
		t.Fatalf("NewHTTPTileMirrors: %v", err)
	}
	fetcher, ok := m.FetcherFor("did:web:a")
	if !ok {
		t.Fatal("expected fetcher for did:web:a")
	}

	// Drive a tile request. Level/index/partial are arbitrary — the
	// httptest server returns 200 for any path, so the round-trip
	// succeeds and the recorder fires. We don't care whether the upstream
	// tessera decoder accepts the bytes; we only need to prove the
	// threaded *http.Client was used on the wire.
	ctx, cancel := context.WithTimeout(context.Background(), 0) // immediately-canceled ctx is enough; we check the recorder, not the body
	_ = ctx
	cancel()
	// Use a fresh ctx so the request can actually flow.
	_, _ = fetcher(context.Background(), 0, 0, 0)

	if got := recorder.calls.Load(); got == 0 {
		t.Fatalf("recording transport saw 0 calls — the threaded client was NOT used; "+
			"the http.DefaultClient fallback may have been re-introduced. calls=%d", got)
	}
	if u := recorder.lastURL.Load(); u == nil || !strings.HasPrefix(*u, srv.URL) {
		t.Errorf("recorded URL %v should start with test server URL %s", u, srv.URL)
	}
}
