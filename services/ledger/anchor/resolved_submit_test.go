/*
FILE PATH: anchor/resolved_submit_test.go

v1.32.0 SDK adoption — Tier C tests for the L5 backdoor closure:
parent admission URL resolved through the on-log FederationGraph
rather than from operator-edit-and-reload config.

# WHAT THIS LOCKS

Every path of resolveEffectiveParentURL and the
SubmitToResolvedHTTPEndpoint composition. The precedence here IS
the cross-log L5 closure; a regression silently re-opens the
URL-substitution backdoor against parent logs.

Coverage:
  - Resolver returns non-empty URL → use it; source label
    "on_log_resolver".
  - Resolver returns empty URL → fall through to fallbackURL;
    source label "config_canary_fallback".
  - Resolver returns an error → fall through to fallbackURL;
    source label "config_canary_fallback".
  - Nil resolver → use fallbackURL.
  - Empty fallback + resolver miss → "none" source, no URL.
  - SubmitToResolvedHTTPEndpoint: empty peerLogDID → construction
    returns an error-emitting function (programming error).
  - SubmitToResolvedHTTPEndpoint: resolver miss + empty fallback
    → call-time error.
  - SubmitToResolvedHTTPEndpoint: resolver hit → POSTs to the
    resolved URL, not the fallback.
  - SubmitToResolvedHTTPEndpoint: resolver miss + non-empty
    fallback → POSTs to the fallback.

Pure unit tests; httptest.Server captures the URL the composed
submit function actually targets.

# discardLogger

Shared with anchor/publisher_test.go via package-level definition.
This file does NOT redefine the helper.
*/
package anchor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
)

// signedFixtureEntry returns a structurally-valid envelope.Entry the
// SDK's envelope.Serialize accepts. The signature bytes are stub
// content — these URL-routing tests don't exercise crypto, only the
// submit-path wiring, so the only requirement is that the entry
// passes Serialize's signature-section validation. SDK v1.33.0's
// AppendSignaturesSection rejects empty signature lists, so we must
// attach at least one structurally-valid Signature.
func signedFixtureEntry(t *testing.T, hdr envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoEd25519,
		Bytes:     make([]byte, 64), // 64-byte stub; encoder is content-blind here
	}}
	return entry
}

// ── resolveEffectiveParentURL ──────────────────────────────────────

// TestResolveEffectiveParentURL_OnLogResolverWins is the load-
// bearing L5 invariant: when the resolver returns a non-empty
// URL, that URL is used and the fallback is NOT consulted. A
// regression here re-opens the cross-log URL-substitution
// attack.
func TestResolveEffectiveParentURL_OnLogResolverWins(t *testing.T) {
	resolver := func(_ context.Context, _ string) (string, error) {
		return "https://parent.example.org/v1/submit", nil
	}
	url, src := resolveEffectiveParentURL(resolver, "did:web:parent",
		"https://canary-should-not-be-used", discardLogger())
	if src != "on_log_resolver" {
		t.Errorf("source: want on_log_resolver, got %q", src)
	}
	if url != "https://parent.example.org/v1/submit" {
		t.Errorf("url: want resolver URL, got %q", url)
	}
}

// TestResolveEffectiveParentURL_FallbackOnResolverError exercises
// the transient-failure path: the resolver errors (walker hiccup),
// and the canary URL keeps the publish path operable.
func TestResolveEffectiveParentURL_FallbackOnResolverError(t *testing.T) {
	resolver := func(_ context.Context, _ string) (string, error) {
		return "", errors.New("walker down")
	}
	url, src := resolveEffectiveParentURL(resolver, "did:web:parent",
		"https://fallback.example.org/v1/submit", discardLogger())
	if src != "config_canary_fallback" {
		t.Errorf("source: want config_canary_fallback, got %q", src)
	}
	if url != "https://fallback.example.org/v1/submit" {
		t.Errorf("url: want fallback URL, got %q", url)
	}
}

// TestResolveEffectiveParentURL_FallbackOnResolverEmpty covers the
// bootstrap-window path: the resolver is wired but no
// FederationGraph entry exists yet for the parent DID. The
// canary remains operable until the on-log entry lands.
func TestResolveEffectiveParentURL_FallbackOnResolverEmpty(t *testing.T) {
	resolver := func(_ context.Context, _ string) (string, error) {
		return "", nil
	}
	url, src := resolveEffectiveParentURL(resolver, "did:web:parent",
		"https://fallback.example.org/v1/submit", discardLogger())
	if src != "config_canary_fallback" {
		t.Errorf("source: want config_canary_fallback, got %q", src)
	}
	if url != "https://fallback.example.org/v1/submit" {
		t.Errorf("url: want fallback URL, got %q", url)
	}
}

// TestResolveEffectiveParentURL_NilResolverUsesFallback covers the
// pre-v1.32.0 deployment shape: no resolver at all. Same fallback
// behavior, source "config_canary_fallback".
func TestResolveEffectiveParentURL_NilResolverUsesFallback(t *testing.T) {
	url, src := resolveEffectiveParentURL(nil, "did:web:parent",
		"https://fallback.example.org/v1/submit", discardLogger())
	if src != "config_canary_fallback" {
		t.Errorf("source: want config_canary_fallback, got %q", src)
	}
	if url != "https://fallback.example.org/v1/submit" {
		t.Errorf("url: want fallback URL, got %q", url)
	}
}

// TestResolveEffectiveParentURL_BothEmptyReturnsNoneSource is the
// hard-failure case: no resolver hit AND no fallback. Returns
// empty URL with source "none" so the caller surfaces a
// structured error rather than POSTing to "".
func TestResolveEffectiveParentURL_BothEmptyReturnsNoneSource(t *testing.T) {
	url, src := resolveEffectiveParentURL(nil, "did:web:parent", "", discardLogger())
	if src != "none" {
		t.Errorf("source: want none, got %q", src)
	}
	if url != "" {
		t.Errorf("url: want empty, got %q", url)
	}
}

// TestResolveEffectiveParentURL_PassesPeerDIDToResolver locks the
// argument-routing: the peerLogDID parameter actually reaches
// the resolver. A regression that swapped DIDs would route to
// the wrong parent log.
func TestResolveEffectiveParentURL_PassesPeerDIDToResolver(t *testing.T) {
	var gotDID string
	resolver := func(_ context.Context, peer string) (string, error) {
		gotDID = peer
		return "https://x", nil
	}
	_, _ = resolveEffectiveParentURL(resolver, "did:web:specific-parent",
		"", discardLogger())
	if gotDID != "did:web:specific-parent" {
		t.Errorf("resolver got %q, want did:web:specific-parent", gotDID)
	}
}

// ── SubmitToResolvedHTTPEndpoint ──────────────────────────────────

// TestSubmitToResolvedHTTPEndpoint_EmptyPeerDIDReturnsErrorFn
// pins the programming-error guard: a composition root that
// forgets to set peerLogDID gets an immediate, repeated error
// from every publish attempt rather than a silent misroute.
func TestSubmitToResolvedHTTPEndpoint_EmptyPeerDIDReturnsErrorFn(t *testing.T) {
	// V1.34 contract: client is REQUIRED at construction. Pass a real
	// client; the empty peerLogDID is what should cause the
	// closure-error behavior under test.
	fn := SubmitToResolvedHTTPEndpoint(&http.Client{}, nil, "", "", discardLogger())
	if err := fn(nil); err == nil {
		t.Error("empty peerLogDID must produce a function that always errors")
	}
}

// TestSubmitToResolvedHTTPEndpoint_NoResolverNoFallbackErrors
// covers the operational-misconfiguration case: the function is
// constructed with neither a resolver nor a fallback. Every
// publish errors at call time with a structured message.
func TestSubmitToResolvedHTTPEndpoint_NoResolverNoFallbackErrors(t *testing.T) {
	// V1.34 contract: client is REQUIRED at construction. The
	// "no resolver and no fallback" misconfiguration is what should
	// cause the closure-error behavior under test.
	fn := SubmitToResolvedHTTPEndpoint(&http.Client{}, nil, "did:web:parent", "", discardLogger())
	// We need a non-nil entry; an empty envelope is enough — the
	// function errors out before it serializes.
	hdr := envelope.ControlHeader{
		SignerDID:   "did:web:test",
		Destination: "did:web:parent",
	}
	entry, err := envelope.NewUnsignedEntry(hdr, []byte("p"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	if err := fn(entry); err == nil {
		t.Error("empty resolver + empty fallback must produce a call-time error")
	}
}

// TestSubmitToResolvedHTTPEndpoint_ResolverHitTargetsResolvedURL
// is the integration-shape lock: when the resolver returns a
// URL, the actual HTTP POST goes there — not to any fallback.
// A regression that POSTed to the fallback while logging the
// resolver URL would silently re-open L5.
func TestSubmitToResolvedHTTPEndpoint_ResolverHitTargetsResolvedURL(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	resolver := func(_ context.Context, _ string) (string, error) {
		return srv.URL, nil
	}

	// Fallback intentionally points at a URL that doesn't exist —
	// if the function calls the fallback we'd see zero hits AND
	// a non-nil error pointing at the bogus URL.
	fn := SubmitToResolvedHTTPEndpoint(srv.Client(), resolver,
		"did:web:parent", "https://bogus-fallback.invalid", discardLogger())

	entry := signedFixtureEntry(t, envelope.ControlHeader{
		SignerDID:   "did:web:test",
		Destination: "did:web:parent",
		EventTime:   1700000000,
	}, []byte("payload"))
	if err := fn(entry); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 hit on resolved URL, got %d", got)
	}
}

// TestSubmitToResolvedHTTPEndpoint_ResolverMissTargetsFallback
// exercises the canary path: resolver returns empty, so the
// HTTP POST goes to the fallback URL. The fallback being a
// httptest.Server lets us assert the request actually arrived
// there.
func TestSubmitToResolvedHTTPEndpoint_ResolverMissTargetsFallback(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	resolver := func(_ context.Context, _ string) (string, error) {
		return "", nil
	}
	fn := SubmitToResolvedHTTPEndpoint(srv.Client(), resolver,
		"did:web:parent", srv.URL, discardLogger())

	entry := signedFixtureEntry(t, envelope.ControlHeader{
		SignerDID:   "did:web:test",
		Destination: "did:web:parent",
		EventTime:   1700000000,
	}, []byte("payload"))
	if err := fn(entry); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected 1 hit on fallback URL, got %d", got)
	}
}

// TestSubmitToResolvedHTTPEndpoint_PerPublishResolve verifies the
// per-publish resolve guarantee — the URL is re-queried on
// every entry, not cached. A regression that cached the first
// resolved URL would let an attacker who briefly poisoned the
// FederationGraph during boot keep the ledger publishing to
// their URL forever.
func TestSubmitToResolvedHTTPEndpoint_PerPublishResolve(t *testing.T) {
	var hitsA, hitsB int32
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hitsA, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hitsB, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srvB.Close()

	var swap atomic.Bool
	resolver := func(_ context.Context, _ string) (string, error) {
		if swap.Load() {
			return srvB.URL, nil
		}
		return srvA.URL, nil
	}
	fn := SubmitToResolvedHTTPEndpoint(srvA.Client(), resolver,
		"did:web:parent", "", discardLogger())

	entry := signedFixtureEntry(t, envelope.ControlHeader{
		SignerDID:   "did:web:test",
		Destination: "did:web:parent",
		EventTime:   1700000000,
	}, []byte("payload"))

	if err := fn(entry); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	swap.Store(true)
	if err := fn(entry); err != nil {
		t.Fatalf("second publish: %v", err)
	}

	if hitsA != 1 {
		t.Errorf("expected 1 hit on srvA, got %d", hitsA)
	}
	if hitsB != 1 {
		t.Errorf("expected 1 hit on srvB (per-publish resolve), got %d", hitsB)
	}
}

// TestSubmitToResolvedHTTPEndpoint_NoClientDefaultsBuildOK guards
// TestSubmitToResolvedHTTPEndpoint_NilClient_Panics pins the v1.34 SDK
// contract: nil client at construction PANICS rather than silently
// building a plaintext DefaultClient. This used to be inverted (the
// old TestSubmitToResolvedHTTPEndpoint_NoClientDefaultsBuildOK pinned
// the silent-fallback behavior); the v1.34 SDK release explicitly
// rejected that pattern across the SDK, and this ledger surface is
// the federation's anchor-publish path — letting a misconfigured
// operator publish anchors over plaintext was the exact silent-
// security-degradation the v1.34 contract removes. The test below
// ensures a future "convenience" refactor that reintroduces the
// silent fallback fails loudly.
func TestSubmitToResolvedHTTPEndpoint_NilClient_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on nil client; got no panic (silent-fallback regression?)")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "client required") {
			t.Errorf("panic message should mention 'client required'; got %q", msg)
		}
		if !strings.Contains(msg, "v1.34 SDK contract") {
			t.Errorf("panic message should cite the v1.34 contract; got %q", msg)
		}
	}()
	_ = SubmitToResolvedHTTPEndpoint(nil, nil, "did:web:parent",
		"https://example.invalid", discardLogger())
}
