/*
FILE PATH: witnessclient/head_sync_resolver_test.go

PRE-11 Phase B (#114) — Tier C lock tests for the witness-endpoint
SOLE-SOURCE contract.

# WHAT THIS LOCKS

resolveEffectiveEndpoints — the function that decides which witness
URLs HeadSync fans cosignature requests to. After PRE-11 Phase B the
on-log resolver is the ONLY source: there is no LEDGER_WITNESS_ENDPOINTS
config dial-list to fall back to. A static fallback would be the
silent-URL-substitution bypass the on-log WitnessEndpointDeclaration
exists to close (Law 10 — Discovery must fail toward refusal, never
forgery).

Coverage (the fail-direction is the whole point):
  - Resolver returns non-empty → used, source "on_log_resolver".
  - Resolver returns empty      → ERROR (fail-loud, no fallback).
  - Resolver returns an error   → ERROR (propagates, no fallback).
  - Nil resolver                → ERROR (unconstructible, no fallback).
  - The resolver receives the config LogDID (per-log addressing).
  - Returned slice is a defensive copy.

Pure unit tests over the consumer's narrow WitnessEndpointResolver
interface — the documented structural-typing injection point, not the
cryptographic verification boundary (that is the cosign collector,
exercised in head_sync_test.go).
*/
package witnessclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// fakeEndpointResolver implements the narrow WitnessEndpointResolver
// interface declared at the consumer. One method, so the fake is one
// method — validating the structural-typing choice (any code exposing
// WitnessEndpoints(ctx, did) ([]string, error) plugs in).
type fakeEndpointResolver struct {
	urls   []string
	err    error
	called bool
	gotDID string
}

func (f *fakeEndpointResolver) WitnessEndpoints(_ context.Context, logDID string) ([]string, error) {
	f.called = true
	f.gotDID = logDID
	return f.urls, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestResolveEffectiveEndpoints_OnLogResolverIsSoleSource: a wired
// resolver returning a non-empty slice resolves, source "on_log_resolver".
// (The "no env → resolves" half of the PRE-11 Phase B proof.)
func TestResolveEffectiveEndpoints_OnLogResolverIsSoleSource(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver: &fakeEndpointResolver{
			urls: []string{"https://onlog-a", "https://onlog-b"},
		},
		EndpointResolverLogDID: "did:example:log",
	}
	urls, src, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "on_log_resolver" {
		t.Fatalf("source: want on_log_resolver, got %q", src)
	}
	if len(urls) != 2 || urls[0] != "https://onlog-a" || urls[1] != "https://onlog-b" {
		t.Fatalf("urls: want on-log slice, got %v", urls)
	}
}

// TestResolveEffectiveEndpoints_EmptyResolverFailsLoud: resolver wired
// but returns no endpoints (the genesis window before any
// WitnessEndpointDeclaration lands). There is NO canary fallback — the
// cosigner must be unconstructible rather than dial operator config.
// (The "empty → fail-closed" half of the proof.)
func TestResolveEffectiveEndpoints_EmptyResolverFailsLoud(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: nil},
		EndpointResolverLogDID: "did:example:log",
	}
	if _, _, err := resolveEffectiveEndpoints(cfg, discardLogger()); err == nil {
		t.Fatalf("expected fail-loud error when the resolver returns no endpoints")
	}
}

// TestResolveEffectiveEndpoints_ResolverErrorFailsLoud: a resolver
// error propagates (fail-closed). Pre-PRE-11 this fell through to the
// config canary — exactly the silent substitution now forbidden.
func TestResolveEffectiveEndpoints_ResolverErrorFailsLoud(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{err: errors.New("walker dead")},
		EndpointResolverLogDID: "did:example:log",
	}
	if _, _, err := resolveEffectiveEndpoints(cfg, discardLogger()); err == nil {
		t.Fatalf("expected fail-loud error when the resolver errors (no config fallback)")
	}
}

// TestResolveEffectiveEndpoints_NilResolverFailsLoud: no resolver wired
// is a construction error — there is no config dial-list to degrade to.
func TestResolveEffectiveEndpoints_NilResolverFailsLoud(t *testing.T) {
	cfg := HeadSyncConfig{EndpointResolver: nil}
	if _, _, err := resolveEffectiveEndpoints(cfg, discardLogger()); err == nil {
		t.Fatalf("expected fail-loud error when no resolver is wired")
	}
}

// TestResolveEffectiveEndpoints_PassesLogDIDToResolver locks per-log
// addressing: the resolver receives the config's LogDID, not a literal.
func TestResolveEffectiveEndpoints_PassesLogDIDToResolver(t *testing.T) {
	res := &fakeEndpointResolver{urls: []string{"https://ok"}}
	cfg := HeadSyncConfig{
		EndpointResolver:       res,
		EndpointResolverLogDID: "did:example:multitenant:log-7",
	}
	if _, _, err := resolveEffectiveEndpoints(cfg, discardLogger()); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !res.called {
		t.Fatalf("resolver must be called")
	}
	if res.gotDID != "did:example:multitenant:log-7" {
		t.Errorf("resolver got DID %q, want did:example:multitenant:log-7", res.gotDID)
	}
}

// TestResolveEffectiveEndpoints_ResultIsDefensiveCopy guards against
// aliasing: mutating the resolver's source slice must not bleed into
// the returned URLs (which become HeadSync.endpoints).
func TestResolveEffectiveEndpoints_ResultIsDefensiveCopy(t *testing.T) {
	src := []string{"https://onlog-a"}
	cfg := HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: src},
		EndpointResolverLogDID: "did:example:log",
	}
	urls, _, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	src[0] = "https://tampered"
	if urls[0] != "https://onlog-a" {
		t.Fatalf("returned slice must be a defensive copy: got %q after source mutation", urls[0])
	}
}
