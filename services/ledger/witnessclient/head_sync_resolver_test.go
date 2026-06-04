/*
FILE PATH: witnessclient/head_sync_resolver_test.go

v1.32.0 SDK adoption — Tier C tests for the L1 backdoor closure:
on-log WitnessEndpointResolver precedence over the config-driven
LEDGER_WITNESS_ENDPOINTS canary fallback.

# WHAT THIS LOCKS

Every path of resolveEffectiveEndpoints — the function that
decides which set of witness URLs HeadSync ends up fanning
cosignature requests to. The precedence here IS the backdoor
closure; if it regresses, the ledger silently goes back to
trusting deployment config for a load-bearing security input.

Coverage:
  - On-log resolver returns non-empty → resolver wins, source
    label "on_log_resolver".
  - On-log resolver returns empty → fall through to config
    canary, source label "config_canary_fallback".
  - On-log resolver returns an error → fall through to config
    canary, source label "config_canary_fallback".
  - Empty EndpointResolverLogDID → resolver path skipped entirely
    (defense against half-wired deployments).
  - Nil resolver → config canary used directly.
  - Both resolver empty AND config empty → constructor error
    (refuse to wire a zero-endpoint collector).
  - Returned slice is a defensive copy (mutating the source
    slice does NOT poison the returned URLs).

Pure unit tests; no DB, no HTTP, no SDK transport. The L1 contract
under test is the SELECTION rule, not the cosignature collection
path (which is exercised by the existing head_sync_test.go).
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
// interface declared at the consumer (witnessclient.WitnessEndpointResolver).
// We deliberately do NOT depend on the SDK's
// *discover.DefaultAuthoritativeResolver — the consumer interface
// is one method, so the test fake is one method. This validates
// the structural-typing choice: any code that exposes
// WitnessEndpoints(ctx, did) ([]string, error) plugs in.
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

// TestResolveEffectiveEndpoints_OnLogResolverWins is the load-
// bearing L1 invariant: when the resolver returns a non-empty
// slice, that slice is used; the canary fallback is NOT consulted.
// A regression here means an operator could silently route witness
// traffic to attacker-controlled URLs by editing
// LEDGER_WITNESS_ENDPOINTS — the exact backdoor the SDK's
// WitnessEndpointDeclarationV1 was designed to close.
func TestResolveEffectiveEndpoints_OnLogResolverWins(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver: &fakeEndpointResolver{
			urls: []string{"https://onlog-a", "https://onlog-b"},
		},
		EndpointResolverLogDID: "did:example:log",
		WitnessEndpoints:       []string{"https://canary-should-not-be-used"},
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

// TestResolveEffectiveEndpoints_FallbackWhenResolverEmpty exercises
// the bootstrap-window path: resolver wired, but no
// WitnessEndpointDeclarationV1 entries on-log yet. The canary
// MUST be used so the ledger remains operable; refusing to start
// here would force operators to redeploy with empty resolver
// config just to get the canary back.
func TestResolveEffectiveEndpoints_FallbackWhenResolverEmpty(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: nil},
		EndpointResolverLogDID: "did:example:log",
		WitnessEndpoints:       []string{"https://canary"},
	}
	urls, src, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "config_canary_fallback" {
		t.Fatalf("source: want config_canary_fallback, got %q", src)
	}
	if len(urls) != 1 || urls[0] != "https://canary" {
		t.Fatalf("urls: want canary slice, got %v", urls)
	}
}

// TestResolveEffectiveEndpoints_FallbackWhenResolverErrors mirrors
// the empty case but with an error return — same fallback
// behavior. The error MUST NOT propagate to the caller because
// a transient resolver outage during ledger boot would crash-
// loop the binary; the canary keeps it alive.
func TestResolveEffectiveEndpoints_FallbackWhenResolverErrors(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{err: errors.New("walker dead")},
		EndpointResolverLogDID: "did:example:log",
		WitnessEndpoints:       []string{"https://canary"},
	}
	urls, src, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "config_canary_fallback" {
		t.Fatalf("source: want config_canary_fallback, got %q", src)
	}
	if len(urls) != 1 || urls[0] != "https://canary" {
		t.Fatalf("urls: want canary slice, got %v", urls)
	}
}

// TestResolveEffectiveEndpoints_NilResolverUsesFallback covers the
// pre-v1.32.0 deployment shape: no resolver wired at all. The
// canary must be used silently — this is the migration-window
// behaviour for ledgers running the new code but without the new
// wire-up.
func TestResolveEffectiveEndpoints_NilResolverUsesFallback(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver: nil,
		WitnessEndpoints: []string{"https://canary"},
	}
	urls, src, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "config_canary_fallback" {
		t.Fatalf("source: want config_canary_fallback, got %q", src)
	}
	if len(urls) != 1 {
		t.Fatalf("urls: want canary slice, got %v", urls)
	}
}

// TestResolveEffectiveEndpoints_EmptyLogDIDSkipsResolver verifies
// the half-wired-deployment defense: an EndpointResolver pointer
// is set but EndpointResolverLogDID is "". Without the DID we
// cannot identify which log's endpoints to fetch, so the
// resolver path is skipped without consulting the resolver. The
// resolver's WitnessEndpoints method MUST NOT be called.
func TestResolveEffectiveEndpoints_EmptyLogDIDSkipsResolver(t *testing.T) {
	res := &fakeEndpointResolver{urls: []string{"https://should-not-be-used"}}
	cfg := HeadSyncConfig{
		EndpointResolver:       res,
		EndpointResolverLogDID: "",
		WitnessEndpoints:       []string{"https://canary"},
	}
	urls, src, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src != "config_canary_fallback" {
		t.Fatalf("source: want config_canary_fallback, got %q", src)
	}
	if len(urls) != 1 || urls[0] != "https://canary" {
		t.Fatalf("urls: want canary slice, got %v", urls)
	}
	if res.called {
		t.Errorf("resolver MUST NOT be called when EndpointResolverLogDID is empty")
	}
}

// TestResolveEffectiveEndpoints_BothEmptyErrors exercises the
// hard-failure case: resolver returns empty AND no canary set.
// The constructor must refuse to wire a zero-endpoint collector —
// silently building one would route every cosignature request to
// the void and fail every commit cycle without a clear cause.
func TestResolveEffectiveEndpoints_BothEmptyErrors(t *testing.T) {
	cfg := HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: nil},
		EndpointResolverLogDID: "did:example:log",
		WitnessEndpoints:       nil,
	}
	_, _, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err == nil {
		t.Fatalf("expected error when both sources empty")
	}
}

// TestResolveEffectiveEndpoints_PassesLogDIDToResolver locks the
// argument-routing: the resolver receives the LogDID from the
// config, not some hardcoded value. A regression that swapped
// the field for an incorrect literal would break per-log
// addressing in multi-tenant deployments.
func TestResolveEffectiveEndpoints_PassesLogDIDToResolver(t *testing.T) {
	res := &fakeEndpointResolver{urls: []string{"https://ok"}}
	cfg := HeadSyncConfig{
		EndpointResolver:       res,
		EndpointResolverLogDID: "did:example:multitenant:log-7",
	}
	_, _, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
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
// aliasing bugs: the returned slice must NOT share underlying
// storage with the source. A mutation through the source slice
// would otherwise corrupt the persisted HeadSync.endpoints field
// and silently route subsequent cosignature requests to whatever
// the mutated URL is.
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
	// Mutate the underlying source — must not bleed into urls.
	src[0] = "https://tampered"
	if urls[0] != "https://onlog-a" {
		t.Fatalf("returned slice must be a defensive copy: got %q after source mutation", urls[0])
	}
}

// TestResolveEffectiveEndpoints_ConfigCanaryIsDefensiveCopy is the
// same protection for the fallback path: mutating the original
// cfg.WitnessEndpoints slice after construction MUST NOT
// corrupt the snapshot the collector wires against.
func TestResolveEffectiveEndpoints_ConfigCanaryIsDefensiveCopy(t *testing.T) {
	canary := []string{"https://canary"}
	cfg := HeadSyncConfig{
		WitnessEndpoints: canary,
	}
	urls, src, err := resolveEffectiveEndpoints(cfg, discardLogger())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if src != "config_canary_fallback" {
		t.Fatalf("source: want config_canary_fallback, got %q", src)
	}
	canary[0] = "https://tampered"
	if urls[0] != "https://canary" {
		t.Fatalf("canary fallback must be defensive-copied: got %q", urls[0])
	}
}
