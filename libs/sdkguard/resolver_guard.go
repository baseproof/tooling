/*
FILE PATH: libs/sdkguard/resolver_guard.go

v1.32.0 SDK adoption — strict-mode assertion that catches the
"resolver compiled but not populated" failure shape.

# THE FAILURE MODE THIS CATCHES

A consumer builds *discover.DefaultAuthoritativeResolver, gets
no error, threads it into TreeHeadClient / cosignClient / etc.,
and the binary starts. At first Resolve* call the resolver
returns ErrFallbackDisabled / ErrLedgerLogDIDMismatch because
one of the load-bearing fields (LogWitnessSets,
MirrorManifest.LogDID, etc.) was left nil at construction.

This is a CONFIGURATION bug — the resolver works fine when
properly populated; the SDK has no way to detect "you forgot to
call MaterializeFromEntries" at construction time. AssertResolverPopulated
is the runtime check that surfaces the bug at boot, in CI, before
the first lookup fails in production.

Mirrors the AssertMTLS shape: no-op in dev / unit tests; panic in
strict mode with file:line + label so the offending wiring is
trivial to find.

# THE CHECKS

A "sufficiently populated" *DefaultAuthoritativeResolver carries:

 1. non-nil receiver (a nil resolver would crash on first call)
 2. MirrorManifest.LogDID non-empty (knows what network it serves)
 3. LogWitnessSets non-nil (witness-fallback path can run, even
    if individual log entries are empty)

Optional fields (DIDFallback, Logger, AuditorScopeAmendmentRecords
in future SDK versions, etc.) are NOT checked — they have
acceptable defaults.

A resolver passing this guard MAY still return ErrFallbackDisabled
for specific lookups (the on-log walker records simply aren't
there yet for a particular auditor / witness). That's correct
fail-closed behavior. The guard catches "wired wrong", not "data
not yet on-log".
*/
package sdkguard

import (
	"fmt"
	"runtime"

	"github.com/baseproof/baseproof/log/discover"
)

// AssertResolverPopulated panics if sdkguard is in strict mode
// AND the supplied resolver fails the population check. No-op
// otherwise. Call this immediately after constructing the
// resolver (typically in cmd/.../main.go after
// crosslog.NewDefaultAuthoritativeResolver) so a misconfigured
// resolver surfaces at boot rather than at first Resolve* call.
//
// label is a short identifier for the call site (e.g.
// "auditor-resolver", "witness-bootstrap"). Required and used
// only in the panic message; pass anything that helps find the
// call site.
//
// Strict mode is controlled by BASEPROOF_FAIL_ON_PLAINTEXT_FALLBACK
// (the same env var used by AssertMTLS) so a single switch toggles
// every sdkguard assertion uniformly across the deployment.
func AssertResolverPopulated(r *discover.DefaultAuthoritativeResolver, label string) {
	if !StrictMode() {
		return
	}
	_, file, line, _ := runtime.Caller(1)

	if r == nil {
		panic(fmt.Sprintf(
			"sdkguard: %s: *discover.DefaultAuthoritativeResolver is nil at %s:%d "+
				"(did you call crosslog.NewDefaultAuthoritativeResolver?)",
			label, file, line))
	}
	if r.MirrorManifest.LogDID == "" {
		panic(fmt.Sprintf(
			"sdkguard: %s: MirrorManifest.LogDID is empty at %s:%d "+
				"(populate from network.BootstrapDocument before threading the resolver)",
			label, file, line))
	}
	if r.LogWitnessSets == nil {
		panic(fmt.Sprintf(
			"sdkguard: %s: LogWitnessSets is nil at %s:%d "+
				"(populate via crosslog.BuildLogWitnessSets from the bootstrap document)",
			label, file, line))
	}
}

// IsResolverPopulated returns the same predicate AssertResolverPopulated
// checks without panicking. Useful for tests or boot-time logging that
// wants to surface the populated state without halting the process.
//
// Returns false for any of:
//   - nil receiver
//   - MirrorManifest.LogDID empty
//   - LogWitnessSets nil
//
// A return of true does NOT guarantee that every Resolve* call will
// succeed — the on-log walker records may be empty for a particular
// identifier. It only guarantees the resolver was minimally wired.
func IsResolverPopulated(r *discover.DefaultAuthoritativeResolver) bool {
	if r == nil {
		return false
	}
	if r.MirrorManifest.LogDID == "" {
		return false
	}
	if r.LogWitnessSets == nil {
		return false
	}
	return true
}
