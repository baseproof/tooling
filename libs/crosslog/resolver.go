/*
FILE PATH: libs/crosslog/resolver.go

v1.32.0 SDK adoption — boot-time constructor for the unified
authoritative endpoint resolver.

# WHY THIS HELPER EXISTS

*discover.DefaultAuthoritativeResolver is a struct with 10
populated fields:

  - MirrorManifest          (from cached /v1/network/mirrors)
  - FederationGraph         (from cached /v1/network/peers)
  - WitnessEndpointRecords  (from MaterializeFromEntries)
  - WitnessLabelRecords     (from MaterializeFromEntries)
  - AuditorRegistryRecords  (from MaterializeFromEntries)
  - KnownWitnessKeys        (from BuildKnownWitnessKeys)
  - LogWitnessSets          (from BuildLogWitnessSets)
  - DIDFallback             (operator-configured)
  - DIDFallbackPolicy       (operator-configured)
  - Logger                  (operator-configured)

Without a centralised constructor, every consumer (auditor,
witness, CLI) wires all 10 fields by hand — and silently forgets
one. The resulting resolver compiles, runs, and returns
ErrFallbackDisabled / ErrLedgerLogDIDMismatch at first lookup
with cryptic context.

This constructor takes a single ResolverInputs bundle, populates
every field, and returns a ready-to-use *DefaultAuthoritativeResolver.
Callers pair it with sdkguard.AssertResolverPopulated(r, label)
to catch missing fields in CI before the first lookup fails.

# DEFENSE-IN-DEPTH LAYERING

Layer 2 (URL discovery) — this constructor is the boot wiring
that gives downstream code the SDK's unified resolver. Without
it, the L1 / L2 / L5 backdoor closures in the SDK (witness URL,
auditor scope, parent admission URL) are uninvokable.

The function performs NO crypto verification of its inputs. Each
record slice MUST have been pre-validated by the caller (entry
signature + cosigned-head admission) — see the SDK's TRUST INPUT
CONTRACT in endpoint_resolver.go.
*/
package crosslog

import (
	"fmt"
	"log/slog"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/log/discover"
)

// ResolverInputs bundles every input the constructor needs.
// Carried as a struct so adding a new field in a future SDK
// version (e.g., AuditorScopeAmendmentRecords in v1.33) doesn't
// require a function-signature change at every call site.
type ResolverInputs struct {
	// MirrorManifest carries the network's identity + ledger URL
	// list. Required: MirrorManifest.LogDID must be non-empty for
	// ResolveLedger to function.
	MirrorManifest discover.MirrorManifest

	// FederationGraph carries Parent / Siblings / Root peer log
	// declarations. Required if ResolvePeer will be called; an
	// empty FederationGraph makes every ResolvePeer call return
	// ErrPeerUnknown.
	FederationGraph discover.FederationGraph

	// Materialized carries the three v1.32.0 walker projections,
	// typically constructed via MaterializeFromEntries from a
	// log scan. Empty slices are permitted — the corresponding
	// Resolve* calls then return ErrFallbackDisabled (or fall
	// through to DID fallback if policy permits).
	Materialized MaterializedNetwork

	// KnownWitnessKeys is the set of PubKeyIDs reachable from
	// genesis via the witness rotation chain. ResolveWitness
	// sanity-checks against this before attempting the on-log
	// lookup. Nil disables the sanity check (NOT recommended for
	// production); pass BuildKnownWitnessKeys output.
	KnownWitnessKeys map[[32]byte]struct{}

	// LogWitnessSets maps a LOG DID to the PubKeyIDs of witnesses
	// that cosign for that log. Used by WitnessEndpoints (the
	// legacy single-LOG-to-many-URLs API) to assemble the per-log
	// witness fallback list. Required: nil makes
	// AssertResolverPopulated panic in strict mode.
	LogWitnessSets map[string][][32]byte

	// DIDFallback is the off-log resolver consulted for advisory
	// cross-check (FallbackAdvisory policy) and resolution
	// fallthrough (FallbackPermitted policy). Optional — nil
	// disables both regardless of policy.
	//
	// Typical wiring is a did.CachingResolver around did.WebDIDResolver
	// with an mTLS-configured *http.Client (libs/clienttls). The
	// resolver MUST be safe for concurrent use.
	DIDFallback did.DIDResolver

	// DIDFallbackPolicy controls advisory / permitted / disabled
	// fallback behavior. Zero value (FallbackDisabled) is the
	// high-assurance default; explicitly set to FallbackAdvisory
	// or FallbackPermitted only when the deployment's posture
	// warrants it.
	DIDFallbackPolicy discover.DIDFallbackPolicy

	// Logger receives structured audit events on every Resolve*
	// call. nil routes to slog.Default(); production deployments
	// wire a process-wide logger so resolve events are visible
	// alongside other audit-grade telemetry.
	Logger *slog.Logger
}

// NewDefaultAuthoritativeResolver constructs a populated
// *discover.DefaultAuthoritativeResolver from the supplied
// inputs. Returns an error when a required field is missing or
// inconsistent.
//
// Validation:
//   - MirrorManifest.LogDID non-empty (knows what network it
//     serves)
//   - LogWitnessSets non-nil (witness-fallback path is wired)
//
// Other fields are permitted to be empty / zero — the SDK's
// Resolve* methods return well-defined errors when the relevant
// record slice is empty, and downstream consumers branch on
// those sentinels.
//
// v1.33.x (#21 Ladder 2): populates AuditorScopeAmendmentRecords from
// in.Materialized.Amendments. The SDK's ResolveAuditorAt 4-arg
// signature consumes both Auditors + Amendments; an empty Amendments
// slice (the typical state in a network that hasn't published Gap 2
// amendments yet) reduces to v1.32.0 registration-only semantics.
//
// Callers SHOULD pair this with sdkguard.AssertResolverPopulated(r,
// "boot-resolver") to surface configuration bugs in CI / staging.
func NewDefaultAuthoritativeResolver(in ResolverInputs) (*discover.DefaultAuthoritativeResolver, error) {
	if in.MirrorManifest.LogDID == "" {
		return nil, fmt.Errorf(
			"crosslog/resolver: MirrorManifest.LogDID required " +
				"(populate from network.BootstrapDocument before constructing the resolver)")
	}
	if in.LogWitnessSets == nil {
		return nil, fmt.Errorf(
			"crosslog/resolver: LogWitnessSets required " +
				"(call BuildLogWitnessSets from the bootstrap document)")
	}

	return &discover.DefaultAuthoritativeResolver{
		MirrorManifest:               in.MirrorManifest,
		FederationGraph:              in.FederationGraph,
		WitnessEndpointRecords:       in.Materialized.Endpoints,
		WitnessLabelRecords:          in.Materialized.Labels,
		AuditorRegistryRecords:       in.Materialized.Auditors,
		AuditorScopeAmendmentRecords: in.Materialized.Amendments,
		KnownWitnessKeys:             in.KnownWitnessKeys,
		LogWitnessSets:               in.LogWitnessSets,
		DIDFallback:                  in.DIDFallback,
		DIDFallbackPolicy:            in.DIDFallbackPolicy,
		Logger:                       in.Logger,
	}, nil
}
