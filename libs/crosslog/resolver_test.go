/*
FILE PATH: libs/crosslog/resolver_test.go

T6 unit tests — NewDefaultAuthoritativeResolver.

Covers the boot-time constructor's validation contract and the
field-population semantics. The function's job is to (1) reject
inputs the resolver can't operate without and (2) populate every
public field of *discover.DefaultAuthoritativeResolver so a
caller can pair it with sdkguard.AssertResolverPopulated without
silent gaps.
*/
package crosslog

import (
	"strings"
	"testing"

	"github.com/baseproof/baseproof/log/discover"
	"github.com/baseproof/baseproof/network"
)

// validResolverInputs returns the minimal-valid ResolverInputs:
// the two required fields populated, everything else at zero.
func validResolverInputs() ResolverInputs {
	return ResolverInputs{
		MirrorManifest: discover.MirrorManifest{
			LogDID: "did:baseproof:network:test",
		},
		LogWitnessSets: map[string][][32]byte{},
	}
}

// ─────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────

func TestNewDefaultAuthoritativeResolver_EmptyMirrorLogDID(t *testing.T) {
	in := validResolverInputs()
	in.MirrorManifest.LogDID = ""
	_, err := NewDefaultAuthoritativeResolver(in)
	if err == nil {
		t.Fatal("empty MirrorManifest.LogDID must error")
	}
	if !strings.Contains(err.Error(), "MirrorManifest.LogDID") {
		t.Errorf("error must name the offending field; got %v", err)
	}
}

func TestNewDefaultAuthoritativeResolver_NilLogWitnessSets(t *testing.T) {
	in := validResolverInputs()
	in.LogWitnessSets = nil
	_, err := NewDefaultAuthoritativeResolver(in)
	if err == nil {
		t.Fatal("nil LogWitnessSets must error")
	}
	if !strings.Contains(err.Error(), "LogWitnessSets") {
		t.Errorf("error must name the offending field; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────
// Field-population semantics
// ─────────────────────────────────────────────────────────────

func TestNewDefaultAuthoritativeResolver_MinimalValid(t *testing.T) {
	r, err := NewDefaultAuthoritativeResolver(validResolverInputs())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil resolver")
	}
	if r.MirrorManifest.LogDID != "did:baseproof:network:test" {
		t.Errorf("MirrorManifest.LogDID: got %q", r.MirrorManifest.LogDID)
	}
	if r.LogWitnessSets == nil {
		t.Error("LogWitnessSets: got nil, want empty map")
	}
	// Materialized fields default to nil/empty — the SDK resolver
	// returns ErrXxx for lookups against empty record slices, which
	// is the correct fail-closed behavior. NOT a constructor error.
	if r.WitnessEndpointRecords != nil {
		t.Errorf("WitnessEndpointRecords: expected nil; got len=%d",
			len(r.WitnessEndpointRecords))
	}
	if r.WitnessLabelRecords != nil {
		t.Errorf("WitnessLabelRecords: expected nil; got len=%d",
			len(r.WitnessLabelRecords))
	}
	if r.AuditorRegistryRecords != nil {
		t.Errorf("AuditorRegistryRecords: expected nil; got len=%d",
			len(r.AuditorRegistryRecords))
	}
}

func TestNewDefaultAuthoritativeResolver_AllFieldsThreaded(t *testing.T) {
	in := ResolverInputs{
		MirrorManifest: discover.MirrorManifest{
			LogDID: "did:baseproof:network:test",
		},
		FederationGraph: discover.FederationGraph{},
		Materialized: MaterializedNetwork{
			Endpoints: network.WitnessEndpointDeclarationByPosition{
				{}, // single zero-value record — only verifying threading
			},
			Labels: network.WitnessIdentityLabelByPosition{
				{}, {},
			},
			Auditors: network.AuditorRegistrationByPosition{
				{}, {}, {},
			},
			// Ladder 2 D3 (#21): v1.33.x Gap 2 amendments flow through.
			Amendments: network.AuditorScopeAmendmentByPosition{
				{}, {}, {}, {},
			},
		},
		KnownWitnessKeys:  map[[32]byte]struct{}{{0x01}: {}},
		LogWitnessSets:    map[string][][32]byte{"did:test:log": {{0x02}}},
		DIDFallbackPolicy: discover.FallbackAdvisory,
	}
	r, err := NewDefaultAuthoritativeResolver(in)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	if len(r.WitnessEndpointRecords) != 1 {
		t.Errorf("Endpoints: got %d, want 1", len(r.WitnessEndpointRecords))
	}
	if len(r.WitnessLabelRecords) != 2 {
		t.Errorf("Labels: got %d, want 2", len(r.WitnessLabelRecords))
	}
	if len(r.AuditorRegistryRecords) != 3 {
		t.Errorf("Auditors: got %d, want 3", len(r.AuditorRegistryRecords))
	}
	// Ladder 2 D3 (#21): the v1.33.x AuditorScopeAmendmentRecords field
	// MUST be populated from Materialized.Amendments. A regression that
	// dropped the assignment line in NewDefaultAuthoritativeResolver
	// would leave the slice nil; the SDK's ResolveAuditorAt would then
	// receive nil amendments and Gap 2 wouldn't function.
	if len(r.AuditorScopeAmendmentRecords) != 4 {
		t.Errorf("Amendments: got %d, want 4", len(r.AuditorScopeAmendmentRecords))
	}
	if _, ok := r.KnownWitnessKeys[[32]byte{0x01}]; !ok {
		t.Error("KnownWitnessKeys not threaded")
	}
	if _, ok := r.LogWitnessSets["did:test:log"]; !ok {
		t.Error("LogWitnessSets not threaded")
	}
	if r.DIDFallbackPolicy != discover.FallbackAdvisory {
		t.Errorf("DIDFallbackPolicy: got %v, want FallbackAdvisory", r.DIDFallbackPolicy)
	}
}

// TestNewDefaultAuthoritativeResolver_PassesSdkguard verifies the
// constructed resolver satisfies the AssertResolverPopulated
// contract — same predicate, opposite direction. Catches a future
// regression where the constructor lets through a resolver that
// the guard would panic on.
func TestNewDefaultAuthoritativeResolver_PassesSdkguard(t *testing.T) {
	r, err := NewDefaultAuthoritativeResolver(validResolverInputs())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// Mirror the guard's predicate inline — the constructor's
	// contract is a SUPERSET of the guard's (constructor MAY
	// require more fields, guard MUST be satisfied by anything the
	// constructor accepts).
	if r == nil {
		t.Fatal("nil resolver")
	}
	if r.MirrorManifest.LogDID == "" {
		t.Error("MirrorManifest.LogDID empty — would fail sdkguard")
	}
	if r.LogWitnessSets == nil {
		t.Error("LogWitnessSets nil — would fail sdkguard")
	}
}
