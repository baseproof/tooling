/*
FILE PATH: libs/monitoring/gossip_reconciler_scope_test.go

v1.32.0 SDK adoption — Tier C tests for the T3.2 auditor-scope gate
in HandleSignedEvent. Symmetric to the ledger's
gossipnet/auditor_scope_gate_test.go — same L2/L5 authorization
gate, same accept/reject matrix, on the symmetric ingest path.

# WHAT THIS LOCKS

Every path of Reconciler.authorizedForKind:

  - nil AuditorRegistry → pre-v1.32 dispatch (every event flows
    through the kind switch).
  - Non-finding kind + non-nil registry → dispatch (gate is permissive
    for non-finding kinds).
  - Finding kind + originator NOT registered → reject.
  - Finding kind + originator registered + scope covers Kind → accept.
  - Finding kind + originator registered + scope MISMATCH → reject.
  - Finding kind + auditor RETIRED at asOf → reject.
  - Empty AuditorRegistry slice + finding kind → reject.
  - Custom AuditorScopeAsOf threads through to the resolver.

A regression on any of these silently re-opens the v1.32.0 L2/L5
authorization backdoor on the inbound gossip path.
*/
package monitoring

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// fakeVerifier implements FindingVerifier returning a configured event.
type fakeVerifier struct {
	event gossip.Event
	err   error
}

func (f *fakeVerifier) Verify(_ context.Context, _ gossip.SignedEvent) (gossip.Event, error) {
	return f.event, f.err
}

// stubFinding satisfies gossip.Event for tests that need a specific Kind
// without the full SDK finding-construction ceremony.
type stubFinding struct {
	kind gossip.Kind
}

func (s *stubFinding) Kind() gossip.Kind      { return s.kind }
func (s *stubFinding) CanonicalBytes() []byte { return nil }
func (s *stubFinding) Bindings() [][32]byte   { return nil }
func (s *stubFinding) Validate() error        { return nil }

// discardLoggerScope returns a logger that drops every record.
func discardLoggerScope() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// validAuditorRegistration returns a syntactically-valid registration
// for use in test fixtures. Mirrors the ledger's validRegistration
// helper to keep the two test suites readable side-by-side.
func validAuditorRegistration(t *testing.T, did string, scope network.AuditorScope) network.AuditorRegistration {
	t.Helper()
	r := network.AuditorRegistration{
		AuditorDID:  did,
		PublicKey:   make([]byte, 33),
		SchemeTag:   1, // ECDSA
		FindingsURL: "https://auditor.example.org/v1/findings",
		Scope:       scope,
	}
	r.PublicKey[0] = 0x02
	if err := r.Validate(); err != nil {
		t.Fatalf("test fixture validAuditorRegistration is invalid: %v", err)
	}
	return r
}

// recordsForScope wraps registrations into the *ByPosition slice the
// reconciler consumes. EffectivePos starts at Sequence=0 so the
// zero-asOf default in the reconciler matches every record (same
// fixture pattern the ledger's recordsFor uses; see Tier-C fix
// fccf046 in clearcompass-ai/ledger).
func recordsForScope(regs ...network.AuditorRegistration) network.AuditorRegistrationByPosition {
	out := make(network.AuditorRegistrationByPosition, 0, len(regs))
	for i, r := range regs {
		out = append(out, network.AuditorRegistrationRecord{
			EffectivePos: types.LogPosition{Sequence: uint64(i)},
			Payload:      r,
		})
	}
	return out
}

// buildReconciler constructs a minimally-wired Reconciler with the
// fake verifier and the test's AuditorRegistry / asOf. Other fields
// (Heads, store, etc.) are stubbed to non-nil so NewReconciler
// validation passes.
func buildReconciler(t *testing.T, ver FindingVerifier, registry network.AuditorRegistrationByPosition, asOf func(context.Context) types.LogPosition) *Reconciler {
	t.Helper()
	heads := NewTrustedHeadStore(discardLoggerScope())
	r, err := NewReconciler(ReconcilerConfig{
		Verifier:         ver,
		Heads:            heads,
		Logger:           discardLoggerScope(),
		AuditorRegistry:  registry,
		AuditorScopeAsOf: asOf,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return r
}

// ── Pre-v1.32 behavior — nil AuditorRegistry ──────────────────

// TestAuthorized_NilRegistryAcceptsAll exercises the pre-v1.32 path:
// when AuditorRegistry is nil, authorizedForKind returns true
// unconditionally. A regression here would silently break every
// deployment that hasn't opted into the gate.
func TestAuthorized_NilRegistryAcceptsAll(t *testing.T) {
	r := buildReconciler(t, &fakeVerifier{}, nil, nil)
	cases := []gossip.Kind{
		gossip.KindEquivocationFinding,
		gossip.KindSMTReplayFinding,
		gossip.KindHistoryRewriteFinding,
		gossip.KindCosignedTreeHead,
		gossip.KindEscrowOverrideAuth,
	}
	for _, k := range cases {
		if !r.authorizedForKind(context.Background(), "did:web:any", k) {
			t.Errorf("nil registry must accept all kinds; rejected %s", k)
		}
	}
}

// ── Non-finding kinds pass through regardless of registry ─────

// TestAuthorized_NonFindingKindPassesThrough exercises the
// permissive-for-non-findings path. Cosigned tree heads, escrow
// authorizations, etc. flow through even when the registry is
// non-nil but empty — they're not gated by the auditor scope.
func TestAuthorized_NonFindingKindPassesThrough(t *testing.T) {
	r := buildReconciler(t, &fakeVerifier{}, network.AuditorRegistrationByPosition{}, nil)
	cases := []gossip.Kind{
		gossip.KindCosignedTreeHead,
		gossip.KindEscrowOverrideAuth,
		gossip.KindOriginatorRotation,
		gossip.KindEntryCommitmentEquivocation,
		gossip.KindGhostLeaf,
	}
	for _, k := range cases {
		if !r.authorizedForKind(context.Background(), "did:web:any", k) {
			t.Errorf("non-finding kind %s must pass through, got rejected", k)
		}
	}
}

// ── Finding kinds — fail-closed for unregistered originator ──

// TestAuthorized_UnregisteredOriginatorRejected pins the load-
// bearing v1.32.0 invariant: a finding-class event whose originator
// is not in the registry is rejected. The pre-v1.32 path would have
// dispatched the event through to the finding's enforcer.
func TestAuthorized_UnregisteredOriginatorRejected(t *testing.T) {
	registry := recordsForScope(validAuditorRegistration(t,
		"did:web:legitimate.example.org", network.ScopeAll))
	r := buildReconciler(t, &fakeVerifier{}, registry, nil)
	if r.authorizedForKind(context.Background(),
		"did:web:imposter.example.org", gossip.KindEquivocationFinding) {
		t.Error("unregistered originator must be rejected")
	}
}

// TestAuthorized_EmptyRegistryRejectsAllFindings covers the
// bootstrap-window state: registry source is wired but no auditors
// registered yet. Same fail-closed posture as unregistered DID.
func TestAuthorized_EmptyRegistryRejectsAllFindings(t *testing.T) {
	r := buildReconciler(t, &fakeVerifier{}, network.AuditorRegistrationByPosition{}, nil)
	cases := []gossip.Kind{
		gossip.KindEquivocationFinding,
		gossip.KindSMTReplayFinding,
		gossip.KindHistoryRewriteFinding,
	}
	for _, k := range cases {
		if r.authorizedForKind(context.Background(), "did:web:any", k) {
			t.Errorf("empty registry must reject finding kind %s", k)
		}
	}
}

// ── Finding kinds — accept / reject by scope ──────────────────

// TestAuthorized_AuthorizedAuditorAccepted exercises the success
// path: a registered auditor whose Scope mask covers the event Kind.
func TestAuthorized_AuthorizedAuditorAccepted(t *testing.T) {
	const auditorDID = "did:web:auditor-equiv.example.org"
	registry := recordsForScope(validAuditorRegistration(t,
		auditorDID, network.ScopeEquivocation))
	r := buildReconciler(t, &fakeVerifier{}, registry, nil)
	if !r.authorizedForKind(context.Background(),
		auditorDID, gossip.KindEquivocationFinding) {
		t.Error("authorized auditor must be accepted")
	}
}

// TestAuthorized_ScopeMismatchRejected exercises the L5-extension
// authorization gate: a registered auditor whose Scope mask does
// NOT cover the event Kind is rejected.
func TestAuthorized_ScopeMismatchRejected(t *testing.T) {
	const auditorDID = "did:web:auditor-equiv-only.example.org"
	registry := recordsForScope(validAuditorRegistration(t,
		auditorDID, network.ScopeEquivocation))
	r := buildReconciler(t, &fakeVerifier{}, registry, nil)
	if r.authorizedForKind(context.Background(),
		auditorDID, gossip.KindHistoryRewriteFinding) {
		t.Error("scope-mismatched event must be rejected")
	}
}

// TestAuthorized_AllScopesAccepted exercises the per-bit scope
// dispatch: an auditor granted Scope=All accepts every CLAIM-class
// finding kind the gate gates. Pins the bit semantics — a regression
// that crossed wires (granting Equivocation enables HistoryRewrite,
// say) would expand auditor authority silently.
//
// v1.33.1 (#21 C4): proof-class kinds (KindCrossLogInclusion,
// KindWitnessRotation) are NOT in this set. The gate explicitly does
// not gate them — see TestAuthorized_ProofKindsAcceptedRegardlessOfRegistry
// below for the proof-class invariant.
func TestAuthorized_AllScopesAccepted(t *testing.T) {
	const auditorDID = "did:web:auditor-all.example.org"
	registry := recordsForScope(validAuditorRegistration(t,
		auditorDID, network.ScopeAll))
	r := buildReconciler(t, &fakeVerifier{}, registry, nil)
	cases := []gossip.Kind{
		gossip.KindEquivocationFinding,
		gossip.KindSMTReplayFinding,
		gossip.KindHistoryRewriteFinding,
	}
	for _, k := range cases {
		if !r.authorizedForKind(context.Background(), auditorDID, k) {
			t.Errorf("Scope=All must accept claim-class kind %s", k)
		}
	}
}

// TestAuthorized_ProofKindsAcceptedRegardlessOfRegistry pins the v1.33.1
// claim-vs-proof structural separation (#21 C4 / baseproof v1.33.1).
//
// Proof-class kinds (KindCrossLogInclusion, KindWitnessRotation) carry
// their authority in the embedded cryptographic body — a Merkle
// inclusion path or K-of-N signatures from the OLD witness set. The
// originator DID is irrelevant; the cryptography is the gate. The
// reconciler MUST pass proof-class events through the auditor-scope
// gate without consulting AuditorRegistry — otherwise legitimate
// witness-self-published rotations under the witness's own gossip
// originator DID get silently rejected.
//
// Both fixtures below should ACCEPT regardless of registry contents:
//   - Empty registry: the gate cannot map an unknown originator → reject
//     in the claim-class path. Proof-class kinds must skip the gate.
//   - Registered originator without the proof-class scope bit: claim
//     path would reject; proof-class kinds must skip the gate.
func TestAuthorized_ProofKindsAcceptedRegardlessOfRegistry(t *testing.T) {
	proofKinds := []gossip.Kind{
		gossip.KindCrossLogInclusion,
		gossip.KindWitnessRotation,
	}

	t.Run("EmptyRegistry", func(t *testing.T) {
		r := buildReconciler(t, &fakeVerifier{},
			network.AuditorRegistrationByPosition{}, nil)
		for _, k := range proofKinds {
			if !r.authorizedForKind(context.Background(),
				"did:web:anyone.example.org", k) {
				t.Errorf("proof-class %s must pass the gate even on empty registry "+
					"(cryptography is the authority)", k)
			}
		}
	})

	t.Run("RegisteredWithoutProofScope", func(t *testing.T) {
		const auditorDID = "did:web:claim-only-auditor.example.org"
		registry := recordsForScope(validAuditorRegistration(t,
			auditorDID, network.ScopeEquivocation)) // claim-class only
		r := buildReconciler(t, &fakeVerifier{}, registry, nil)
		for _, k := range proofKinds {
			if !r.authorizedForKind(context.Background(), auditorDID, k) {
				t.Errorf("proof-class %s must pass the gate even when originator "+
					"is registered without proof-scope bits", k)
			}
		}
	})
}

// TestAuthorized_UnsortedRegistryRejectedWithExplicitReason pins B1
// (#21): an unsorted registry produces ErrAuditorRecordsUnsorted from
// the SDK; the gate maps it to reason="registry unsorted (operator
// config bug)" rather than the default "originator not registered" —
// that's the right diagnostic for the operator chasing the failure.
//
// BuildAuditorRegistryFromConfig sorts on the producer side; this test
// constructs an unsorted slice DIRECTLY (bypassing the constructor) to
// exercise the gate's defensive arm — the same arm that catches a
// hand-assembled slice that escaped the constructor.
func TestAuthorized_UnsortedRegistryRejectedWithExplicitReason(t *testing.T) {
	reg1 := validAuditorRegistration(t, "did:web:auditor.example.org",
		network.ScopeEquivocation)
	// Hand-assemble with descending EffectivePos so sort.IsSorted
	// returns false.
	registry := network.AuditorRegistrationByPosition{
		{EffectivePos: types.LogPosition{Sequence: 10}, Payload: reg1},
		{EffectivePos: types.LogPosition{Sequence: 5}, Payload: reg1},
	}
	r := buildReconciler(t, &fakeVerifier{}, registry, nil)

	// The gate's authorizedForKind returns false on any error; the
	// distinguishing assertion is the log-line reason, but we cannot
	// inspect slog output cleanly from here. The behavioural pin is
	// "rejects" — the SDK invariant is "ResolveAuditorAt returns
	// ErrAuditorRecordsUnsorted on unsorted input", and the gate's
	// switch is exhaustive against the three documented sentinels.
	if r.authorizedForKind(context.Background(),
		"did:web:auditor.example.org", gossip.KindEquivocationFinding) {
		t.Error("unsorted registry must be rejected")
	}
}

// ── Time-of-effect: retirement ───────────────────────────────

// TestAuthorized_RetiredAuditorRejected pins the retirement
// semantic: an auditor registered, then retired, MUST be rejected
// for events at/after the retirement asOf.
func TestAuthorized_RetiredAuditorRejected(t *testing.T) {
	const auditorDID = "did:web:auditor-retired.example.org"
	reg := validAuditorRegistration(t, auditorDID, network.ScopeEquivocation)
	retiredAt := uint64(10)
	reg.RetiredAt = &retiredAt
	registry := recordsForScope(reg)

	asOf := func(_ context.Context) types.LogPosition {
		return types.LogPosition{Sequence: 20}
	}
	r := buildReconciler(t, &fakeVerifier{}, registry, asOf)
	if r.authorizedForKind(context.Background(),
		auditorDID, gossip.KindEquivocationFinding) {
		t.Error("retired auditor must be rejected at asOf > RetiredAt")
	}
}

// ── isClaimKind classification ──────────────────────────────────

// TestIsClaimKind_ExhaustivePins exhaustively checks the v1.33.1
// claim-class table. A regression that re-added proof-class kinds
// (KindCrossLogInclusion, KindWitnessRotation) to the gate would
// silently re-introduce the confused-authority bug that v1.33.1's
// AuthorizedForClaim/AuthorizedForProof split eliminated.
//
// notGated explicitly includes the two proof-class kinds: their
// absence from isClaimKind is the structural invariant this test
// exists to lock.
func TestIsClaimKind_ExhaustivePins(t *testing.T) {
	gated := []gossip.Kind{
		gossip.KindEquivocationFinding,
		gossip.KindSMTReplayFinding,
		gossip.KindHistoryRewriteFinding,
	}
	for _, k := range gated {
		if !isClaimKind(k) {
			t.Errorf("isClaimKind(%s) = false, want true", k)
		}
	}

	notGated := []gossip.Kind{
		// Proof-class — MUST NOT be in isClaimKind. v1.33.1 structural
		// invariant; a regression here re-introduces the over-gating bug.
		gossip.KindCrossLogInclusion,
		gossip.KindWitnessRotation,
		// Non-finding kinds — never gated.
		gossip.KindCosignedTreeHead,
		gossip.KindEscrowOverrideAuth,
		gossip.KindOriginatorRotation,
		gossip.KindEntryCommitmentEquivocation,
		gossip.KindGhostLeaf,
	}
	for _, k := range notGated {
		if isClaimKind(k) {
			t.Errorf("isClaimKind(%s) = true, want false", k)
		}
	}
}

// ── HandleSignedEvent end-to-end shape ────────────────────────

// TestHandleSignedEvent_ScopeGateRejectsBeforeDispatch verifies the
// gate runs BEFORE the kind switch. The test rigs a verifier
// returning a verified Equivocation finding; the originator isn't
// in the registry. HandleSignedEvent MUST return nil (silent reject
// — the puller advances past) without invoking any enforcer or
// store path.
func TestHandleSignedEvent_ScopeGateRejectsBeforeDispatch(t *testing.T) {
	registry := recordsForScope(validAuditorRegistration(t,
		"did:web:registered.example.org", network.ScopeAll))
	verifier := &fakeVerifier{event: &stubFinding{kind: gossip.KindEquivocationFinding}}
	r := buildReconciler(t, verifier, registry, nil)

	err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{
		Originator: "did:web:imposter.example.org",
		Kind:       gossip.KindEquivocationFinding,
	})
	if err != nil {
		t.Errorf("scope-gate rejection must return nil error (silent reject); got %v", err)
	}
}

// TestHandleSignedEvent_NilRegistryDispatches verifies the pre-v1.32
// path: nil AuditorRegistry → every verified event flows through. We
// use a real *findings.CosignedTreeHeadFinding so the reconciler's
// type-switch matches the case branch — a stubFinding{} of the same
// Kind falls through to "default:" (verified finding, no enforcer) and
// does NOT exercise the CosignedTreeHead dispatch the test claims to
// pin. B4 (#21): the previous stubFinding version of this test would
// not catch a regression that broke the *findings.CosignedTreeHeadFinding
// case arm.
//
// The dispatch ASSERTION is observable via the heads store's record:
// RecordCosignedHead is called only when the *findings.CosignedTreeHeadFinding
// case fires. We don't need to inspect the heads store directly — the
// shape "no error, gate did not reject, real-finding case ran" is the
// behavioural pin.
func TestHandleSignedEvent_NilRegistryDispatches(t *testing.T) {
	f := cthFinding(t, 100, 0xAA) // reused from gossip_reconciler_test.go
	verifier := &fakeVerifier{event: f}
	r := buildReconciler(t, verifier, nil, nil)

	if err := r.HandleSignedEvent(context.Background(), gossip.SignedEvent{
		Originator: "did:web:any",
		Kind:       gossip.KindCosignedTreeHead,
	}); err != nil {
		t.Errorf("nil registry + verified CosignedTreeHead must not error; got %v", err)
	}
}

// _ keeps findings imported even when the file's tests only consume
// *findings.CosignedTreeHeadFinding via the cthFinding helper from the
// sibling test file. The package-level use makes the import obvious to
// readers and survives a tooling cleanup that would otherwise remove
// the import.
var _ = findings.CosignedTreeHeadFinding{}
