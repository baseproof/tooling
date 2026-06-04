/*
FILE PATH: internal/auditorregistry/fetcher_test.go

v1.33.1 SDK adoption — locks the gate/API consistency invariant.

# WHAT THIS LOCKS

The gate (gossipnet/auditor_scope_gate.go) enforces the
amendment-merged auditor scope when authorizing finding-class
events. The API projection at GET /v1/network/auditors MUST
serve the same merged view, or downstream consumers (CLI, JN's
auditor reconciler, the operator dashboards) believe the
network's auditor authority is one thing while the ledger
enforces another. PR #178 wired the amendment plumbing through
the gate but left the projection serving the raw registration
scope — a silent disagreement that this test prevents from
recurring.

# COVERAGE

  - The fetcher merges amendments into the projection's Scope
    (TestFetcher_AmendmentsMergeIntoScope).
  - Constructor rejects nil registry / nil treeSizer
    (TestNew_RejectsMissingDependencies).
  - Retired auditors are filtered (TestFetcher_RetiredAuditorsFiltered).
  - Nil amendment source is allowed and equivalent to "no
    amendments yet" (TestFetcher_NilAmendmentsAllowed).
  - Registry source error surfaces as a wrapped error
    (TestFetcher_RegistrySourceErrorSurfaces).
  - Amendment source error surfaces as a wrapped error — mirrors
    the gate's fail-closed posture on amendment-source failure
    (TestFetcher_AmendmentSourceErrorSurfaces).
*/
package auditorregistry_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/internal/auditorregistry"
)

// fixedTreeSize implements admission.TreeSizeProvider with a
// constant sequence — the fetcher serializes asOf into AsOfSeq
// and uses it for the SDK's ResolveAuditorAt call.
type fixedTreeSize struct{ seq uint64 }

func (f fixedTreeSize) LatestTreeSize(_ context.Context) (uint64, error) {
	return f.seq, nil
}

// validReg returns a Validate()-clean AuditorRegistration. Mirrors
// the gossipnet test fixture pattern so the same field shapes
// satisfy both.
func validReg(t *testing.T, did string, scope network.AuditorScope) network.AuditorRegistration {
	t.Helper()
	r := network.AuditorRegistration{
		AuditorDID:  did,
		PublicKey:   make([]byte, 33),
		SchemeTag:   1,
		FindingsURL: "https://auditor.example.org/v1/findings",
		Scope:       scope,
	}
	r.PublicKey[0] = 0x02
	if err := r.Validate(); err != nil {
		t.Fatalf("validReg fixture invalid: %v", err)
	}
	return r
}

func regAt(r network.AuditorRegistration, seq uint64) network.AuditorRegistrationRecord {
	return network.AuditorRegistrationRecord{
		EffectivePos: types.LogPosition{Sequence: seq},
		Payload:      r,
	}
}

func amendAt(t *testing.T, did string, newScope network.AuditorScope, seq uint64) network.AuditorScopeAmendmentRecord {
	t.Helper()
	a := network.AuditorScopeAmendment{
		AuditorDID: did,
		NewScope:   newScope,
		Reason:     "test fixture",
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("amendAt fixture invalid: %v", err)
	}
	return network.AuditorScopeAmendmentRecord{
		EffectivePos: types.LogPosition{Sequence: seq},
		Payload:      a,
	}
}

// ── Core projection contract ──────────────────────────────────

// TestFetcher_AmendmentsMergeIntoScope is the load-bearing
// regression. Registration with ScopeEquivocation; later
// amendment to ScopeAll; the projection MUST report a Scope
// string containing "smt_replay" (proving the amendment's
// NewScope replaced the registration's narrower scope, not the
// other way around). This is the test that would have caught
// PR #178's silent disagreement between gate and API.
func TestFetcher_AmendmentsMergeIntoScope(t *testing.T) {
	const did = "did:web:auditor-expand.example.org"
	registry := func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		return []network.AuditorRegistrationRecord{
			regAt(validReg(t, did, network.ScopeEquivocation), 0),
		}, nil
	}
	amendments := func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
		return []network.AuditorScopeAmendmentRecord{
			amendAt(t, did, network.ScopeAll, 5),
		}, nil
	}

	f, err := auditorregistry.New(registry, amendments, fixedTreeSize{seq: 10})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	view, err := f.LoadCurrentAuditors(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrentAuditors: %v", err)
	}
	if len(view.Auditors) != 1 {
		t.Fatalf("auditors: got %d, want 1", len(view.Auditors))
	}
	got := view.Auditors[0]
	if got.AuditorDID != did {
		t.Errorf("auditor_did: got %q, want %q", got.AuditorDID, did)
	}
	if !strings.Contains(got.Scope, "smt_replay") {
		t.Errorf("scope: got %q — expected amendment-merged scope to include smt_replay; "+
			"the projection is serving the raw registration scope, gate/API will disagree", got.Scope)
	}
	if !strings.Contains(got.Scope, "equivocation") {
		t.Errorf("scope: got %q — expected merged ScopeAll to include equivocation", got.Scope)
	}
	if view.AsOfSeq != 10 {
		t.Errorf("as_of_seq: got %d, want 10", view.AsOfSeq)
	}
}

// TestFetcher_AmendmentReducingScopeReflectedInProjection mirrors
// the gate test of the same shape: an amendment narrowing scope
// MUST be reflected in the projection. A regression that fell
// back to the raw registration on narrowing amendments would
// over-report auditor authority.
func TestFetcher_AmendmentReducingScopeReflectedInProjection(t *testing.T) {
	const did = "did:web:auditor-reduce.example.org"
	registry := func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		return []network.AuditorRegistrationRecord{
			regAt(validReg(t, did, network.ScopeAll), 0),
		}, nil
	}
	amendments := func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
		return []network.AuditorScopeAmendmentRecord{
			amendAt(t, did, network.ScopeEquivocation, 5),
		}, nil
	}

	f, _ := auditorregistry.New(registry, amendments, fixedTreeSize{seq: 10})
	view, err := f.LoadCurrentAuditors(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrentAuditors: %v", err)
	}
	if len(view.Auditors) != 1 {
		t.Fatalf("auditors: got %d, want 1", len(view.Auditors))
	}
	got := view.Auditors[0].Scope
	if strings.Contains(got, "smt_replay") {
		t.Errorf("scope: got %q — amendment-narrowed scope MUST NOT include smt_replay", got)
	}
	if !strings.Contains(got, "equivocation") {
		t.Errorf("scope: got %q — narrowed scope must still include equivocation", got)
	}
}

// TestFetcher_NilAmendmentsAllowed locks the bootstrap-window
// posture: a deployment with no amendment source wired (typical
// pre-Gap-2 networks, or networks that have never issued an
// amendment) MUST serve the registration scope alone.
func TestFetcher_NilAmendmentsAllowed(t *testing.T) {
	const did = "did:web:auditor-noamend.example.org"
	registry := func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		return []network.AuditorRegistrationRecord{
			regAt(validReg(t, did, network.ScopeSMTReplay), 0),
		}, nil
	}

	f, err := auditorregistry.New(registry, nil, fixedTreeSize{seq: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	view, err := f.LoadCurrentAuditors(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrentAuditors: %v", err)
	}
	if len(view.Auditors) != 1 {
		t.Fatalf("auditors: got %d, want 1", len(view.Auditors))
	}
	if view.Auditors[0].Scope != "smt_replay" {
		t.Errorf("scope: got %q, want smt_replay", view.Auditors[0].Scope)
	}
}

// TestFetcher_RetiredAuditorsFiltered pins the "current active
// set" contract. A retired auditor's registration is on-log but
// the view MUST exclude them — consumers asking "who is currently
// authorized to publish findings" want the active set only.
func TestFetcher_RetiredAuditorsFiltered(t *testing.T) {
	const activeDID = "did:web:auditor-active.example.org"
	const retiredDID = "did:web:auditor-retired.example.org"
	retiredAt := uint64(5)

	registry := func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		active := validReg(t, activeDID, network.ScopeEquivocation)
		retired := validReg(t, retiredDID, network.ScopeEquivocation)
		retired.RetiredAt = &retiredAt
		return []network.AuditorRegistrationRecord{
			regAt(active, 0),
			regAt(retired, 1),
		}, nil
	}

	f, _ := auditorregistry.New(registry, nil, fixedTreeSize{seq: 10})
	view, err := f.LoadCurrentAuditors(context.Background())
	if err != nil {
		t.Fatalf("LoadCurrentAuditors: %v", err)
	}
	if len(view.Auditors) != 1 {
		t.Fatalf("retired auditor should be filtered: got %d auditors", len(view.Auditors))
	}
	if view.Auditors[0].AuditorDID != activeDID {
		t.Errorf("expected active auditor, got %q", view.Auditors[0].AuditorDID)
	}
}

// ── Constructor preconditions ─────────────────────────────────

// TestNew_RejectsMissingDependencies locks the required-arg contract.
// The fetcher CANNOT operate without a registry source (no records
// to walk) and CANNOT determine asOf without a treeSizer.
func TestNew_RejectsMissingDependencies(t *testing.T) {
	t.Run("nil registry", func(t *testing.T) {
		_, err := auditorregistry.New(nil, nil, fixedTreeSize{})
		if err == nil {
			t.Fatal("nil registry must be rejected at construction")
		}
	})
	t.Run("nil treeSizer", func(t *testing.T) {
		_, err := auditorregistry.New(
			func(_ context.Context) ([]network.AuditorRegistrationRecord, error) { return nil, nil },
			nil, nil)
		if err == nil {
			t.Fatal("nil treeSizer must be rejected at construction")
		}
	})
}

// ── Source-error surfaces ─────────────────────────────────────

// TestFetcher_RegistrySourceErrorSurfaces ensures registry walker
// failures are reported as errors — the api handler maps non-
// ErrAuditorsNotConfigured errors to 500, so operators see the
// projection going dark rather than silently empty.
func TestFetcher_RegistrySourceErrorSurfaces(t *testing.T) {
	boom := errors.New("registry walker down")
	registry := func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		return nil, boom
	}
	f, _ := auditorregistry.New(registry, nil, fixedTreeSize{})
	_, err := f.LoadCurrentAuditors(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("registry source error must surface (wrapped); got %v", err)
	}
}

// TestFetcher_AmendmentSourceErrorSurfaces mirrors the gate's
// fail-closed posture for the amendment source. A walker hiccup
// MUST NOT be silently downgraded to "use the registration alone"
// because that would over-report the auditor's authority while
// the gate enforces the narrowed amendment.
func TestFetcher_AmendmentSourceErrorSurfaces(t *testing.T) {
	boom := errors.New("amendment walker down")
	registry := func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		return nil, nil
	}
	amendments := func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
		return nil, boom
	}
	f, _ := auditorregistry.New(registry, amendments, fixedTreeSize{})
	_, err := f.LoadCurrentAuditors(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("amendment source error must surface (wrapped); got %v", err)
	}
}
