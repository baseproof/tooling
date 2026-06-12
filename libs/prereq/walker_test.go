/*
FILE PATH: libs/prereq/walker_test.go

DESCRIPTION:

	Tests pinning the Walker contract. Two intertwined surfaces
	(vocabulary + prerequisite evaluation) tested via small
	in-memory policies built per case so the assertions stay tight
	and obvious.

	Coverage:
	  - Vocabulary: unknown event_type rejected.
	  - Hard ancestor present / missing.
	  - Hard authority present / missing.
	  - Mixed Hard + Advisory rules: Hard violation rejects;
	    Advisory surfaced but does not block.
	  - Multiple ancestors: OR semantics.
	  - HasObservedEvent / HasAuthorityScope helpers.
	  - Edge cases: nil walker, nil policy, walker with
	    un-registered policy event.
*/
package prereq

import (
	"testing"
)

// ─── helpers ────────────────────────────────────────────────────────

func policyWith(eventRules map[string][]Prereq) *InMemoryPolicy {
	p, err := NewInMemoryPolicy(eventRules)
	if err != nil {
		panic(err)
	}
	return p
}

// ─── vocabulary ─────────────────────────────────────────────────────

func TestWalker_UnknownEventTypeRejected(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{"a": {}})}
	v := w.Check("wizard", EvalContext{})
	if v.OK {
		t.Fatal("must reject unknown event_type")
	}
	if v.Rejection != WalkRejectUnknownEvent {
		t.Errorf("Rejection=%s, want %s", v.Rejection, WalkRejectUnknownEvent)
	}
}

func TestWalker_KnownEventNoRules_OK(t *testing.T) {
	// Event registered with empty rule list — vocabulary covers it
	// and there's nothing to check.
	w := &Walker{Policy: policyWith(map[string][]Prereq{"record_opened": {}})}
	v := w.Check("record_opened", EvalContext{})
	if !v.OK {
		t.Errorf("known event with no rules must be OK: %+v", v)
	}
	if v.Rejection != WalkOK {
		t.Errorf("Rejection=%s", v.Rejection)
	}
}

// ─── ancestor rules ─────────────────────────────────────────────────

func ancestorRule(modes PrereqMode, ancestors ...string) Prereq {
	return Prereq{
		Mode:             modes,
		RequiredAncestor: ancestors,
		Reason:           "test ancestor rule",
	}
}

func TestWalker_HardAncestor_Present_OK(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"amendment": {ancestorRule(PrereqModeHard, "record_opened")},
	})}
	v := w.Check("amendment", EvalContext{
		ObservedEvents: []string{"record_opened"},
	})
	if !v.OK {
		t.Errorf("ancestor present but not OK: %+v", v)
	}
}

func TestWalker_HardAncestor_Missing_Rejected(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"amendment": {ancestorRule(PrereqModeHard, "record_opened")},
	})}
	v := w.Check("amendment", EvalContext{
		ObservedEvents: []string{"review"}, // wrong event
	})
	if v.OK {
		t.Fatal("must reject when ancestor missing")
	}
	if v.Rejection != WalkRejectMissingAncestor {
		t.Errorf("Rejection=%s, want %s", v.Rejection, WalkRejectMissingAncestor)
	}
	if len(v.Hard) != 1 {
		t.Errorf("expected 1 Hard violation, got %d", len(v.Hard))
	}
}

func TestWalker_AncestorOR_AnyMatchSatisfies(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"decision": {ancestorRule(PrereqModeHard,
			"response_filed", "withdrawal_filed")},
	})}
	v := w.Check("decision", EvalContext{
		ObservedEvents: []string{"withdrawal_filed"},
	})
	if !v.OK {
		t.Errorf("OR-semantics: withdrawal_filed should satisfy: %+v", v)
	}
}

// ─── authority rules ────────────────────────────────────────────────

func authorityRule(scope string) Prereq {
	return Prereq{
		Mode:              PrereqModeHard,
		RequiredAuthority: scope,
		Reason:            "test authority rule",
	}
}

func TestWalker_HardAuthority_Present_OK(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"appointment": {authorityRule("appointment_authority")},
	})}
	v := w.Check("appointment", EvalContext{
		PrimaryAuthorityScopes: []string{"appointment_authority"},
	})
	if !v.OK {
		t.Errorf("authority present but not OK: %+v", v)
	}
}

func TestWalker_HardAuthority_Missing_Rejected(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"appointment": {authorityRule("appointment_authority")},
	})}
	v := w.Check("appointment", EvalContext{
		PrimaryAuthorityScopes: []string{"filing_authority"}, // wrong scope
	})
	if v.OK {
		t.Fatal("must reject when authority missing")
	}
	if v.Rejection != WalkRejectMissingAuthority {
		t.Errorf("Rejection=%s, want %s", v.Rejection, WalkRejectMissingAuthority)
	}
}

// ─── mixed Hard + Advisory ─────────────────────────────────────────

func TestWalker_AdvisoryViolation_DoesNotBlock(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"publication": {
			ancestorRule(PrereqModeHard, "record_opened"),
			ancestorRule(PrereqModeAdvisory, "review"),
		},
	})}
	v := w.Check("publication", EvalContext{
		ObservedEvents: []string{"record_opened"}, // review missing
	})
	if !v.OK {
		t.Errorf("advisory violation must NOT block: %+v", v)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}
	if len(v.Hard) != 0 {
		t.Errorf("expected 0 Hard violations, got %d", len(v.Hard))
	}
}

func TestWalker_MultipleHardRules_FirstFailureDecides(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"decision": {
			ancestorRule(PrereqModeHard, "record_opened"),
			ancestorRule(PrereqModeHard, "response_filed"),
		},
	})}
	v := w.Check("decision", EvalContext{
		ObservedEvents: []string{}, // both fail
	})
	if v.OK {
		t.Fatal("must reject when multiple Hard rules unsatisfied")
	}
	if len(v.Hard) != 2 {
		t.Errorf("expected 2 Hard violations, got %d", len(v.Hard))
	}
	// The Reason cites the first (deterministic) failure.
	if v.Reason == "" {
		t.Error("expected a Reason for the rejection")
	}
}

func TestWalker_HardAndAdvisory_BothViolated_HardDecides(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{
		"publication": {
			ancestorRule(PrereqModeHard, "record_opened"),
			ancestorRule(PrereqModeAdvisory, "review"),
		},
	})}
	v := w.Check("publication", EvalContext{
		ObservedEvents: []string{}, // both fail
	})
	if v.OK {
		t.Fatal("must reject")
	}
	if len(v.Hard) != 1 || len(v.Advisory) != 1 {
		t.Errorf("violations split incorrectly: hard=%d advisory=%d",
			len(v.Hard), len(v.Advisory))
	}
}

// ─── helpers ────────────────────────────────────────────────────────

func TestHasObservedEvent(t *testing.T) {
	ctx := EvalContext{ObservedEvents: []string{"a", "b"}}
	if !HasObservedEvent(ctx, "a") {
		t.Error("a should be observed")
	}
	if HasObservedEvent(ctx, "c") {
		t.Error("c should NOT be observed")
	}
	if HasObservedEvent(EvalContext{}, "any") {
		t.Error("empty ctx should observe nothing")
	}
}

func TestHasAuthorityScope(t *testing.T) {
	ctx := EvalContext{PrimaryAuthorityScopes: []string{"a", "b"}}
	if !HasAuthorityScope(ctx, "a") {
		t.Error("a should be a held scope")
	}
	if HasAuthorityScope(ctx, "c") {
		t.Error("c should NOT be a held scope")
	}
}

// ─── edge cases ─────────────────────────────────────────────────────

func TestWalker_NilWalker(t *testing.T) {
	var w *Walker
	v := w.Check("evt", EvalContext{})
	if v.Rejection != WalkPolicyError {
		t.Errorf("nil walker: Rejection=%s", v.Rejection)
	}
}

func TestWalker_NilPolicy(t *testing.T) {
	w := &Walker{}
	v := w.Check("evt", EvalContext{})
	if v.Rejection != WalkPolicyError {
		t.Errorf("nil policy: Rejection=%s", v.Rejection)
	}
}

// Verdict.EventType always echoed.
func TestWalker_VerdictEchoesEventType(t *testing.T) {
	w := &Walker{Policy: policyWith(map[string][]Prereq{"a": {}})}
	v := w.Check("anything", EvalContext{})
	if v.EventType != "anything" {
		t.Errorf("EventType drift: %q", v.EventType)
	}
}
