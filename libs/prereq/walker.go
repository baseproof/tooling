/*
FILE PATH: libs/prereq/walker.go

DESCRIPTION:

	Walker — evaluates an event_type against the prerequisite
	policy and returns a closed-set verdict. Two intertwined gates:

	  1. Vocabulary. Reject up front if event_type is not in
	     policy.EventTypes(). This is the v1.6 "closed-set" promise.

	  2. Per-rule evaluation. For each Hard rule, the walker checks
	     the CaseContext and records a violation if unsatisfied.
	     Any Hard violation rejects the entry. Advisory violations
	     are surfaced but do not block.

	Why a CaseContext (not a fetcher): the walker is a pure
	function of (event_type × policy × ctx). The aggregator builds
	the context once per case-root subtree and feeds the same data
	to every walker call. Tests drive the walker with hand-built
	contexts; production wiring plugs in a real subtree
	scanner.

	The walker DOES NOT fetch entries. The walker DOES NOT mutate
	the policy. It is a small, testable predicate.

OVERVIEW:

	Rejection         — closed-set rejection code.
	CaseContext       — observed events + signer authorities.
	Verdict           — outcome shape.
	Violation         — single rule failure (mode + reason +
	                    rule pointer for audit).
	Walker            — Check(eventType, ctx) Verdict.
	HasObservedEvent  — helper.
	HasAuthorityScope — helper.

KEY DEPENDENCIES:

	None — only the Policy interface from policy.go.
*/
package prereq

import (
	"fmt"
)

// ─── Rejection enum ─────────────────────────────────────────────────

// Rejection is the closed set of walker outcomes. Stable string
// form so audit logs and dashboards can pivot on it.
type Rejection string

const (
	// WalkOK signals "no Hard violations + event in vocabulary".
	// Advisory violations may still be present in Verdict.Advisory.
	WalkOK Rejection = "ok"

	// WalkRejectUnknownEvent: event_type not in policy.EventTypes().
	WalkRejectUnknownEvent Rejection = "unknown_event_type"

	// WalkRejectMissingAncestor: at least one Hard
	// RequiredAncestor rule unsatisfied.
	WalkRejectMissingAncestor Rejection = "missing_ancestor"

	// WalkRejectMissingAuthority: at least one Hard
	// RequiredAuthority rule unsatisfied.
	WalkRejectMissingAuthority Rejection = "missing_authority"

	// WalkPolicyError: policy.Lookup returned an unexpected error
	// after KnowsEventType returned true. Should not happen in
	// practice; surfaces the inconsistency rather than silently
	// passing.
	WalkPolicyError Rejection = "policy_error"
)

// ─── Context ────────────────────────────────────────────────────────

// CaseContext carries the prerequisite-evaluation inputs for one
// entry. The caller assembles this from the case-root subtree (for
// observed events) and the primary signer's authority chain (for
// scopes).
type CaseContext struct {
	// CaseRef is the docket / case identifier. Surfaced in
	// Verdict.Reason for human-readable diagnostics.
	CaseRef string

	// ObservedEvents is the set of event_types that appear in the
	// case-root subtree at the time of the check. Used by
	// RequiredAncestor rules.
	ObservedEvents []string

	// PrimaryAuthorityScopes lists every authority scope the
	// primary signer holds in their delegation chain (e.g.
	// "judicial_appointment_authority", "filing_authority"). Used
	// by RequiredAuthority rules.
	PrimaryAuthorityScopes []string
}

// ─── Verdict + Violation ───────────────────────────────────────────

// Violation is a single rule that the walker found unsatisfied.
type Violation struct {
	Mode   PrereqMode
	Rule   *Prereq // pointer into the rule list returned by Lookup
	Reason string  // copied from Rule.Reason; preserved for audit
}

// Verdict is the closed-set outcome of Walker.Check.
type Verdict struct {
	// OK is true iff there are zero Hard violations AND event_type
	// is in the vocabulary.
	OK bool

	// EventType echoes the input for log diagnostics.
	EventType string

	// Rejection is the closed-set rejection code. Set to WalkOK
	// when OK==true.
	Rejection Rejection

	// Reason is a human-readable summary of why the verdict landed
	// the way it did. Empty for the OK happy path.
	Reason string

	// Hard contains every Hard rule violation. Non-empty implies
	// !OK. Order mirrors Lookup's return order.
	Hard []Violation

	// Advisory contains every Advisory rule violation. Surfaced
	// for audit; does NOT influence OK.
	Advisory []Violation
}

// ─── Walker ─────────────────────────────────────────────────────────

// Walker is the prerequisite predicate. Construct once per
// process; reuse across entries. Safe for concurrent use as long
// as the underlying Policy is.
type Walker struct {
	Policy Policy
}

// Check evaluates eventType against the policy using ctx as the
// observed-state input. Returns a Verdict. Never returns an error
// — the verdict's Rejection field carries the failure mode.
func (w *Walker) Check(eventType string, ctx CaseContext) Verdict {
	if w == nil || w.Policy == nil {
		return Verdict{
			EventType: eventType,
			Rejection: WalkPolicyError,
			Reason:    "walker has no policy",
		}
	}
	if !w.Policy.KnowsEventType(eventType) {
		return Verdict{
			EventType: eventType,
			Rejection: WalkRejectUnknownEvent,
			Reason:    fmt.Sprintf("%q is not in the closed-set vocabulary", eventType),
		}
	}
	rules, err := w.Policy.Lookup(eventType)
	if err != nil {
		return Verdict{
			EventType: eventType,
			Rejection: WalkPolicyError,
			Reason:    fmt.Sprintf("policy lookup error: %v", err),
		}
	}

	v := Verdict{EventType: eventType}
	for i := range rules {
		rule := &rules[i]
		ok, why := evaluateRule(rule, ctx)
		if ok {
			continue
		}
		viol := Violation{Mode: rule.Mode, Rule: rule, Reason: why}
		switch rule.Mode {
		case PrereqModeHard:
			v.Hard = append(v.Hard, viol)
		case PrereqModeAdvisory:
			v.Advisory = append(v.Advisory, viol)
		}
	}

	if len(v.Hard) == 0 {
		v.OK = true
		v.Rejection = WalkOK
		return v
	}
	first := v.Hard[0]
	if first.Rule.IsAuthorityRule() {
		v.Rejection = WalkRejectMissingAuthority
	} else {
		v.Rejection = WalkRejectMissingAncestor
	}
	v.Reason = first.Reason
	return v
}

// ─── helpers ────────────────────────────────────────────────────────

// evaluateRule returns (satisfied, reason). When satisfied, reason
// is "". When unsatisfied, reason is a short diagnostic.
func evaluateRule(r *Prereq, ctx CaseContext) (bool, string) {
	if r.IsAncestorRule() {
		for _, want := range r.RequiredAncestor {
			if HasObservedEvent(ctx, want) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%s: requires one of %v in subtree", r.Reason, r.RequiredAncestor)
	}
	if r.IsAuthorityRule() {
		if HasAuthorityScope(ctx, r.RequiredAuthority) {
			return true, ""
		}
		return false, fmt.Sprintf("%s: signer lacks scope %q", r.Reason, r.RequiredAuthority)
	}
	// Defensive — validateRule should have rejected this rule.
	return false, "malformed rule"
}

// HasObservedEvent reports whether eventType appears in
// ctx.ObservedEvents. Linear scan — the slice is small in practice
// (one case-root subtree).
func HasObservedEvent(ctx CaseContext, eventType string) bool {
	for _, e := range ctx.ObservedEvents {
		if e == eventType {
			return true
		}
	}
	return false
}

// HasAuthorityScope reports whether scope appears in
// ctx.PrimaryAuthorityScopes.
func HasAuthorityScope(ctx CaseContext, scope string) bool {
	for _, s := range ctx.PrimaryAuthorityScopes {
		if s == scope {
			return true
		}
	}
	return false
}
