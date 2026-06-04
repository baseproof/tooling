/*
FILE PATH: libs/prereq/policy.go

DESCRIPTION:

	.preqs prerequisite policy. Two intertwined v1.6
	surfaces ship in this package:

	  1. Closed-set vocabulary. Only event_types declared in the
	     policy may appear on-log. The walker rejects unknown
	     event_types up front; the aggregator enforces the same
	     constraint downstream. No silent additions.

	  2. Per-event prerequisite rules. Each event_type carries zero
	     or more Prereq entries. Each rule is either Hard (the
	     walker rejects when unsatisfied) or Advisory (surfaced for
	     audit but does not block). Two rule shapes ship:

	       RequiredAncestor  — at least one entry of one of these
	                           event_types must already exist in the
	                           case-root subtree (e.g.,
	                           motion_continuance requires a
	                           case_initiated ancestor).

	       RequiredAuthority — the primary signer's delegation chain
	                           must include this authority scope
	                           (e.g., judicial_appointment requires
	                           judicial_appointment_authority).

	The verifier evaluates rules against a CaseContext the caller
	builds (observed event_types in the subtree + authority scopes
	held by the primary signer). This keeps the policy module pure
	— no fetcher, no walk-the-SMT side effects — so tests can drive
	every rule from a small in-memory fixture.

OVERVIEW:

	PrereqMode      — Hard | Advisory enum.
	Prereq          — single rule.
	EventRuleSet    — ([]Prereq) for one event_type.
	Policy          — interface (KnowsEventType, Lookup, EventTypes).
	InMemoryPolicy  — RWMutex-protected map impl.
	Sentinels.

KEY DEPENDENCIES:

	None — pure data.
*/
package prereq

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ─── Mode enum ──────────────────────────────────────────────────────

// PrereqMode classifies a prerequisite. Closed set; the walker uses
// it to decide whether a violation rejects the entry (Hard) or just
// surfaces an audit-trail note (Advisory).
type PrereqMode int

const (
	// PrereqModeUnspecified is the zero value. validateRule rejects
	// it; an explicit Hard/Advisory tag is required so writers
	// cannot accidentally ship a no-op rule.
	PrereqModeUnspecified PrereqMode = 0

	// PrereqModeHard means the walker rejects the entry when this
	// rule is unsatisfied.
	PrereqModeHard PrereqMode = 1

	// PrereqModeAdvisory means the walker surfaces the violation in
	// the verdict's Advisory list but does NOT reject. Used for
	// recommended-but-not-blocking rules (e.g., transcripts that
	// should but need not exist before publication).
	PrereqModeAdvisory PrereqMode = 2
)

// String returns a human-readable mode label.
func (m PrereqMode) String() string {
	switch m {
	case PrereqModeHard:
		return "hard"
	case PrereqModeAdvisory:
		return "advisory"
	default:
		return "unspecified"
	}
}

// IsValid reports whether m is Hard or Advisory.
func (m PrereqMode) IsValid() bool {
	return m == PrereqModeHard || m == PrereqModeAdvisory
}

// ─── Rule ───────────────────────────────────────────────────────────

// Prereq is one prerequisite rule for an event_type. Exactly one of
// RequiredAncestor or RequiredAuthority must be set; the validator
// rejects rules that set both or neither.
type Prereq struct {
	// Mode classifies the rule (Hard | Advisory). Required.
	Mode PrereqMode `json:"mode"`

	// RequiredAncestor: at least one entry whose event_type is in
	// this list must already exist in the case-root subtree. OR
	// semantics. Mutually exclusive with RequiredAuthority.
	RequiredAncestor []string `json:"required_ancestor,omitempty"`

	// RequiredAuthority: the primary signer's authority chain must
	// include this scope (e.g., "judicial_appointment_authority").
	// Mutually exclusive with RequiredAncestor.
	RequiredAuthority string `json:"required_authority,omitempty"`

	// Reason is a human-readable explanation surfaced in
	// Verdict.Violations. Required (non-empty).
	Reason string `json:"reason"`
}

// IsAncestorRule reports whether this rule checks the case-root
// subtree (RequiredAncestor non-empty).
func (p *Prereq) IsAncestorRule() bool {
	return p != nil && len(p.RequiredAncestor) > 0
}

// IsAuthorityRule reports whether this rule checks the primary
// signer's authority chain (RequiredAuthority non-empty).
func (p *Prereq) IsAuthorityRule() bool {
	return p != nil && p.RequiredAuthority != ""
}

// ─── Policy interface ───────────────────────────────────────────────

// Policy is the closed-set prerequisite store. The vocabulary is
// the set of event_types with at least one entry (even an empty
// rule list) — KnowsEventType returns true for those. Unknown
// event_types are rejected by the walker.
type Policy interface {
	// KnowsEventType reports whether eventType is in the closed-set
	// vocabulary. Used by the walker as the vocabulary gate.
	KnowsEventType(eventType string) bool

	// Lookup returns the rule list for eventType, or
	// ErrUnknownEventType when not in the vocabulary. Returning a
	// rule list of length 0 means "the event is in the vocabulary
	// but has no prerequisites" — distinct from "unknown".
	Lookup(eventType string) ([]Prereq, error)

	// EventTypes returns a sorted snapshot of all known event_types.
	// Used by the aggregator for closed-set audits.
	EventTypes() []string
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	ErrUnknownEventType = errors.New("prerequisites: event_type not in vocabulary")
	ErrInvalidRule      = errors.New("prerequisites: invalid rule")
	ErrDuplicateEvent   = errors.New("prerequisites: duplicate event_type registration")
)

// ─── InMemoryPolicy ─────────────────────────────────────────────────

// InMemoryPolicy is the default Policy backed by a single map. Safe
// for concurrent reads and writes. Construct via NewInMemoryPolicy
// (validated) or NewEmptyInMemoryPolicy (test scaffolding).
type InMemoryPolicy struct {
	mu sync.RWMutex
	m  map[string][]Prereq
}

// NewEmptyInMemoryPolicy constructs an empty policy. Useful for
// tests that build the vocabulary one rule at a time.
func NewEmptyInMemoryPolicy() *InMemoryPolicy {
	return &InMemoryPolicy{m: make(map[string][]Prereq)}
}

// NewInMemoryPolicy constructs a policy from a list of (event_type,
// rules) pairs and validates every rule. Returns ErrInvalidRule on
// any structural failure or ErrDuplicateEvent if the same
// event_type appears twice.
func NewInMemoryPolicy(rulesByEvent map[string][]Prereq) (*InMemoryPolicy, error) {
	out := NewEmptyInMemoryPolicy()
	for evt, rules := range rulesByEvent {
		if err := out.Register(evt, rules); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Register adds eventType + its rules to the policy. Returns
// ErrDuplicateEvent if eventType is already registered, or
// ErrInvalidRule if any rule fails structural validation.
func (p *InMemoryPolicy) Register(eventType string, rules []Prereq) error {
	if eventType == "" {
		return fmt.Errorf("%w: empty event_type", ErrInvalidRule)
	}
	for i := range rules {
		if err := validateRule(&rules[i]); err != nil {
			return fmt.Errorf("%s rule[%d]: %w", eventType, i, err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.m[eventType]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateEvent, eventType)
	}
	cp := make([]Prereq, len(rules))
	copy(cp, rules)
	p.m[eventType] = cp
	return nil
}

// KnowsEventType satisfies Policy.
func (p *InMemoryPolicy) KnowsEventType(eventType string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.m[eventType]
	return ok
}

// Lookup satisfies Policy.
func (p *InMemoryPolicy) Lookup(eventType string) ([]Prereq, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	rules, ok := p.m[eventType]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownEventType, eventType)
	}
	cp := make([]Prereq, len(rules))
	copy(cp, rules)
	return cp, nil
}

// EventTypes satisfies Policy.
func (p *InMemoryPolicy) EventTypes() []string {
	p.mu.RLock()
	out := make([]string, 0, len(p.m))
	for k := range p.m {
		out = append(out, k)
	}
	p.mu.RUnlock()
	sort.Strings(out)
	return out
}

// ─── validation helper ─────────────────────────────────────────────

// validateRule enforces the Prereq invariants. Exposed for tests.
func validateRule(r *Prereq) error {
	if r == nil {
		return fmt.Errorf("%w: nil rule", ErrInvalidRule)
	}
	if !r.Mode.IsValid() {
		return fmt.Errorf("%w: mode unspecified", ErrInvalidRule)
	}
	hasAncestor := len(r.RequiredAncestor) > 0
	hasAuthority := r.RequiredAuthority != ""
	if hasAncestor && hasAuthority {
		return fmt.Errorf("%w: ancestor + authority on same rule", ErrInvalidRule)
	}
	if !hasAncestor && !hasAuthority {
		return fmt.Errorf("%w: rule must set ancestor or authority", ErrInvalidRule)
	}
	if r.Reason == "" {
		return fmt.Errorf("%w: empty reason", ErrInvalidRule)
	}
	return nil
}

// Static check.
var _ Policy = (*InMemoryPolicy)(nil)
