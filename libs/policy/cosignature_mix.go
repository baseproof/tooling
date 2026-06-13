/*
FILE PATH: libs/policy/cosignature_mix.go

DESCRIPTION:

	Intra-entry signature-mix policy — the agnostic mechanism for "which
	filer capacity may file which event_type, cosigned by which signer
	roles, at what threshold". One entry, N inline signatures in
	entry.Signatures, role-filtered threshold per event_type.

	SCOPE — NOT to be confused with the SDK's attestation.Policy. That
	primitive governs SEPARATE attestation entries pointing at a primary
	via ControlHeader.CosignatureOf. This package governs multiple
	signatures INSIDE a single entry. Both mechanics coexist; the wire
	field name remains "cosignature" for compatibility.

	The policy is a closed-set table. A verifier calls Lookup(eventType)
	once per entry and reads the rule:

	  rule.AllowedFilerRoles    — the capacity role must be in here
	  rule.RequiredSignerRoles  — at least one cosigner must hold one
	  rule.MinSignerCosigners   — count threshold (default 1)
	  rule.IntraExchangeOnly    — every signer from the entry's exchange
	  rule.RequiredCredentials  — capacity.credentials must contain each

	MECHANISM vs CONTENT: this package owns the rule SHAPE and its
	evaluation. The role vocabulary (which filer roles exist on a given
	network) is the network owner's CONTENT, injected via
	WithKnownFilerRoles — never hardcoded here. Without the option the
	set is open: any non-empty token validates structurally.

OVERVIEW:

	FilerRole             — opaque role token (content defines values).
	CosignatureRule       — the rule struct.
	CosignatureMixPolicy  — interface (Lookup, List).
	InMemoryPolicy        — RWMutex-protected map implementation
	                        (methods in cosignature_mix_inmemory.go).
	Option                — construction options (WithKnownFilerRoles).
	Sentinel errors and structural validation.

KEY DEPENDENCIES:

	None — stdlib only. The network owner supplies role content.
*/
package policy

import (
	"errors"
	"fmt"
	"sync"
)

// FilerRole is an opaque filer-capacity token (e.g. "registrar",
// "operator"). The valid set for a network is the owner's content,
// supplied via WithKnownFilerRoles; this package never defines values.
type FilerRole string

// CosignatureRule is one row of the policy table — the cosignature
// requirements for a single event_type. Stable JSON tags; the
// loader (cosignature_mix_loader.go) round-trips this shape, and the
// network manifest embeds it verbatim so describe and validate share
// one source.
type CosignatureRule struct {
	// EventType is the snake_case event identifier.
	// Required, unique per policy instance.
	EventType string `json:"event_type"`

	// AllowedFilerRoles lists the FilerRole values that may file
	// this event. Empty means "no filer permitted" — the event is
	// solely a signer action; no filer cosignature is required and
	// the verifier accepts entries with no filed_by_capacity at all.
	AllowedFilerRoles []FilerRole `json:"allowed_filer_roles,omitempty"`

	// RequiredSignerRoles names the signer roles permitted to
	// cosign. OR semantics — at least one cosigner with a role in
	// this list must be present. Required (non-empty) when
	// AllowedFilerRoles is non-empty.
	RequiredSignerRoles []string `json:"required_signer_roles,omitempty"`

	// MinSignerCosigners is the minimum count of cosigners with
	// roles in RequiredSignerRoles. Default 1. Larger values for
	// sensitive events (e.g., 2 for a personnel appointment).
	MinSignerCosigners int `json:"min_signer_cosigners,omitempty"`

	// IntraExchangeOnly: when true, every cosigner must come from
	// the entry's exchange (Header.Destination). When false,
	// cross-exchange cosigners are accepted (transfers, relay
	// attestations, bulk imports).
	IntraExchangeOnly bool `json:"intra_exchange_only"`

	// RequiredCredentials is the list of credential keys the
	// filer's capacity.credentials map must contain (non-empty
	// values) — e.g. a bar/registration number for professional
	// filings.
	RequiredCredentials []string `json:"required_credentials,omitempty"`

	// RequiredScope is the scope(s) a cosigner's on-log delegation must
	// grant to cosign this event — handed to the verifying walk as the
	// Constraint.RequiredScopes. PRE-13b #181 scope-at-publish: a GATED
	// event (one with RequiredSignerRoles) MUST declare a non-empty
	// RequiredScope, so the walk always has a scope to enforce. A network
	// cannot publish a gated event whose scope is undeclared
	// (ValidateScopeAtPublish). Empty is valid only for a non-gated event.
	RequiredScope []string `json:"required_scope,omitempty"`
}

// PermitsFilerRole reports whether role is in the rule's
// AllowedFilerRoles list. Convenience used by verifiers.
func (r *CosignatureRule) PermitsFilerRole(role FilerRole) bool {
	for _, allowed := range r.AllowedFilerRoles {
		if allowed == role {
			return true
		}
	}
	return false
}

// PermitsSignerRole reports whether signerRole is in the rule's
// RequiredSignerRoles list (OR semantics).
func (r *CosignatureRule) PermitsSignerRole(signerRole string) bool {
	for _, allowed := range r.RequiredSignerRoles {
		if allowed == signerRole {
			return true
		}
	}
	return false
}

// RequiresFiler reports whether this event MUST carry a
// filed_by_capacity block. False for signer-only events where no
// filer cosignature is involved.
func (r *CosignatureRule) RequiresFiler() bool {
	return len(r.AllowedFilerRoles) > 0
}

// EffectiveMinCosigners returns the minimum count of cosigners
// required for the event:
//
//   - If MinSignerCosigners > 0, use it (explicit threshold).
//   - Else, if the rule requires a filer, default to 1 (the
//     convention for professional filings).
//   - Else, 0 (pure-signer events need only the primary signer;
//     no cosignature threshold).
func (r *CosignatureRule) EffectiveMinCosigners() int {
	if r.MinSignerCosigners > 0 {
		return r.MinSignerCosigners
	}
	if r.RequiresFiler() {
		return 1
	}
	return 0
}

// RequiresScope reports whether this event is GATED — it requires authority
// cosigners (RequiredSignerRoles) and therefore must declare RequiredScope.
func (r *CosignatureRule) RequiresScope() bool {
	return len(r.RequiredSignerRoles) > 0
}

// RequiredScopes returns the scope set a cosigner's delegation must grant, for
// the verifying walk's Constraint.RequiredScopes.
func (r *CosignatureRule) RequiredScopes() []string {
	return r.RequiredScope
}

// ─── Interface ──────────────────────────────────────────────────────

// CosignatureMixPolicy is the seam between a verifier and the rule
// table. Implementations: InMemoryPolicy (this package); storage- or
// on-log-governed variants if a deployment needs them.
type CosignatureMixPolicy interface {
	// Lookup returns the rule for eventType, or ErrRuleNotFound
	// when unknown.
	Lookup(eventType string) (*CosignatureRule, error)

	// List returns all rules in deterministic order (alpha by
	// EventType).
	List() []*CosignatureRule
}

// ─── Sentinel errors ──────────────────────────────────────────────────

var (
	// ErrRuleNotFound fires from Lookup when eventType is unknown.
	// Verifier policy: closed-set, unknown events are REJECTED.
	ErrRuleNotFound = errors.New("policy/cosignature_mix: rule not found")

	// ErrInvalidRule fires for missing/malformed fields at construction.
	ErrInvalidRule = errors.New("policy/cosignature_mix: invalid rule")

	// ErrGatedEventNoScope is the scope-at-publish rejection (PRE-13b #181):
	// a gated event_type (one with RequiredSignerRoles) declared no
	// RequiredScope, so the verifying walk would have nothing to enforce. A
	// network cannot publish such a policy.
	ErrGatedEventNoScope = errors.New("policy/cosignature_mix: gated event_type has no required_scope (scope-at-publish)")

	// ErrDuplicateRule fires when Add or NewInMemoryPolicy receives
	// two rules with the same EventType.
	ErrDuplicateRule = errors.New("policy/cosignature_mix: duplicate rule")
)

// ─── Options ──────────────────────────────────────────────────────────

// Option configures policy construction (NewInMemoryPolicy, ParseJSON,
// LoadFile). Options are retained by the policy so later Add / Replace /
// ReloadFromFile validate under the same configuration.
type Option func(*options)

type options struct {
	knownFilerRoles map[FilerRole]struct{}
}

// WithKnownFilerRoles closes the filer-role set: any rule naming a
// filer role outside the given set is rejected with ErrInvalidRule.
// This is how a network owner injects its role vocabulary (content)
// into the validation mechanism. Omitting the option leaves the set
// open — structural validation only.
func WithKnownFilerRoles(roles ...FilerRole) Option {
	return func(o *options) {
		if o.knownFilerRoles == nil {
			o.knownFilerRoles = make(map[FilerRole]struct{}, len(roles))
		}
		for _, r := range roles {
			o.knownFilerRoles[r] = struct{}{}
		}
	}
}

// validateRule runs structural sanity, plus closed-set membership when
// known is non-nil. A rule with no filer roles (pure signer event) is
// valid — RequiredSignerRoles may be empty there. Otherwise the rule
// must list both filer + signer roles.
func validateRule(r CosignatureRule, known map[FilerRole]struct{}) error {
	if r.EventType == "" {
		return fmt.Errorf("%w: event_type required", ErrInvalidRule)
	}
	for i, fr := range r.AllowedFilerRoles {
		if fr == "" {
			return fmt.Errorf("%w: event %q allowed_filer_roles[%d] empty",
				ErrInvalidRule, r.EventType, i)
		}
		if known != nil {
			if _, ok := known[fr]; !ok {
				return fmt.Errorf("%w: event %q allowed_filer_roles[%d] %q not in the configured filer-role set",
					ErrInvalidRule, r.EventType, i, string(fr))
			}
		}
	}
	if r.RequiresFiler() && len(r.RequiredSignerRoles) == 0 {
		return fmt.Errorf("%w: event %q has filer roles but no required_signer_roles",
			ErrInvalidRule, r.EventType)
	}
	for i, sr := range r.RequiredSignerRoles {
		if sr == "" {
			return fmt.Errorf("%w: event %q required_signer_roles[%d] empty",
				ErrInvalidRule, r.EventType, i)
		}
	}
	if r.MinSignerCosigners < 0 {
		return fmt.Errorf("%w: event %q min_signer_cosigners must be >= 0",
			ErrInvalidRule, r.EventType)
	}
	for i, c := range r.RequiredCredentials {
		if c == "" {
			return fmt.Errorf("%w: event %q required_credentials[%d] empty",
				ErrInvalidRule, r.EventType, i)
		}
	}
	return nil
}

// ValidateScopeAtPublish enforces PRE-13b #181 scope-at-publish over a rule
// set: every GATED event_type (one with RequiredSignerRoles) MUST declare a
// non-empty RequiredScope, and every scope entry must be non-empty. Returns
// ErrGatedEventNoScope on the first gated-without-scope violation. Call it at
// bundle/policy publish (freeze) so a network cannot ship a gated event whose
// scope is undeclared — provenance is always enforced by the walk, so scope
// must always be present for the walk to enforce. Non-gated events may omit it.
func ValidateScopeAtPublish(rules []CosignatureRule) error {
	for i := range rules {
		r := &rules[i]
		if !r.RequiresScope() {
			continue
		}
		if len(r.RequiredScope) == 0 {
			return fmt.Errorf("%w: event %q", ErrGatedEventNoScope, r.EventType)
		}
		for j, s := range r.RequiredScope {
			if s == "" {
				return fmt.Errorf("%w: event %q required_scope[%d] empty",
					ErrInvalidRule, r.EventType, j)
			}
		}
	}
	return nil
}

// ─── InMemoryPolicy ──────────────────────────────────────────────────

// InMemoryPolicy is the default CosignatureMixPolicy. RWMutex-
// protected; safe for concurrent use. Method bodies live in
// cosignature_mix_inmemory.go.
type InMemoryPolicy struct {
	mu    sync.RWMutex
	rules map[string]*CosignatureRule
	opts  options
}

// NewInMemoryPolicy constructs a policy from a slice of rules.
// Rejects duplicates and validates each rule individually. Options
// (e.g. WithKnownFilerRoles) are retained for later Add / Replace /
// ReloadFromFile.
func NewInMemoryPolicy(rules []CosignatureRule, opts ...Option) (*InMemoryPolicy, error) {
	p := &InMemoryPolicy{rules: make(map[string]*CosignatureRule, len(rules))}
	for _, o := range opts {
		o(&p.opts)
	}
	for _, r := range rules {
		if err := validateRule(r, p.opts.knownFilerRoles); err != nil {
			return nil, err
		}
		if _, dup := p.rules[r.EventType]; dup {
			return nil, fmt.Errorf("%w: event_type=%s", ErrDuplicateRule, r.EventType)
		}
		copyRule := r
		p.rules[r.EventType] = &copyRule
	}
	return p, nil
}

// Static check that InMemoryPolicy satisfies the interface.
var _ CosignatureMixPolicy = (*InMemoryPolicy)(nil)
