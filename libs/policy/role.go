/*
FILE PATH: libs/policy/role.go

DESCRIPTION:

	Actor classification + the role-catalog row. The MECHANISM of
	authority policy: how a role is shaped (actor class, delegation
	durations, scope bounds, grant edges). The CONTENT — which roles a
	network defines, their names and scope vocabularies — is the network
	owner's catalog, built from these shapes.

	Three actor classes, by cryptographic relationship to the log:

	  Actor 1 — Signer. Holds network keys; appears in the role
	            catalog and in delegation chains.
	  Actor 2 — Filer. Holds an own DID sufficient to cosign a
	            filing, but has no catalog entry and no delegation
	            chain — every filing carries a filed_by_capacity
	            block declaring role + credentials; the on-log claim
	            IS the record.
	  Actor 3 — Party. A passive metadata subject, recorded only via
	            binding payloads.

	Membership-by-actor answers "may this role cosign a filer's
	submission?" — the catalog stores the actor class; the
	cosignature-mix evaluator reads it.

OVERVIEW:

	Actor      — closed-set int enum (stable wire values).
	Role       — one catalog row (JSON-taggable for file loaders and
	             for embedding in the network manifest).
	ValidateActor / ValidateRole — structural checks.

KEY DEPENDENCIES:

	None — stdlib only.
*/
package policy

import (
	"fmt"
	"time"
)

// Actor enumerates the closed-set classification. Integer values are
// STABLE — JSON catalog loaders and on-log payloads serialize the int.
// Adding a new class appends at the end; never renumber.
type Actor int

const (
	// ActorUnspecified is the zero value. Validation rejects it; it
	// exists only so omitting Actor in code produces a loud error
	// rather than silently classifying as a Signer.
	ActorUnspecified Actor = 0

	// ActorSigner holds network cryptographic keys with an on-log
	// delegation chain.
	ActorSigner Actor = 1

	// ActorFiler holds an own DID for cosignature but has no
	// catalog entry and no delegation chain; capacity travels in
	// the payload's filed_by_capacity block.
	ActorFiler Actor = 2

	// ActorParty is a passive metadata subject.
	ActorParty Actor = 3
)

// String returns a human-readable name. Used in audit logs and
// error messages. Stable strings — log parsers key on these.
func (a Actor) String() string {
	switch a {
	case ActorUnspecified:
		return "actor_unspecified"
	case ActorSigner:
		return "actor_signer"
	case ActorFiler:
		return "actor_filer"
	case ActorParty:
		return "actor_party"
	default:
		return fmt.Sprintf("actor_unknown_%d", int(a))
	}
}

// IsValid reports whether a is one of the three defined classes.
// ActorUnspecified is NOT valid — calling code must opt in.
func (a Actor) IsValid() bool {
	switch a {
	case ActorSigner, ActorFiler, ActorParty:
		return true
	default:
		return false
	}
}

// HoldsKeys reports whether actors of this class hold network
// cryptographic keys with on-log delegation-chain authority.
// Only ActorSigner does. ActorFiler holds an OWN DID sufficient to
// produce a cosignature, but no catalog entry, no chain, no scope —
// the cosignature-mix evaluator uses this distinction.
func (a Actor) HoldsKeys() bool {
	return a == ActorSigner
}

// ValidateActor returns nil iff a is a defined class.
func ValidateActor(a Actor) error {
	if !a.IsValid() {
		return fmt.Errorf("policy/role: actor must be one of {1, 2, 3}, got %d (%s)",
			int(a), a.String())
	}
	return nil
}

// Role is the typed description of one role in a network's catalog.
// Field JSON tags allow a single struct to be loaded from a JSON
// catalog file and embedded verbatim in the network manifest.
type Role struct {
	// Name is the catalog key. Required, must equal the map key in
	// any catalog that stores it.
	Name string `json:"name"`

	// Actor classifies the role. Catalogs list ActorSigner
	// (key-holding) roles by design — ActorFiler attestations live
	// in the payload's filed_by_capacity block; ActorParty subjects
	// in binding entries.
	//
	// Stored as an int via the Actor alias so JSON loaders accept
	// plain numbers ({"actor": 1}) without a custom unmarshaller.
	Actor Actor `json:"actor"`

	// Description is human-readable; recorded only in the catalog,
	// not on-log.
	Description string `json:"description,omitempty"`

	// MaxDuration is the upper bound on (ExpiresAt - IssuedAt) for
	// any delegation in this role. Required (>0).
	MaxDuration time.Duration `json:"max_duration"`

	// DefaultDuration is what delegation issuance uses when the
	// caller does not specify ExpiresAt. Must be <= MaxDuration.
	// Required.
	DefaultDuration time.Duration `json:"default_duration"`

	// AllowedScope is the universe of scope tokens a holder of this
	// role *may* be granted. Issued delegations' Scope must be a
	// subset. Required (non-empty).
	AllowedScope []string `json:"allowed_scope"`

	// DefaultScope is the scope tokens granted when the caller
	// passes no Scope. Must be a subset of AllowedScope. Required
	// (non-empty).
	DefaultScope []string `json:"default_scope"`

	// DelegableBy lists the role names that may *grant* this role.
	// "*" means any role whose own scope includes the matching
	// invite:* token. Empty means no role may grant — the role is
	// instituted directly by the institutional DID at depth 0.
	DelegableBy []string `json:"delegable_by,omitempty"`

	// DelegableScope is the slice of AllowedScope a holder of this
	// role may pass downstream when granting another role. If empty
	// and DelegableBy is non-empty, holders may pass through any
	// subset of their own current scope. The SDK's scope-enforcement
	// intersection rule (narrower-cannot-be-widened) always applies
	// on top of this.
	DelegableScope []string `json:"delegable_scope,omitempty"`
}

// ValidateRole runs the structural checks a catalog row must satisfy:
// a name, a valid Signer actor class (catalogs hold key-holding roles),
// positive durations with DefaultDuration <= MaxDuration, and a
// non-empty DefaultScope ⊆ AllowedScope.
func ValidateRole(r Role) error {
	if r.Name == "" {
		return fmt.Errorf("policy/role: name required")
	}
	if err := ValidateActor(r.Actor); err != nil {
		return fmt.Errorf("policy/role: %q: %w", r.Name, err)
	}
	if r.Actor != ActorSigner {
		return fmt.Errorf("policy/role: %q: catalogs hold key-holding (signer) roles; got %s",
			r.Name, r.Actor)
	}
	if r.MaxDuration <= 0 {
		return fmt.Errorf("policy/role: %q: max_duration must be > 0", r.Name)
	}
	if r.DefaultDuration <= 0 || r.DefaultDuration > r.MaxDuration {
		return fmt.Errorf("policy/role: %q: default_duration must be in (0, max_duration]", r.Name)
	}
	if len(r.AllowedScope) == 0 {
		return fmt.Errorf("policy/role: %q: allowed_scope required", r.Name)
	}
	if len(r.DefaultScope) == 0 {
		return fmt.Errorf("policy/role: %q: default_scope required", r.Name)
	}
	allowed := make(map[string]struct{}, len(r.AllowedScope))
	for _, s := range r.AllowedScope {
		allowed[s] = struct{}{}
	}
	for _, s := range r.DefaultScope {
		if _, ok := allowed[s]; !ok {
			return fmt.Errorf("policy/role: %q: default_scope token %q not in allowed_scope", r.Name, s)
		}
	}
	return nil
}
