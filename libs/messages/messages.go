// Package messages is the agnostic catalog of the FOUNDATIONAL message
// structures a baseproof ledger accepts — the typed entries every network
// speaks, with no domain knowledge. A network ACCEPTS a subset (named in its
// network bundle's "messages" section) and layers domain payload schemas on top.
//
// The catalog names each structure, the lane + authority it resolves through,
// its effect on the SMT, and the fields it requires beyond the common
// SignerDID + Destination — so a client can answer "what can I say to this
// network", and submit/validation can reject a structure the network does not
// admit before anything hits the wire.
//
// It mirrors the SDK's typed builders (baseproof builder/entry_builders.go);
// messages_test.go constructs a representative set with the real SDK and pins
// each one's authority path, so the catalog and the SDK cannot silently drift.
package messages

import "sort"

// Lane groups structures by the role they play in the log.
type Lane string

const (
	LaneOrigin     Lane = "origin"     // an entity's own lifecycle
	LaneAuthority  Lane = "authority"  // scope / authority-set governance
	LaneKey        Lane = "key"        // key rotation / pre-commitment
	LaneSchema     Lane = "schema"     // schema (vocabulary) definitions
	LaneCommentary Lane = "commentary" // zero-SMT-impact annotations
)

// Authority is how the ledger authorizes the structure's effect.
type Authority string

const (
	AuthSameSigner Authority = "same-signer"     // the entity's own key
	AuthDelegated  Authority = "delegated"       // a delegate, via a delegation chain
	AuthScope      Authority = "scope-authority" // a member of the scope's authority set
	AuthNone       Authority = "none"            // no authority effect (commentary)
)

// LeafEffect is the structure's impact on the SMT (membership) tree.
type LeafEffect string

const (
	LeafNone   LeafEffect = "none"   // no leaf created or changed
	LeafCreate LeafEffect = "create" // mints a new SMT leaf
	LeafMutate LeafEffect = "mutate" // advances an existing leaf's tips
)

// Structure describes one foundational message structure.
type Structure struct {
	Name      string     // agnostic canonical name (a network bundle references this)
	Builder   string     // the SDK builder that constructs it (diagnostic)
	Lane      Lane       //
	Authority Authority  //
	Leaf      LeafEffect //
	Requires  []string   // params required beyond the common SignerDID + Destination
	Summary   string     //
}

// catalog is the full, ordered set of foundational structures. Order is lane,
// then lifecycle — the order `info` prints them in.
var catalog = []Structure{
	{"entity", "BuildRootEntity", LaneOrigin, AuthSameSigner, LeafCreate, nil,
		"A new root entity; becomes an SMT leaf (OriginTip = AuthorityTip = self)."},
	{"amendment", "BuildAmendment", LaneOrigin, AuthSameSigner, LeafMutate, []string{"TargetRoot"},
		"A same-signer update of an entity; advances its OriginTip."},
	{"delegated-amendment", "BuildPathBEntry", LaneOrigin, AuthDelegated, LeafMutate, []string{"TargetRoot", "DelegationPointers"},
		"An update authorized by a delegation chain (a delegate signs); advances OriginTip."},
	{"delegation", "BuildDelegation", LaneOrigin, AuthSameSigner, LeafCreate, []string{"DelegateDID"},
		"Grants authority from an owner to a delegate; a leaf, live until revoked."},
	{"succession", "BuildSuccession", LaneOrigin, AuthSameSigner, LeafMutate, []string{"TargetRoot"},
		"Replaces an entity (same signer); advances OriginTip."},
	{"revocation", "BuildRevocation", LaneOrigin, AuthSameSigner, LeafMutate, []string{"TargetRoot"},
		"Revokes an entity; breaks liveness of delegations off it."},

	{"scope", "BuildScopeCreation", LaneAuthority, AuthSameSigner, LeafCreate, []string{"AuthoritySet"},
		"A scope entity carrying an authority set (the signer must be in the set)."},
	{"scope-amendment", "BuildScopeAmendment", LaneAuthority, AuthScope, LeafMutate, []string{"TargetRoot", "NewAuthoritySet"},
		"Updates a scope's authority set; advances AuthorityTip."},
	{"scope-removal", "BuildScopeRemoval", LaneAuthority, AuthScope, LeafMutate, []string{"ScopePointer"},
		"Removes a scope authority; advances AuthorityTip."},
	{"enforcement", "BuildEnforcement", LaneAuthority, AuthScope, LeafMutate, []string{"TargetRoot", "ScopePointer"},
		"A scope-authority enforcement; advances AuthorityTip, not OriginTip."},

	{"key-rotation", "BuildKeyRotation", LaneKey, AuthSameSigner, LeafMutate, []string{"TargetRoot"},
		"Rotates a DID profile's key (requires a payload or a new public key)."},
	{"key-precommit", "BuildKeyPrecommit", LaneKey, AuthSameSigner, LeafMutate, []string{"TargetRoot"},
		"Pre-commits the next key for a future rotation."},

	{"schema", "BuildSchemaEntry", LaneSchema, AuthSameSigner, LeafCreate, []string{"Parameters"},
		"Defines a schema — the payload vocabulary other entries cite by SchemaRef."},

	{"commentary", "BuildCommentary", LaneCommentary, AuthNone, LeafNone, nil,
		"Free-form commentary; zero SMT impact."},
	{"cosignature", "BuildCosignature", LaneCommentary, AuthNone, LeafNone, []string{"CosignatureOf"},
		"Endorses another entry; zero SMT impact."},
	{"recovery-request", "BuildRecoveryRequest", LaneCommentary, AuthNone, LeafNone, nil,
		"Initiates key recovery; escrow nodes cosign to authorize."},
	{"mirror", "BuildMirrorEntry", LaneCommentary, AuthNone, LeafNone, []string{"SourceLogDID"},
		"Mirrors a foreign-log entry for cross-jurisdiction relay; zero SMT impact."},
}

// Catalog returns all foundational structures in stable (lane, lifecycle) order.
func Catalog() []Structure {
	out := make([]Structure, len(catalog))
	copy(out, catalog)
	return out
}

// Lookup returns the structure with the given canonical name.
func Lookup(name string) (Structure, bool) {
	for _, s := range catalog {
		if s.Name == name {
			return s, true
		}
	}
	return Structure{}, false
}

// Valid reports whether name is a known foundational structure.
func Valid(name string) bool {
	_, ok := Lookup(name)
	return ok
}

// Names returns every canonical structure name, sorted.
func Names() []string {
	out := make([]string, len(catalog))
	for i, s := range catalog {
		out[i] = s.Name
	}
	sort.Strings(out)
	return out
}

// Unknown returns the names in `accepted` that are NOT foundational structures —
// so a network bundle's "messages" list can be validated (empty ⇒ all known).
func Unknown(accepted []string) []string {
	var bad []string
	for _, n := range accepted {
		if !Valid(n) {
			bad = append(bad, n)
		}
	}
	return bad
}
