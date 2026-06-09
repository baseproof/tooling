package messages

import (
	"testing"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"
)

// TestCatalogIntegrity pins the catalog's internal invariants: unique names +
// builders, no empty fields, known enum values, and the commentary lane carries
// no authority/leaf effect.
func TestCatalogIntegrity(t *testing.T) {
	names := map[string]bool{}
	builders := map[string]bool{}
	for _, s := range Catalog() {
		if s.Name == "" || s.Builder == "" || s.Summary == "" {
			t.Errorf("structure %+v has an empty Name/Builder/Summary", s)
		}
		if names[s.Name] {
			t.Errorf("duplicate structure name %q", s.Name)
		}
		names[s.Name] = true
		if builders[s.Builder] {
			t.Errorf("duplicate builder %q", s.Builder)
		}
		builders[s.Builder] = true
		switch s.Lane {
		case LaneOrigin, LaneAuthority, LaneKey, LaneSchema, LaneCommentary:
		default:
			t.Errorf("%s: unknown lane %q", s.Name, s.Lane)
		}
		switch s.Authority {
		case AuthSameSigner, AuthDelegated, AuthScope, AuthNone:
		default:
			t.Errorf("%s: unknown authority %q", s.Name, s.Authority)
		}
		switch s.Leaf {
		case LeafNone, LeafCreate, LeafMutate:
		default:
			t.Errorf("%s: unknown leaf effect %q", s.Name, s.Leaf)
		}
		if s.Lane == LaneCommentary && (s.Authority != AuthNone || s.Leaf != LeafNone) {
			t.Errorf("%s: commentary must be authority=none leaf=none, got %s/%s", s.Name, s.Authority, s.Leaf)
		}
	}

	if _, ok := Lookup("entity"); !ok {
		t.Error("Lookup(entity) should hit")
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup(nope) should miss")
	}
	if !Valid("amendment") || Valid("nope") {
		t.Error("Valid wrong")
	}
	if got := Unknown([]string{"entity", "nope", "schema"}); len(got) != 1 || got[0] != "nope" {
		t.Errorf("Unknown = %v, want [nope]", got)
	}
	if len(Names()) != len(catalog) {
		t.Errorf("Names len %d != catalog %d", len(Names()), len(catalog))
	}
}

// TestCatalogMatchesSDK constructs one structure per AUTHORITY kind with the
// REAL SDK builders and asserts the catalog's Authority equals the AuthorityPath
// the SDK actually set on the header — the cross-check that keeps the catalog
// honest (a relabelled structure here fails the build).
func TestCatalogMatchesSDK(t *testing.T) {
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer := kp.DID
	const dest = "did:web:exchange.example"
	pos := types.LogPosition{LogDID: "did:web:log.example", Sequence: 1}
	authSet := map[string]struct{}{signer: {}}

	build := func(name string) (*envelope.Entry, error) {
		switch name {
		case "entity":
			return builder.BuildRootEntity(builder.RootEntityParams{Destination: dest, SignerDID: signer, Payload: []byte("x")})
		case "amendment":
			return builder.BuildAmendment(builder.AmendmentParams{Destination: dest, SignerDID: signer, TargetRoot: pos, Payload: []byte("x")})
		case "delegation":
			return builder.BuildDelegation(builder.DelegationParams{Destination: dest, SignerDID: signer, DelegateDID: "did:key:zDelegate", Payload: []byte("x")})
		case "delegated-amendment":
			return builder.BuildPathBEntry(builder.PathBParams{Destination: dest, SignerDID: signer, TargetRoot: pos, DelegationPointers: []types.LogPosition{pos}, Payload: []byte("x")})
		case "scope":
			return builder.BuildScopeCreation(builder.ScopeCreationParams{Destination: dest, SignerDID: signer, AuthoritySet: authSet, Payload: []byte("x")})
		case "scope-amendment":
			return builder.BuildScopeAmendment(builder.ScopeAmendmentParams{Destination: dest, SignerDID: signer, TargetRoot: pos, ScopePointer: pos, NewAuthoritySet: authSet, Payload: []byte("x")})
		case "commentary":
			return builder.BuildCommentary(builder.CommentaryParams{Destination: dest, SignerDID: signer, Payload: []byte("x")})
		case "cosignature":
			return builder.BuildCosignature(builder.CosignatureParams{Destination: dest, SignerDID: signer, CosignatureOf: pos, Payload: []byte("x")})
		case "mirror":
			return builder.BuildMirrorEntry(builder.MirrorParams{Destination: dest, SignerDID: signer, SourceLogDID: "did:web:other.log", SourcePosition: pos})
		}
		t.Fatalf("no builder wired for %q", name)
		return nil, nil
	}

	want := map[Authority]*envelope.AuthorityPath{
		AuthSameSigner: ap(envelope.AuthoritySameSigner),
		AuthDelegated:  ap(envelope.AuthorityDelegation),
		AuthScope:      ap(envelope.AuthorityScopeAuthority),
		AuthNone:       nil,
	}

	for _, name := range []string{
		"entity", "amendment", "delegation", "delegated-amendment",
		"scope", "scope-amendment", "commentary", "cosignature", "mirror",
	} {
		s, ok := Lookup(name)
		if !ok {
			t.Fatalf("catalog missing %q", name)
		}
		e, err := build(name)
		if err != nil {
			t.Fatalf("%s: SDK build failed: %v", name, err)
		}
		got := e.Header.AuthorityPath
		exp := want[s.Authority]
		switch {
		case exp == nil && got != nil:
			t.Errorf("%s: catalog authority=%s (nil path) but SDK set %v", name, s.Authority, *got)
		case exp != nil && got == nil:
			t.Errorf("%s: catalog authority=%s (%v) but SDK set nil", name, s.Authority, *exp)
		case exp != nil && got != nil && *exp != *got:
			t.Errorf("%s: catalog authority=%s ⇒ %v, but SDK set %v", name, s.Authority, *exp, *got)
		}
	}
}

func ap(p envelope.AuthorityPath) *envelope.AuthorityPath { return &p }
