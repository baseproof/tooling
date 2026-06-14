/*
FILE PATH: libs/policy/cosignature_mix_test.go

DESCRIPTION:

	Pins the cosignature-mix mechanism's contract:

	  - rule helpers (PermitsFilerRole / PermitsSignerRole /
	    RequiresFiler / EffectiveMinCosigners) over the three rule
	    classes: pure-signer, filer-with-default threshold, explicit
	    threshold;
	  - structural validation rejects every malformed shape with
	    ErrInvalidRule, and the CLOSED-SET option (WithKnownFilerRoles)
	    converts unknown filer tokens from accepted to rejected —
	    proving the mechanism/content split: content is injected,
	    never hardcoded;
	  - the table is copy-safe (mutating a Lookup/List result cannot
	    corrupt the policy) and concurrency-safe under -race;
	  - the loader trio: ParseJSON/LoadFile construct-or-refuse
	    atomically; a failed ReloadFromFile leaves the prior rules
	    fully in effect (the system never goes policy-less).

	Fixtures use a neutral vocabulary (operator/registrar/approver)
	— the mechanism owns no domain.
*/
package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// filedRule is the common filer-cosigned rule fixture.
func filedRule(evt string) CosignatureRule {
	return CosignatureRule{
		EventType:           evt,
		AllowedFilerRoles:   []FilerRole{"operator", "registrar"},
		RequiredSignerRoles: []string{"approver"},
		IntraExchangeOnly:   true,
		RequiredCredentials: []string{"registration_number"},
	}
}

// signerRule is a pure-signer event (no filer, no threshold).
func signerRule(evt string) CosignatureRule {
	return CosignatureRule{EventType: evt}
}

// ─── rule helpers ────────────────────────────────────────────────────

func TestCosignatureRule_Helpers(t *testing.T) {
	filed := filedRule("amendment")
	pure := signerRule("decision")
	explicit := CosignatureRule{
		EventType:           "appointment",
		AllowedFilerRoles:   []FilerRole{"operator"},
		RequiredSignerRoles: []string{"approver", "senior_approver"},
		MinSignerCosigners:  2,
	}

	if !filed.PermitsFilerRole("operator") || !filed.PermitsFilerRole("registrar") {
		t.Error("filed rule must permit its listed filer roles")
	}
	if filed.PermitsFilerRole("intruder") {
		t.Error("a role outside AllowedFilerRoles must not be permitted")
	}
	if pure.PermitsFilerRole("operator") {
		t.Error("a pure-signer rule permits no filer role at all")
	}

	if !filed.PermitsSignerRole("approver") || filed.PermitsSignerRole("operator") {
		t.Error("PermitsSignerRole must match RequiredSignerRoles exactly (OR semantics)")
	}

	if !filed.RequiresFiler() || pure.RequiresFiler() {
		t.Error("RequiresFiler ⇔ AllowedFilerRoles non-empty")
	}

	// The three threshold regimes.
	if got := pure.EffectiveMinCosigners(); got != 0 {
		t.Errorf("pure-signer threshold = %d, want 0 (primary signer only)", got)
	}
	if got := filed.EffectiveMinCosigners(); got != 1 {
		t.Errorf("filed default threshold = %d, want 1", got)
	}
	if got := explicit.EffectiveMinCosigners(); got != 2 {
		t.Errorf("explicit threshold = %d, want 2", got)
	}
}

// ─── structural validation ───────────────────────────────────────────

func TestNewInMemoryPolicy_StructuralRejections(t *testing.T) {
	cases := []struct {
		name string
		rule CosignatureRule
		want string // substring of the error
	}{
		{"empty event_type", CosignatureRule{}, "event_type required"},
		{"empty filer token", CosignatureRule{
			EventType:           "evt",
			AllowedFilerRoles:   []FilerRole{""},
			RequiredSignerRoles: []string{"approver"},
		}, "allowed_filer_roles[0] empty"},
		{"filer without signer roles", CosignatureRule{
			EventType:         "evt",
			AllowedFilerRoles: []FilerRole{"operator"},
		}, "no required_signer_roles"},
		{"empty signer role", CosignatureRule{
			EventType:           "evt",
			AllowedFilerRoles:   []FilerRole{"operator"},
			RequiredSignerRoles: []string{""},
		}, "required_signer_roles[0] empty"},
		{"negative threshold", CosignatureRule{
			EventType:          "evt",
			MinSignerCosigners: -1,
		}, "must be >= 0"},
		{"empty credential key", CosignatureRule{
			EventType:           "evt",
			RequiredCredentials: []string{""},
		}, "required_credentials[0] empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewInMemoryPolicy([]CosignatureRule{tc.rule})
			if !errors.Is(err, ErrInvalidRule) {
				t.Fatalf("want ErrInvalidRule, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}
}

func TestNewInMemoryPolicy_DuplicateRejected(t *testing.T) {
	_, err := NewInMemoryPolicy([]CosignatureRule{signerRule("evt"), signerRule("evt")})
	if !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("duplicate event_type must yield ErrDuplicateRule, got %v", err)
	}
}

// ─── scope-at-publish (PRE-13b #181) ─────────────────────────────────

// A GATED event (one carrying RequiredSignerRoles) is the unit the verifying
// walk enforces provenance over; scope-at-publish makes the SCOPE that walk
// must enforce a publish-time obligation. A network therefore cannot freeze a
// bundle that gates an event without declaring which delegation scope
// authorizes the cosigner — the walk always has a scope to check. The
// accessors and ValidateScopeAtPublish are pinned together here:
// RequiresScope ⇔ gated, and a gated rule with no scope is unpublishable.
func TestValidateScopeAtPublish(t *testing.T) {
	// Accessors: RequiresScope ⇔ RequiredSignerRoles non-empty.
	gated := filedRule("amendment") // RequiredSignerRoles=["approver"], no scope set
	nongated := signerRule("notice")
	if !gated.RequiresScope() {
		t.Error("a rule with RequiredSignerRoles is gated and must report RequiresScope")
	}
	if nongated.RequiresScope() {
		t.Error("a rule with no RequiredSignerRoles is not gated and requires no scope")
	}

	// 1. Gated WITHOUT scope → ErrGatedEventNoScope (the publish refusal).
	if err := ValidateScopeAtPublish([]CosignatureRule{gated}); !errors.Is(err, ErrGatedEventNoScope) {
		t.Fatalf("a gated event with no required_scope must be unpublishable, got %v", err)
	}

	// 2. Gated WITH scope → admitted; the accessor surfaces it for the walk.
	scoped := gated
	scoped.RequiredScope = []string{"court.amendment"}
	if err := ValidateScopeAtPublish([]CosignatureRule{scoped}); err != nil {
		t.Fatalf("a gated event that declares its scope must publish: %v", err)
	}
	if got := scoped.RequiredScopes(); len(got) != 1 || got[0] != "court.amendment" {
		t.Errorf("RequiredScopes must surface the declared scope for the walk, got %v", got)
	}

	// 3. Non-gated WITHOUT scope → admitted (scope is meaningless with no gate).
	if err := ValidateScopeAtPublish([]CosignatureRule{nongated}); err != nil {
		t.Fatalf("a non-gated event may omit scope: %v", err)
	}

	// 4. Gated with an EMPTY scope token → ErrInvalidRule (malformed, not absent).
	empty := gated
	empty.RequiredScope = []string{""}
	if err := ValidateScopeAtPublish([]CosignatureRule{empty}); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("an empty scope token is malformed and must reject with ErrInvalidRule, got %v", err)
	}

	// 5. Over a SET, the offending gated event is named in the rejection.
	err := ValidateScopeAtPublish([]CosignatureRule{nongated, gated})
	if !errors.Is(err, ErrGatedEventNoScope) || !strings.Contains(err.Error(), "amendment") {
		t.Fatalf("the offending gated event must be named in the rejection, got %v", err)
	}
}

// ─── the closed-set option: content injected, never hardcoded ────────

func TestWithKnownFilerRoles_ClosesTheSet(t *testing.T) {
	rules := []CosignatureRule{filedRule("amendment")}

	// Open set (no option): any non-empty token validates.
	if _, err := NewInMemoryPolicy(rules); err != nil {
		t.Fatalf("open set must accept structural rules: %v", err)
	}

	// Closed set covering the fixture's roles: accepted.
	if _, err := NewInMemoryPolicy(rules,
		WithKnownFilerRoles("operator", "registrar")); err != nil {
		t.Fatalf("closed set covering the rules must accept: %v", err)
	}

	// Closed set missing one: rejected, naming the stray token.
	_, err := NewInMemoryPolicy(rules, WithKnownFilerRoles("operator"))
	if !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("out-of-set filer role must reject with ErrInvalidRule, got %v", err)
	}
	if !strings.Contains(err.Error(), `"registrar"`) {
		t.Errorf("rejection should name the offending token: %v", err)
	}
}

func TestOptions_RetainedAcrossMutations(t *testing.T) {
	p, err := NewInMemoryPolicy(nil, WithKnownFilerRoles("operator"))
	if err != nil {
		t.Fatal(err)
	}
	bad := CosignatureRule{
		EventType:           "evt",
		AllowedFilerRoles:   []FilerRole{"stranger"},
		RequiredSignerRoles: []string{"approver"},
	}
	if err := p.Add(bad); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("Add must validate under the constructed closed set: %v", err)
	}
	if err := p.Replace([]CosignatureRule{bad}); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("Replace must validate under the constructed closed set: %v", err)
	}
}

// ─── table semantics ─────────────────────────────────────────────────

func TestLookup_NotFoundSentinel(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{signerRule("known")})
	if _, err := p.Lookup("unknown"); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("closed-set lookup of an unknown event must be ErrRuleNotFound, got %v", err)
	}
}

func TestList_DeterministicOrder(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{
		signerRule("c"), signerRule("a"), signerRule("b"),
	})
	got := p.List()
	want := []string{"a", "b", "c"}
	for i, r := range got {
		if r.EventType != want[i] {
			t.Fatalf("List order: got[%d]=%s, want %s", i, r.EventType, want[i])
		}
	}
}

func TestLookupAndList_ReturnCopies(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{filedRule("amendment")})

	got, err := p.Lookup("amendment")
	if err != nil {
		t.Fatal(err)
	}
	got.EventType = "vandalized"
	got.RequiredSignerRoles[0] = "vandal" // shared backing array is acceptable to share? prove the row itself is safe

	again, err := p.Lookup("amendment")
	if err != nil {
		t.Fatalf("the table row must be unaffected by mutating a returned copy: %v", err)
	}
	if again.EventType != "amendment" {
		t.Errorf("Lookup returned a live pointer into the table (EventType=%q)", again.EventType)
	}

	p.List()[0].EventType = "vandalized"
	if _, err := p.Lookup("amendment"); err != nil {
		t.Error("List must return copies; mutating them corrupted the table")
	}
}

func TestAddAndReplace(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{signerRule("a")})
	if err := p.Add(signerRule("b")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := p.Add(signerRule("a")); !errors.Is(err, ErrDuplicateRule) {
		t.Fatalf("Add duplicate: want ErrDuplicateRule, got %v", err)
	}
	if err := p.Replace([]CosignatureRule{signerRule("z")}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := p.Lookup("a"); !errors.Is(err, ErrRuleNotFound) {
		t.Error("Replace must drop prior rules atomically")
	}
	if _, err := p.Lookup("z"); err != nil {
		t.Error("Replace must install the new rules")
	}
}

func TestConcurrentReadersAndReplace(t *testing.T) {
	p, _ := NewInMemoryPolicy([]CosignatureRule{signerRule("a"), signerRule("b")})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = p.Lookup("a")
				_ = p.List()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			_ = p.Replace([]CosignatureRule{signerRule("a"), signerRule("b")})
		}
	}()
	wg.Wait()
}

// ─── the loader trio ─────────────────────────────────────────────────

const goodPolicyJSON = `{
  "rules": [
    {
      "event_type": "amendment",
      "allowed_filer_roles": ["operator"],
      "required_signer_roles": ["approver"],
      "min_signer_cosigners": 1,
      "intra_exchange_only": true,
      "required_credentials": ["registration_number"]
    },
    {"event_type": "decision", "intra_exchange_only": true}
  ]
}`

func TestParseJSON_HappyPath(t *testing.T) {
	p, err := ParseJSON([]byte(goodPolicyJSON))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	r, err := p.Lookup("amendment")
	if err != nil {
		t.Fatal(err)
	}
	if !r.IntraExchangeOnly || r.EffectiveMinCosigners() != 1 || !r.PermitsFilerRole("operator") {
		t.Errorf("parsed rule lost fields: %+v", r)
	}
}

func TestParseJSON_Rejections(t *testing.T) {
	if _, err := ParseJSON([]byte("{not json")); err == nil {
		t.Error("malformed JSON must error")
	}
	if _, err := ParseJSON([]byte(`{"rules":[{"event_type":""}]}`)); !errors.Is(err, ErrInvalidRule) {
		t.Error("invalid rule must surface ErrInvalidRule")
	}
	dup := `{"rules":[{"event_type":"e"},{"event_type":"e"}]}`
	if _, err := ParseJSON([]byte(dup)); !errors.Is(err, ErrDuplicateRule) {
		t.Error("duplicate rules must surface ErrDuplicateRule")
	}
	// The closed-set option applies to parsing too.
	if _, err := ParseJSON([]byte(goodPolicyJSON), WithKnownFilerRoles("registrar")); !errors.Is(err, ErrInvalidRule) {
		t.Error("ParseJSON must honor WithKnownFilerRoles")
	}
}

func TestLoadFile_AndMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(goodPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if _, err := LoadFile(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("missing file must error")
	}
}

func TestReloadFromFile_FailedReloadKeepsPriorRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(goodPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// A bad rewrite must refuse — and leave every prior rule in effect.
	if err := os.WriteFile(path, []byte(`{"rules":[{"event_type":""}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.ReloadFromFile(path); !errors.Is(err, ErrInvalidRule) {
		t.Fatalf("bad reload must surface ErrInvalidRule, got %v", err)
	}
	if _, err := p.Lookup("amendment"); err != nil {
		t.Error("failed reload must keep the previous policy fully in effect")
	}

	// A good rewrite replaces atomically.
	good := `{"rules":[{"event_type":"fresh"}]}`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.ReloadFromFile(path); err != nil {
		t.Fatalf("good reload: %v", err)
	}
	if _, err := p.Lookup("amendment"); !errors.Is(err, ErrRuleNotFound) {
		t.Error("successful reload must drop prior rules")
	}
	if _, err := p.Lookup("fresh"); err != nil {
		t.Error("successful reload must install new rules")
	}
}
