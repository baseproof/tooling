// FILE PATH: libs/prereq/policy_test.go
//
// Tests pinning prerequisites.Policy: closed-set vocabulary,
// per-event rule registration, structural validation, and
// concurrency-safe lookups.
package prereq

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

// ─── PrereqMode ─────────────────────────────────────────────────────

func TestPrereqMode_IsValid(t *testing.T) {
	if PrereqModeUnspecified.IsValid() {
		t.Error("Unspecified must NOT be valid")
	}
	if !PrereqModeHard.IsValid() {
		t.Error("Hard must be valid")
	}
	if !PrereqModeAdvisory.IsValid() {
		t.Error("Advisory must be valid")
	}
	if PrereqMode(99).IsValid() {
		t.Error("undefined enum value must NOT be valid")
	}
}

func TestPrereqMode_String(t *testing.T) {
	for _, tc := range []struct {
		m    PrereqMode
		want string
	}{
		{PrereqModeHard, "hard"},
		{PrereqModeAdvisory, "advisory"},
		{PrereqModeUnspecified, "unspecified"},
		{PrereqMode(99), "unspecified"},
	} {
		if tc.m.String() != tc.want {
			t.Errorf("%v.String() = %q, want %q", tc.m, tc.m.String(), tc.want)
		}
	}
}

// ─── Prereq predicates ─────────────────────────────────────────────

func TestPrereq_IsAncestorRule(t *testing.T) {
	r := &Prereq{RequiredAncestor: []string{"a"}}
	if !r.IsAncestorRule() {
		t.Error("expected ancestor rule")
	}
	if r.IsAuthorityRule() {
		t.Error("must not be authority rule")
	}
	if (*Prereq)(nil).IsAncestorRule() {
		t.Error("nil receiver must be false")
	}
}

func TestPrereq_IsAuthorityRule(t *testing.T) {
	r := &Prereq{RequiredAuthority: "scope"}
	if !r.IsAuthorityRule() {
		t.Error("expected authority rule")
	}
	if r.IsAncestorRule() {
		t.Error("must not be ancestor rule")
	}
	if (*Prereq)(nil).IsAuthorityRule() {
		t.Error("nil receiver must be false")
	}
}

// ─── validateRule ──────────────────────────────────────────────────

func TestValidateRule_HappyAncestor(t *testing.T) {
	r := &Prereq{
		Mode:             PrereqModeHard,
		RequiredAncestor: []string{"record_opened"},
		Reason:           "case lifecycle",
	}
	if err := validateRule(r); err != nil {
		t.Errorf("happy ancestor: %v", err)
	}
}

func TestValidateRule_HappyAuthority(t *testing.T) {
	r := &Prereq{
		Mode:              PrereqModeHard,
		RequiredAuthority: "appointment_authority",
		Reason:            "personnel",
	}
	if err := validateRule(r); err != nil {
		t.Errorf("happy authority: %v", err)
	}
}

func TestValidateRule_RejectsNil(t *testing.T) {
	if err := validateRule(nil); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("nil rule: %v", err)
	}
}

func TestValidateRule_RejectsModeUnspecified(t *testing.T) {
	r := &Prereq{
		RequiredAncestor: []string{"x"},
		Reason:           "y",
	}
	if err := validateRule(r); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("mode unspecified: %v", err)
	}
}

func TestValidateRule_RejectsBothSurfaces(t *testing.T) {
	r := &Prereq{
		Mode:              PrereqModeHard,
		RequiredAncestor:  []string{"x"},
		RequiredAuthority: "y",
		Reason:            "z",
	}
	if err := validateRule(r); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("both surfaces set: %v", err)
	}
}

func TestValidateRule_RejectsNeitherSurface(t *testing.T) {
	r := &Prereq{Mode: PrereqModeHard, Reason: "y"}
	if err := validateRule(r); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("neither surface set: %v", err)
	}
}

func TestValidateRule_RejectsEmptyReason(t *testing.T) {
	r := &Prereq{
		Mode:             PrereqModeHard,
		RequiredAncestor: []string{"x"},
	}
	if err := validateRule(r); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("empty reason: %v", err)
	}
}

// ─── InMemoryPolicy ────────────────────────────────────────────────

func TestInMemoryPolicy_RegisterAndLookup(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	rules := []Prereq{
		{Mode: PrereqModeHard, RequiredAncestor: []string{"a"}, Reason: "r"},
	}
	if err := p.Register("evt", rules); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := p.Lookup("evt")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !reflect.DeepEqual(got, rules) {
		t.Errorf("rules drift: %+v", got)
	}
}

func TestInMemoryPolicy_KnowsEventType(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	if p.KnowsEventType("evt") {
		t.Error("empty policy must not know any event")
	}
	p.Register("evt", []Prereq{})
	if !p.KnowsEventType("evt") {
		t.Error("registered event should be known (even with empty rules)")
	}
}

func TestInMemoryPolicy_LookupUnknown(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	_, err := p.Lookup("nope")
	if !errors.Is(err, ErrUnknownEventType) {
		t.Errorf("expected ErrUnknownEventType, got: %v", err)
	}
}

func TestInMemoryPolicy_RejectsDuplicate(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	p.Register("evt", []Prereq{})
	err := p.Register("evt", []Prereq{})
	if !errors.Is(err, ErrDuplicateEvent) {
		t.Errorf("expected ErrDuplicateEvent, got: %v", err)
	}
}

func TestInMemoryPolicy_RejectsEmptyEventType(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	err := p.Register("", []Prereq{})
	if !errors.Is(err, ErrInvalidRule) {
		t.Errorf("empty event_type: %v", err)
	}
}

func TestInMemoryPolicy_RejectsInvalidRule(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	bad := []Prereq{
		{Mode: PrereqModeHard, Reason: "x"}, // neither surface set
	}
	err := p.Register("evt", bad)
	if !errors.Is(err, ErrInvalidRule) {
		t.Errorf("invalid rule: %v", err)
	}
}

func TestInMemoryPolicy_EventTypesSorted(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	for _, e := range []string{"c", "a", "b"} {
		p.Register(e, []Prereq{})
	}
	got := p.EventTypes()
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EventTypes() = %v, want %v", got, want)
	}
}

func TestInMemoryPolicy_DefensiveCopyOnLookup(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	rules := []Prereq{
		{Mode: PrereqModeHard, RequiredAncestor: []string{"a"}, Reason: "r"},
	}
	p.Register("evt", rules)
	got, _ := p.Lookup("evt")
	got[0].Reason = "MUTATED"
	got2, _ := p.Lookup("evt")
	if got2[0].Reason == "MUTATED" {
		t.Error("Lookup must defensively copy")
	}
}

func TestInMemoryPolicy_DefensiveCopyOnRegister(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	rules := []Prereq{
		{Mode: PrereqModeHard, RequiredAncestor: []string{"a"}, Reason: "r"},
	}
	p.Register("evt", rules)
	rules[0].Reason = "MUTATED"
	got, _ := p.Lookup("evt")
	if got[0].Reason == "MUTATED" {
		t.Error("Register must defensively copy the input slice")
	}
}

// ─── NewInMemoryPolicy bulk ─────────────────────────────────────────

func TestNewInMemoryPolicy_Bulk(t *testing.T) {
	rules := map[string][]Prereq{
		"a": {{Mode: PrereqModeHard, RequiredAncestor: []string{"x"}, Reason: "r"}},
		"b": {},
	}
	p, err := NewInMemoryPolicy(rules)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if !p.KnowsEventType("a") || !p.KnowsEventType("b") {
		t.Error("bulk-registered events not recognized")
	}
}

func TestNewInMemoryPolicy_PropagatesValidationError(t *testing.T) {
	bad := map[string][]Prereq{
		"a": {{Mode: PrereqModeHard, Reason: "r"}}, // neither surface
	}
	_, err := NewInMemoryPolicy(bad)
	if !errors.Is(err, ErrInvalidRule) {
		t.Errorf("expected ErrInvalidRule, got: %v", err)
	}
}

// ─── concurrency ───────────────────────────────────────────────────

func TestInMemoryPolicy_ConcurrentReadsWriters(t *testing.T) {
	p := NewEmptyInMemoryPolicy()
	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			evt := "evt-" + string(rune('a'+i%26))
			_ = p.Register(evt, []Prereq{
				{Mode: PrereqModeHard, RequiredAncestor: []string{"x"}, Reason: "r"},
			})
			_, _ = p.Lookup(evt)
			_ = p.KnowsEventType(evt)
			_ = p.EventTypes()
		}(i)
	}
	wg.Wait()
}
