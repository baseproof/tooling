/*
FILE PATH: libs/policy/role_test.go

DESCRIPTION:

	Pins the Actor enum's wire stability (ints AND strings are parsed
	by log consumers — neither may ever drift) and ValidateRole's
	structural contract: catalogs hold key-holding signer roles with
	bounded delegation durations and DefaultScope ⊆ AllowedScope.
*/
package policy

import (
	"strings"
	"testing"
	"time"
)

func TestActor_WireStability(t *testing.T) {
	// Both the ints and the strings are serialized contracts.
	cases := []struct {
		a    Actor
		i    int
		s    string
		ok   bool
		keys bool
	}{
		{ActorUnspecified, 0, "actor_unspecified", false, false},
		{ActorSigner, 1, "actor_signer", true, true},
		{ActorFiler, 2, "actor_filer", true, false},
		{ActorParty, 3, "actor_party", true, false},
		{Actor(9), 9, "actor_unknown_9", false, false},
	}
	for _, c := range cases {
		if int(c.a) != c.i {
			t.Errorf("Actor %s int drifted: %d != %d", c.s, int(c.a), c.i)
		}
		if c.a.String() != c.s {
			t.Errorf("Actor string drifted: %q != %q", c.a.String(), c.s)
		}
		if c.a.IsValid() != c.ok {
			t.Errorf("Actor %s IsValid = %v, want %v", c.s, c.a.IsValid(), c.ok)
		}
		if c.a.HoldsKeys() != c.keys {
			t.Errorf("Actor %s HoldsKeys = %v, want %v", c.s, c.a.HoldsKeys(), c.keys)
		}
	}
	if err := ValidateActor(ActorSigner); err != nil {
		t.Errorf("ValidateActor(signer): %v", err)
	}
	if err := ValidateActor(ActorUnspecified); err == nil {
		t.Error("the zero Actor must fail validation loudly")
	}
}

func validRole() Role {
	return Role{
		Name:            "approver",
		Actor:           ActorSigner,
		MaxDuration:     30 * 24 * time.Hour,
		DefaultDuration: 7 * 24 * time.Hour,
		AllowedScope:    []string{"approve:record", "invite:operator"},
		DefaultScope:    []string{"approve:record"},
	}
}

func TestValidateRole(t *testing.T) {
	if err := ValidateRole(validRole()); err != nil {
		t.Fatalf("the reference role must validate: %v", err)
	}

	mutate := func(f func(*Role)) Role {
		r := validRole()
		f(&r)
		return r
	}
	cases := []struct {
		name string
		r    Role
		want string
	}{
		{"empty name", mutate(func(r *Role) { r.Name = "" }), "name required"},
		{"zero actor", mutate(func(r *Role) { r.Actor = ActorUnspecified }), "actor must be"},
		{"non-signer actor", mutate(func(r *Role) { r.Actor = ActorFiler }), "key-holding"},
		{"zero max duration", mutate(func(r *Role) { r.MaxDuration = 0 }), "max_duration"},
		{"default exceeds max", mutate(func(r *Role) { r.DefaultDuration = r.MaxDuration + time.Hour }), "default_duration"},
		{"zero default duration", mutate(func(r *Role) { r.DefaultDuration = 0 }), "default_duration"},
		{"empty allowed scope", mutate(func(r *Role) { r.AllowedScope = nil }), "allowed_scope required"},
		{"empty default scope", mutate(func(r *Role) { r.DefaultScope = nil }), "default_scope required"},
		{"default outside allowed", mutate(func(r *Role) { r.DefaultScope = []string{"rogue:token"} }), "not in allowed_scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRole(tc.r)
			if err == nil {
				t.Fatal("must reject")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}
}
