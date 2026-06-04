/*
FILE PATH: libs/sdkguard/resolver_guard_test.go

T7 unit tests — AssertResolverPopulated + IsResolverPopulated.

Verifies the strict-mode panic gate and the predicate variant.
The function is one of the few that intentionally panics, so the
test discipline is: recover() in every panic-path test, assert
on the panic message substring.

# COVERAGE MATRIX

## StrictMode off (env var unset or unset to false-y)

  - nil resolver               → no panic
  - resolver missing fields    → no panic
  - resolver fully populated   → no panic

## StrictMode on (env var = "true")

  - nil resolver               → panic, message contains "nil"
  - MirrorManifest.LogDID empty → panic, message contains "MirrorManifest.LogDID"
  - LogWitnessSets nil         → panic, message contains "LogWitnessSets"
  - fully populated resolver   → no panic

## IsResolverPopulated (no env dependency)

  - nil receiver               → false
  - MirrorManifest.LogDID empty → false
  - LogWitnessSets nil         → false
  - fully populated            → true
*/
package sdkguard

import (
	"strings"
	"testing"

	"github.com/baseproof/baseproof/log/discover"
)

// fullResolver returns a *discover.DefaultAuthoritativeResolver with
// the minimum fields populated to pass AssertResolverPopulated. The
// rest of the SDK-resolver fields are left at zero — the guard only
// gates on the three required fields.
func fullResolver() *discover.DefaultAuthoritativeResolver {
	return &discover.DefaultAuthoritativeResolver{
		MirrorManifest: discover.MirrorManifest{
			LogDID: "did:baseproof:network:test",
		},
		LogWitnessSets: map[string][][32]byte{},
	}
}

// expectPanicContaining runs fn and asserts it panicked with a
// message containing each of the supplied substrings. Test fails
// if fn does NOT panic, or if the panic message lacks any substring.
func expectPanicContaining(t *testing.T, fn func(), wantSubstrings ...string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected panic; got nil")
			return
		}
		msg, ok := r.(string)
		if !ok {
			// fmt.Sprintf returns string; if AssertResolverPopulated
			// ever switches to a typed value, this catches it.
			t.Errorf("panic value must be string; got %T: %v", r, r)
			return
		}
		for _, want := range wantSubstrings {
			if !strings.Contains(msg, want) {
				t.Errorf("panic message %q must contain %q", msg, want)
			}
		}
	}()
	fn()
}

// expectNoPanic runs fn and asserts it did not panic.
func expectNoPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic: %v", r)
		}
	}()
	fn()
}

// ─────────────────────────────────────────────────────────────
// StrictMode off — everything is a no-op
// ─────────────────────────────────────────────────────────────

func TestAssertResolverPopulated_StrictOff_NilResolver(t *testing.T) {
	// Default: env var unset → StrictMode false.
	t.Setenv(EnvFailOnPlaintext, "")
	expectNoPanic(t, func() {
		AssertResolverPopulated(nil, "test-label")
	})
}

func TestAssertResolverPopulated_StrictOff_BadResolver(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "")
	bad := &discover.DefaultAuthoritativeResolver{} // every field zero
	expectNoPanic(t, func() {
		AssertResolverPopulated(bad, "test-label")
	})
}

func TestAssertResolverPopulated_StrictOff_FullResolver(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "")
	expectNoPanic(t, func() {
		AssertResolverPopulated(fullResolver(), "test-label")
	})
}

// ─────────────────────────────────────────────────────────────
// StrictMode on — panic per missing field
// ─────────────────────────────────────────────────────────────

func TestAssertResolverPopulated_StrictOn_NilResolver(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	expectPanicContaining(t, func() {
		AssertResolverPopulated(nil, "boot-resolver")
	}, "sdkguard", "boot-resolver", "nil")
}

func TestAssertResolverPopulated_StrictOn_EmptyLogDID(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	r := fullResolver()
	r.MirrorManifest.LogDID = ""
	expectPanicContaining(t, func() {
		AssertResolverPopulated(r, "boot-resolver")
	}, "sdkguard", "boot-resolver", "MirrorManifest.LogDID")
}

func TestAssertResolverPopulated_StrictOn_NilLogWitnessSets(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	r := fullResolver()
	r.LogWitnessSets = nil
	expectPanicContaining(t, func() {
		AssertResolverPopulated(r, "boot-resolver")
	}, "sdkguard", "boot-resolver", "LogWitnessSets")
}

func TestAssertResolverPopulated_StrictOn_FullResolverPasses(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	expectNoPanic(t, func() {
		AssertResolverPopulated(fullResolver(), "boot-resolver")
	})
}

// ─────────────────────────────────────────────────────────────
// StrictMode toggle — verify "1", "yes", "true" all enable
// ─────────────────────────────────────────────────────────────

func TestAssertResolverPopulated_StrictModeAcceptedValues(t *testing.T) {
	cases := []string{"true", "1", "yes", "TRUE", "Yes"}
	for _, v := range cases {
		t.Run("env="+v, func(t *testing.T) {
			t.Setenv(EnvFailOnPlaintext, v)
			expectPanicContaining(t, func() {
				AssertResolverPopulated(nil, "test")
			}, "nil")
		})
	}
}

func TestAssertResolverPopulated_StrictModeRejectedValues(t *testing.T) {
	cases := []string{"false", "0", "no", "", "off", "random"}
	for _, v := range cases {
		t.Run("env="+v, func(t *testing.T) {
			t.Setenv(EnvFailOnPlaintext, v)
			expectNoPanic(t, func() {
				AssertResolverPopulated(nil, "test")
			})
		})
	}
}

// ─────────────────────────────────────────────────────────────
// IsResolverPopulated (no env dependency)
// ─────────────────────────────────────────────────────────────

func TestIsResolverPopulated_Nil(t *testing.T) {
	if IsResolverPopulated(nil) {
		t.Error("nil resolver: got true, want false")
	}
}

func TestIsResolverPopulated_EmptyLogDID(t *testing.T) {
	r := fullResolver()
	r.MirrorManifest.LogDID = ""
	if IsResolverPopulated(r) {
		t.Error("empty LogDID: got true, want false")
	}
}

func TestIsResolverPopulated_NilLogWitnessSets(t *testing.T) {
	r := fullResolver()
	r.LogWitnessSets = nil
	if IsResolverPopulated(r) {
		t.Error("nil LogWitnessSets: got true, want false")
	}
}

func TestIsResolverPopulated_Full(t *testing.T) {
	if !IsResolverPopulated(fullResolver()) {
		t.Error("fully populated resolver: got false, want true")
	}
}

// ─────────────────────────────────────────────────────────────
// Panic message format — file:line + label
// ─────────────────────────────────────────────────────────────

// TestAssertResolverPopulated_PanicMessageHasFileLine verifies
// the runtime.Caller(1) reference produces a file:line that
// points at the TEST file, not at the guard's source. This
// ensures operators looking at a CI failure see THEIR
// composition root, not the guard internals.
func TestAssertResolverPopulated_PanicMessageHasFileLine(t *testing.T) {
	t.Setenv(EnvFailOnPlaintext, "true")
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		msg := r.(string)
		// The panic must reference THIS test file (not the
		// resolver_guard.go internals).
		if !strings.Contains(msg, "resolver_guard_test.go") {
			t.Errorf("panic message must include caller file:line; got: %s", msg)
		}
	}()
	AssertResolverPopulated(nil, "label-from-test")
}
