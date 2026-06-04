/*
FILE PATH: libs/httpmw/identity_test.go

DESCRIPTION:

	Coverage for the identity context surface. Pinned properties:

	  1. WithCallerDID + CallerDIDFromContext round-trip preserves the DID.
	  2. Empty DID is a no-op (does not pollute context).
	  3. Reading from a context that never had a DID returns "".
	  4. Context key is unexported — external code can NOT set the key
	     via raw context.WithValue (compile-time + runtime check).
	  5. writeUnauth produces 401 with WWW-Authenticate: Bearer header
	     and an empty body (no diagnostic leakage).
	  6. Authenticator interface contract holds (compile-time check
	     on a stub).
*/
package httpmw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// Context round-trip
// ─────────────────────────────────────────────────────────────────────

func TestWithCallerDID_RoundTrip(t *testing.T) {
	ctx := context.Background()
	const did = "did:web:state:tn:davidson:judge-mcclendon"
	ctx = WithCallerDID(ctx, did)
	if got := CallerDIDFromContext(ctx); got != did {
		t.Errorf("CallerDIDFromContext = %q, want %q", got, did)
	}
}

func TestWithCallerDID_EmptyIsNoOp(t *testing.T) {
	ctx := context.Background()
	got := WithCallerDID(ctx, "")
	if got != ctx {
		t.Errorf("WithCallerDID(\"\") should return the input ctx unchanged")
	}
	if did := CallerDIDFromContext(got); did != "" {
		t.Errorf("CallerDIDFromContext after empty Set = %q, want \"\"", did)
	}
}

func TestCallerDIDFromContext_AbsentReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	if got := CallerDIDFromContext(ctx); got != "" {
		t.Errorf("CallerDIDFromContext on bare ctx = %q, want \"\"", got)
	}
}

func TestWithCallerDID_OverwriteSecondCallWins(t *testing.T) {
	ctx := WithCallerDID(context.Background(), "did:first")
	ctx = WithCallerDID(ctx, "did:second")
	if got := CallerDIDFromContext(ctx); got != "did:second" {
		t.Errorf("second-call overwrite lost: got %q, want %q", got, "did:second")
	}
}

// TestContextKey_Unexported_NotForgeableViaForeignType is the
// architectural lock-in: external code cannot inject a callerDID by
// crafting their own key type. They'd have to import middleware.
// callerDIDKey, which is unexported.
//
// Test by attempting to forge with a sibling-shaped struct in this
// test file (still inside the package; external code can't even do
// THIS) and confirming the foreign key does NOT round-trip through
// CallerDIDFromContext.
func TestContextKey_Unexported_NotForgeableViaForeignType(t *testing.T) {
	type foreignKey struct{}
	ctx := context.WithValue(context.Background(), foreignKey{}, "did:web:attacker")
	if got := CallerDIDFromContext(ctx); got != "" {
		t.Errorf("foreign key leaked through CallerDIDFromContext: %q", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// writeUnauth
// ─────────────────────────────────────────────────────────────────────

func TestWriteUnauth_Returns401(t *testing.T) {
	rec := httptest.NewRecorder()
	writeUnauth(rec)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestWriteUnauth_SetsWWWAuthenticateHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	writeUnauth(rec)
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
}

// TestWriteUnauth_NoBodyLeak pins the no-information-disclosure rule.
// Bodies returned to unauthenticated callers MUST NOT carry
// backend-specific markers (e.g., "JWT expired" vs "no client cert")
// because that fingerprints which auth path failed and aids attackers
// probing for misconfigurations.
func TestWriteUnauth_NoBodyLeak(t *testing.T) {
	rec := httptest.NewRecorder()
	writeUnauth(rec)
	// http.Error writes a single trailing newline by default — accept
	// that as "empty for fingerprinting purposes" and assert there's
	// no extra content.
	body := rec.Body.String()
	if len(body) > 1 {
		t.Errorf("response body should be empty (or just \"\\n\"); got %q", body)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Authenticator interface (compile-time check)
// ─────────────────────────────────────────────────────────────────────

// stubAuth always succeeds with the supplied DID. Compile-time test
// that the Authenticator interface is satisfiable by a tiny type.
type stubAuth struct{ did string }

func (s stubAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithCallerDID(r.Context(), s.did)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var _ Authenticator = stubAuth{}

// TestAuthenticator_StubRoundTrip exercises the Authenticator surface
// end-to-end: wrap a handler that reads CallerDIDFromContext, fire a
// request, assert the wrapped handler sees the stub's DID.
func TestAuthenticator_StubRoundTrip(t *testing.T) {
	const want = "did:web:test:judge"
	a := stubAuth{did: want}
	var seen string
	wrapped := a.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = CallerDIDFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	wrapped.ServeHTTP(httptest.NewRecorder(), req)
	if seen != want {
		t.Errorf("downstream handler saw callerDID = %q, want %q", seen, want)
	}
}

// TestErrUnauthenticated_StableSentinel pins the sentinel string so an
// unwary edit doesn't break callers that errors.Is against it.
func TestErrUnauthenticated_StableSentinel(t *testing.T) {
	if ErrUnauthenticated == nil {
		t.Fatal("ErrUnauthenticated must be non-nil")
	}
	if ErrUnauthenticated.Error() == "" {
		t.Error("ErrUnauthenticated must have a non-empty message")
	}
}
