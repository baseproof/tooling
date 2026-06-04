/*
FILE PATH: libs/identity/identity_test.go

DESCRIPTION:

	Tests for Claims and the sentinel-error contract. The interface
	itself is exercised end-to-end by privy_stub_test.go which drives
	a deterministic in-memory implementation.
*/
package identity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── Claims.Validate ────────────────────────────────────────────────

func makeValidClaims(now time.Time) *Claims {
	return &Claims{
		Subject:       "did:key:zQ3shCLAIMSUBJECT",
		Issuer:        "https://auth.privy.io",
		IssuedAt:      now.Add(-time.Minute),
		NotBefore:     now.Add(-time.Minute),
		ExpiresAt:     now.Add(time.Hour),
		Email:         "judge@example.org",
		EmailVerified: true,
	}
}

func TestClaims_Validate_HappyPath(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)
	if err := c.Validate(now); err != nil {
		t.Fatalf("happy-path: %v", err)
	}
}

func TestClaims_Validate_NilClaims(t *testing.T) {
	var c *Claims
	if err := c.Validate(time.Now()); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil-claims error, got: %v", err)
	}
}

func TestClaims_Validate_MissingSubject(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)
	c.Subject = ""
	if err := c.Validate(now); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("got: %v", err)
	}
}

func TestClaims_Validate_MissingIssuer(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)
	c.Issuer = ""
	if err := c.Validate(now); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("got: %v", err)
	}
}

func TestClaims_Validate_MissingExpiresAt(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)
	c.ExpiresAt = time.Time{}
	if err := c.Validate(now); err == nil || !strings.Contains(err.Error(), "expires_at") {
		t.Fatalf("got: %v", err)
	}
}

func TestClaims_Validate_Expired(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)
	c.ExpiresAt = now.Add(-time.Second)
	err := c.Validate(now)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("error must wrap ErrTokenExpired: %v", err)
	}
}

func TestClaims_Validate_NotYetValid(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)
	c.NotBefore = now.Add(time.Hour)
	err := c.Validate(now)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrTokenNotYetValid) {
		t.Errorf("error must wrap ErrTokenNotYetValid: %v", err)
	}
}

func TestClaims_Validate_ExpiresBeforeIssued(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)
	c.IssuedAt = now.Add(2 * time.Hour) // after exp
	err := c.Validate(now)
	if err == nil || !strings.Contains(err.Error(), "expires_at must be after issued_at") {
		t.Fatalf("got: %v", err)
	}
}

func TestClaims_IsEmailTrusted(t *testing.T) {
	now := time.Now()
	c := makeValidClaims(now)

	if !c.IsEmailTrusted() {
		t.Error("verified email should be trusted")
	}

	c.EmailVerified = false
	if c.IsEmailTrusted() {
		t.Error("unverified email must NOT be trusted")
	}

	c.EmailVerified = true
	c.Email = ""
	if c.IsEmailTrusted() {
		t.Error("missing email must NOT be trusted")
	}

	var nilClaims *Claims
	if nilClaims.IsEmailTrusted() {
		t.Error("nil claims must NOT be trusted")
	}
}

// ─── Sentinel errors ────────────────────────────────────────────────

func TestSentinels_AreDistinct(t *testing.T) {
	all := []error{
		ErrTokenInvalid,
		ErrTokenExpired,
		ErrTokenNotYetValid,
		ErrSignerNotFound,
		ErrSignRejected,
		ErrSignTimeout,
		ErrProviderUnavailable,
	}
	for i, e := range all {
		if e == nil {
			t.Errorf("sentinel %d is nil", i)
		}
		for j, f := range all {
			if i == j {
				continue
			}
			if errors.Is(e, f) {
				t.Errorf("sentinel %d (%v) should not Is sentinel %d (%v)", i, e, j, f)
			}
		}
	}
}
