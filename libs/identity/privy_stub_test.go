/*
FILE PATH: libs/identity/privy_stub_test.go

DESCRIPTION:

	End-to-end contract tests against StubProvider. These tests
	exercise the IdentityProvider interface as a black box; passing
	them is the precondition for any provider (real Privy, alternate
	IdP) to drop in without code changes elsewhere in JN.
*/
package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─── helpers ────────────────────────────────────────────────────────

func newKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return priv
}

func nonZeroDigest() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(i + 1)
	}
	return d
}

// ─── Health ─────────────────────────────────────────────────────────

func TestStub_Health_Default(t *testing.T) {
	s := NewStubProvider()
	if err := s.Health(context.Background()); err != nil {
		t.Errorf("default health: %v", err)
	}
}

func TestStub_Health_Configured(t *testing.T) {
	s := NewStubProvider()
	want := errors.New("synthetic")
	s.SetHealthErr(want)
	if got := s.Health(context.Background()); got != want {
		t.Errorf("health: got %v want %v", got, want)
	}
}

// ─── VerifyToken ────────────────────────────────────────────────────

func TestStub_VerifyToken_HappyPath(t *testing.T) {
	s := NewStubProvider()
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetNowFn(func() time.Time { return now })

	claims := &Claims{
		Subject:   "did:key:zQ3sh1",
		Issuer:    "https://auth.privy.io",
		ExpiresAt: now.Add(time.Hour),
	}
	s.BindToken("good-token", claims)

	got, err := s.VerifyToken(context.Background(), "good-token")
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.Subject != claims.Subject {
		t.Errorf("subject drift: got %q", got.Subject)
	}
}

func TestStub_VerifyToken_Unknown(t *testing.T) {
	s := NewStubProvider()
	_, err := s.VerifyToken(context.Background(), "nope")
	if err == nil || !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("unknown token must wrap ErrTokenInvalid: %v", err)
	}
}

func TestStub_VerifyToken_Expired(t *testing.T) {
	s := NewStubProvider()
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetNowFn(func() time.Time { return now })

	s.BindToken("expired", &Claims{
		Subject:   "did:key:zQ3shE",
		Issuer:    "i",
		ExpiresAt: now.Add(-time.Second),
	})

	_, err := s.VerifyToken(context.Background(), "expired")
	if err == nil || !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got: %v", err)
	}
}

// ─── PublicKey ──────────────────────────────────────────────────────
// (SignDigest tests live in privy_stub_signing_test.go in the same package.)

func TestStub_PublicKey_HappyPath(t *testing.T) {
	s := NewStubProvider()
	priv := newKey(t)
	did := "did:key:zQ3shPUB"
	s.BindKey(did, priv)

	pub, err := s.PublicKey(context.Background(), did)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if len(pub) != 65 || pub[0] != 0x04 {
		t.Errorf("uncompressed pubkey expected 65 bytes with 0x04 prefix, got len=%d prefix=%#x",
			len(pub), pub[0])
	}
}

func TestStub_PublicKey_Unknown(t *testing.T) {
	s := NewStubProvider()
	_, err := s.PublicKey(context.Background(), "did:key:zQ3shNONE")
	if err == nil || !errors.Is(err, ErrSignerNotFound) {
		t.Errorf("expected ErrSignerNotFound, got: %v", err)
	}
}

// ─── Concurrency smoke test ─────────────────────────────────────────

func TestStub_ConcurrentReadsSafe(t *testing.T) {
	s := NewStubProvider()
	priv := newKey(t)
	did := "did:key:zQ3shCONCUR"
	s.BindKey(did, priv)
	s.BindToken("tok", &Claims{
		Subject:   did,
		Issuer:    "i",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			ctx := context.Background()
			for j := 0; j < 50; j++ {
				_, _ = s.PublicKey(ctx, did)
				_, _ = s.VerifyToken(ctx, "tok")
				_, _ = s.SignDigest(ctx, SignRequest{
					SignerDID: did,
					Digest:    nonZeroDigest(),
					Display:   makeValidDisplay(),
				})
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
