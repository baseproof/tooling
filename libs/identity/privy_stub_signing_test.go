/*
FILE PATH: libs/identity/privy_stub_signing_test.go

DESCRIPTION:

	SignDigest contract tests against StubProvider. Helpers newKey
	and nonZeroDigest are defined in privy_stub_test.go and shared
	across this same package.
*/
package identity

import (
	"context"
	"errors"
	"testing"

	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestStub_SignDigest_HappyPath(t *testing.T) {
	s := NewStubProvider()
	priv := newKey(t)
	did := "did:key:zQ3shSIGNER"
	s.BindKey(did, priv)

	digest := nonZeroDigest()
	resp, err := s.SignDigest(context.Background(), SignRequest{
		SignerDID: did,
		Digest:    digest,
		Display:   makeValidDisplay(),
		Reason:    "Test",
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(resp.Signature) != 65 {
		t.Errorf("compact sig should be 65 bytes, got %d", len(resp.Signature))
	}
	if len(resp.PublicKey) != 65 {
		t.Errorf("uncompressed pubkey should be 65 bytes, got %d", len(resp.PublicKey))
	}
	if resp.Algorithm != "secp256k1" {
		t.Errorf("alg: got %q", resp.Algorithm)
	}
}

func TestStub_SignDigest_VerifiesAgainstPublicKey(t *testing.T) {
	s := NewStubProvider()
	priv := newKey(t)
	did := "did:key:zQ3shVERIFY"
	s.BindKey(did, priv)

	digest := nonZeroDigest()
	resp, err := s.SignDigest(context.Background(), SignRequest{
		SignerDID: did,
		Digest:    digest,
		Display:   makeValidDisplay(),
	})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	// SignCompact returns [recoveryByte || R(32) || S(32)]. Recover
	// the public key from the signature + digest and confirm it
	// matches the bound key — round-trip proves the signature is
	// valid for this digest.
	recovered, _, err := dcrecdsa.RecoverCompact(resp.Signature, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if string(recovered.SerializeUncompressed()) != string(priv.PubKey().SerializeUncompressed()) {
		t.Error("recovered pubkey != bound pubkey")
	}
}

func TestStub_SignDigest_UnknownSigner(t *testing.T) {
	s := NewStubProvider()
	_, err := s.SignDigest(context.Background(), SignRequest{
		SignerDID: "did:key:zQ3shUNKNOWN",
		Digest:    nonZeroDigest(),
		Display:   makeValidDisplay(),
	})
	if err == nil || !errors.Is(err, ErrSignerNotFound) {
		t.Errorf("expected ErrSignerNotFound, got: %v", err)
	}
}

func TestStub_SignDigest_Rejected(t *testing.T) {
	s := NewStubProvider()
	priv := newKey(t)
	did := "did:key:zQ3shREJECT"
	s.BindKey(did, priv)
	s.RejectSigning(did, true)

	_, err := s.SignDigest(context.Background(), SignRequest{
		SignerDID: did,
		Digest:    nonZeroDigest(),
		Display:   makeValidDisplay(),
	})
	if err == nil || !errors.Is(err, ErrSignRejected) {
		t.Errorf("expected ErrSignRejected, got: %v", err)
	}

	// Toggling off restores signing.
	s.RejectSigning(did, false)
	if _, err := s.SignDigest(context.Background(), SignRequest{
		SignerDID: did,
		Digest:    nonZeroDigest(),
		Display:   makeValidDisplay(),
	}); err != nil {
		t.Errorf("after un-rejection: %v", err)
	}
}

func TestStub_SignDigest_Timeout(t *testing.T) {
	s := NewStubProvider()
	priv := newKey(t)
	did := "did:key:zQ3shTIMEOUT"
	s.BindKey(did, priv)
	s.TimeoutSigning(did, true)

	_, err := s.SignDigest(context.Background(), SignRequest{
		SignerDID: did,
		Digest:    nonZeroDigest(),
		Display:   makeValidDisplay(),
	})
	if err == nil || !errors.Is(err, ErrSignTimeout) {
		t.Errorf("expected ErrSignTimeout, got: %v", err)
	}
}

func TestStub_SignDigest_ValidatesRequest(t *testing.T) {
	s := NewStubProvider()
	_, err := s.SignDigest(context.Background(), SignRequest{
		SignerDID: "", // missing
		Digest:    nonZeroDigest(),
		Display:   makeValidDisplay(),
	})
	if err == nil {
		t.Error("expected validation error for missing signer_did")
	}
}
