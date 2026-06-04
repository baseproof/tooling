/*
FILE PATH: libs/keystore/vault/vault_secp256k1_test.go

DESCRIPTION:

	secp256k1 round-trip tests for the Vault Transit keystore. Mock
	Vault server lives in vault_fakeserver_test.go.
*/
package vault

import (
	"testing"

	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/baseproof/tooling/libs/keystore"
)

func TestVault_Secp256k1_GenerateAndPubKey(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	info, err := ks.Generate("did:web:test:judge", "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(info.PublicKey) != 65 || info.PublicKey[0] != 0x04 {
		t.Errorf("PublicKey shape wrong: len=%d prefix=%x", len(info.PublicKey), info.PublicKey[0])
	}
	if info.Curve != keystore.CurveSecp256k1 {
		t.Errorf("Curve = %q, want secp256k1", info.Curve)
	}
}

func TestVault_Secp256k1_SignRoundTripsViaRecovery(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	info, err := ks.Generate("did:web:test:judge", "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sig, err := ks.Sign("did:web:test:judge", digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	pub, _, err := decredecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if recovered := pub.SerializeUncompressed(); string(recovered) != string(info.PublicKey) {
		t.Errorf("recovered pubkey != stored pubkey")
	}
}

func TestVault_Secp256k1_GenerateRequiresDID(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.Generate("", "signing"); err == nil {
		t.Error("expected error for empty DID")
	}
}

// TestVault_PublicKey_CacheMissFallsBackToVault exercises the
// fallback path where keysSec doesn't have the DID — e.g., after a
// process restart that lost the in-memory cache but Vault still
// holds the key. PublicKey must fetch via fetchPublicKey rather
// than error.
func TestVault_PublicKey_CacheMissFallsBackToVault(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	info, err := ks.Generate("did:web:test:judge", "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Simulate process restart: clear the cache without destroying
	// the Vault-side key.
	ks.mu.Lock()
	delete(ks.keysSec, "did:web:test:judge")
	ks.mu.Unlock()

	pub, err := ks.PublicKey("did:web:test:judge")
	if err != nil {
		t.Fatalf("PublicKey after cache clear: %v", err)
	}
	if string(pub) != string(info.PublicKey) {
		t.Error("fallback-fetched PublicKey != original Generate's PublicKey")
	}
}

// TestVault_PublicKey_AbsentDID surfaces the underlying Vault 404
// when no key exists for the DID (neither in cache nor on the
// server).
func TestVault_PublicKey_AbsentDID(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.PublicKey("did:web:never:generated"); err == nil {
		t.Error("expected error for unknown DID")
	}
}

// TestVault_SignEntry_AbsentDID surfaces the Vault 404 — Sign
// returns an error, SignEntry shouldn't synthesize success or panic
// on the strip.
func TestVault_SignEntry_AbsentDID(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.SignEntry("did:web:never:generated", [32]byte{1}); err == nil {
		t.Error("expected error for unknown DID")
	}
}
