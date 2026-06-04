/*
FILE PATH: libs/keystore/conformance.go

DESCRIPTION:

	Cross-backend conformance suite. Every keystore.KeyStore
	implementation (memory, vault, pkcs11) must pass this same suite
	so the wire shapes (65-byte SignCompact, 65-byte uncompressed
	pubkey, recovery byte recovers the same key) are guaranteed
	interchangeable at the call site.

	Caller patterns:

	  // Memory backend:
	  keystore.RunSecp256k1Conformance(t, keystore.NewMemoryKeyStore())

	  // Vault backend (in vault_keystore_test.go's TestMain or
	  // a dedicated test):
	  ks, _ := vault.New(vault.Config{Address: srv.URL, Token: "t",
	      HTTPClient: srv.Client()})
	  keystore.RunSecp256k1Conformance(t, ks)

	  // PKCS#11 backend (real SoftHSM, build-tagged):
	  ks, _ := pkcs11.New(pkcs11.Config{...})
	  keystore.RunSecp256k1Conformance(t, ks)

	This file lives in the parent keystore package so any backend can
	import it from its own test file without a circular dependency on
	a sibling test package.
*/
package keystore

import (
	"bytes"
	"testing"

	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// RunSecp256k1Conformance exercises Generate / SignSecp256k1 /
// PublicKeySecp256k1 / Destroy on the supplied implementation and
// asserts the wire-shape invariants every backend must honor:
//
//  1. Generate returns 65-byte uncompressed (0x04 prefix) public key.
//  2. SignSecp256k1 returns 65 bytes shaped as [v+27 || R || S].
//  3. RecoverCompact on the signature returns the same public key.
//  4. Destroy removes the key (subsequent SignSecp256k1 errors).
func RunSecp256k1Conformance(t *testing.T, ks KeyStore) {
	t.Helper()
	const did = "did:web:test:conformance"

	info, err := ks.Generate(did, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(info.PublicKey) != 65 || info.PublicKey[0] != 0x04 {
		t.Fatalf("PublicKey shape wrong: len=%d prefix=%x",
			len(info.PublicKey), info.PublicKey[0])
	}
	if info.Curve != CurveSecp256k1 {
		t.Errorf("Curve = %q, want secp256k1", info.Curve)
	}

	pub, err := ks.PublicKey(did)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !bytes.Equal(pub, info.PublicKey) {
		t.Errorf("PublicKey != Generate's public key")
	}

	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sig, err := ks.Sign(did, digest)
	if err != nil {
		t.Fatalf("SignSecp256k1: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	if v := sig[0]; v != 27 && v != 28 {
		t.Errorf("recovery byte = %d, want 27 or 28", v)
	}

	recovered, _, err := decredecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if got := recovered.SerializeUncompressed(); !bytes.Equal(got, info.PublicKey) {
		t.Errorf("recovered pubkey != stored pubkey")
	}

	if err := ks.Destroy(did); err != nil {
		t.Errorf("Destroy: %v", err)
	}
	if _, err := ks.Sign(did, digest); err == nil {
		t.Errorf("Sign after Destroy should error")
	}
}
