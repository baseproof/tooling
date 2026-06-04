/*
FILE PATH: libs/keystore/signer/signer_test.go

DESCRIPTION:

	Validation contracts for the keys/v1.Signer adapter. Drives the
	in-memory keystore (deterministic, no external deps) and pins:

	  - New requires non-nil keystore + non-empty DID.
	  - New errors when the keystore has no key for the DID.
	  - Address derived once at construction matches Address derived
	    directly from the keystore's public key via
	    signatures.AddressFromPubkey.
	  - Sign returns 65-byte Ethereum-format (r || s || v) and
	    RecoverSecp256k1 over (digest, sig) returns the same public
	    key the keystore generated.
	  - DID round-trips.
*/
package signer

import (
	"bytes"
	"testing"

	sdksigs "github.com/baseproof/baseproof/crypto/signatures"

	"github.com/baseproof/tooling/libs/keystore"
)

const testDID = "did:web:state:tn:davidson:judge-mcclendon"

func newAdapter(t *testing.T) (*Adapter, *keystore.MemoryKeyStore, []byte) {
	t.Helper()
	ks := keystore.NewMemoryKeyStore()
	info, err := ks.Generate(testDID, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	a, err := New(ks, testDID)
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}
	return a, ks, info.PublicKey
}

func TestNew_RequiresKeystore(t *testing.T) {
	if _, err := New(nil, testDID); err == nil {
		t.Error("expected error for nil keystore")
	}
}

func TestNew_RequiresDID(t *testing.T) {
	if _, err := New(keystore.NewMemoryKeyStore(), ""); err == nil {
		t.Error("expected error for empty DID")
	}
}

func TestNew_UnknownDID_Errors(t *testing.T) {
	if _, err := New(keystore.NewMemoryKeyStore(), "did:web:no-key"); err == nil {
		t.Error("expected error for unknown DID")
	}
}

func TestAdapter_AddressMatchesPubkeyDerivation(t *testing.T) {
	a, _, pub := newAdapter(t)
	want, err := sdksigs.AddressFromPubkey(pub)
	if err != nil {
		t.Fatalf("AddressFromPubkey: %v", err)
	}
	if got := a.Address(); got != want {
		t.Errorf("Address = %x, want %x", got, want)
	}
}

func TestAdapter_DIDRoundTrips(t *testing.T) {
	a, _, _ := newAdapter(t)
	if got := a.DID(); got != testDID {
		t.Errorf("DID = %q, want %q", got, testDID)
	}
}

func TestAdapter_Sign_EthereumFormat_RecoversPubkey(t *testing.T) {
	a, _, pub := newAdapter(t)
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(0xa0 + i)
	}
	sig, err := a.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != sdksigs.EthereumSignatureLen {
		t.Fatalf("sig len = %d, want %d", len(sig), sdksigs.EthereumSignatureLen)
	}
	// v MUST be 27 or 28 (the Ethereum convention; SCW
	// isValidSignature accepts these directly).
	if v := sig[64]; v != 27 && v != 28 {
		t.Errorf("v = %d, want 27 or 28", v)
	}
	recovered, err := sdksigs.RecoverSecp256k1(digest, sig)
	if err != nil {
		t.Fatalf("RecoverSecp256k1: %v", err)
	}
	if !bytes.Equal(recovered, pub) {
		t.Errorf("recovered pubkey != generated pubkey")
	}
}

func TestAdapter_NilSafety(t *testing.T) {
	var a *Adapter
	if got := a.Address(); got != ([20]byte{}) {
		t.Errorf("nil.Address = %x, want zero", got)
	}
	if got := a.DID(); got != "" {
		t.Errorf("nil.DID = %q, want empty", got)
	}
	if _, err := a.Sign([32]byte{}); err == nil {
		t.Error("nil.Sign should error")
	}
}

func TestAdapter_SignAfterDestroy_Errors(t *testing.T) {
	a, ks, _ := newAdapter(t)
	if err := ks.Destroy(testDID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := a.Sign([32]byte{1}); err == nil {
		t.Error("Sign after Destroy should error")
	}
}
