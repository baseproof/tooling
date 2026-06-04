/*
FILE PATH: exchange/keystore/keystore_test.go

Tests for the secp256k1-only MemoryKeyStore: key generation + the two
signature shapes (Sign = 65-byte recoverable SignCompact for SCW/ecrecover;
SignEntry = 64-byte R||S that the SDK's VerifyEntry accepts for log
entries), staged old-key-signs rotation, and the escrow export.
*/
package keystore

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/baseproof/baseproof/crypto/signatures"
)

const testDID = "did:web:clerk.example.gov"

func nonZeroDigest() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(i + 1)
	}
	return d
}

func TestMemoryKeyStore_Generate(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, err := ks.Generate(testDID, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if info.Curve != CurveSecp256k1 {
		t.Errorf("Curve = %q, want secp256k1", info.Curve)
	}
	if len(info.PublicKey) != 65 || info.PublicKey[0] != 0x04 {
		t.Errorf("PublicKey shape: len=%d prefix=%#x, want 65/0x04", len(info.PublicKey), info.PublicKey[0])
	}
	if info.DID != testDID || info.KeyID == "" || info.Purpose != "signing" {
		t.Errorf("KeyInfo fields wrong: %+v", info)
	}
}

func TestMemoryKeyStore_Generate_RejectsEmptyDID(t *testing.T) {
	if _, err := NewMemoryKeyStore().Generate("", "signing"); err == nil {
		t.Fatal("empty DID must error")
	}
}

func TestMemoryKeyStore_PublicKey_CopyAndUnknown(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, _ := ks.Generate(testDID, "signing")
	got, err := ks.PublicKey(testDID)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !bytes.Equal(got, info.PublicKey) {
		t.Error("PublicKey != Generate's key")
	}
	got[0] = 0xFF // mutate the returned copy
	again, _ := ks.PublicKey(testDID)
	if again[0] != 0x04 {
		t.Error("PublicKey must return a fresh copy (stored key was mutated)")
	}
	if _, err := ks.PublicKey("did:web:nobody"); err == nil {
		t.Error("unknown DID must error")
	}
}

// Sign is the 65-byte recoverable SignCompact (SCW/ecrecover); the
// recovered key must equal the bound key, and RFC 6979 makes it
// deterministic.
func TestMemoryKeyStore_Sign_Recoverable(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, _ := ks.Generate(testDID, "signing")
	digest := nonZeroDigest()

	sig, err := ks.Sign(testDID, digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("Sign len = %d, want 65 (v||R||S)", len(sig))
	}
	recovered, _, err := ecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if !bytes.Equal(recovered.SerializeUncompressed(), info.PublicKey) {
		t.Error("recovered pubkey != bound pubkey")
	}
	sig2, _ := ks.Sign(testDID, digest)
	if !bytes.Equal(sig, sig2) {
		t.Error("RFC 6979 deterministic sign should be byte-identical")
	}
}

// SignEntry is the 64-byte SigAlgoECDSA shape; it MUST verify under the
// SDK's signatures.VerifyEntry (the same primitive the ledger uses).
func TestMemoryKeyStore_SignEntry_VerifiesUnderSDK(t *testing.T) {
	ks := NewMemoryKeyStore()
	info, _ := ks.Generate(testDID, "signing")
	digest := sha256.Sum256([]byte("canonical entry signing payload"))

	sig, err := ks.SignEntry(testDID, digest)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("SignEntry len = %d, want 64 (R||S)", len(sig))
	}
	pub, err := signatures.ParsePubKey(info.PublicKey)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	if err := signatures.VerifyEntry(digest, sig, pub); err != nil {
		t.Fatalf("VerifyEntry rejected a SignEntry signature: %v", err)
	}
}

func TestMemoryKeyStore_Sign_UnknownDID(t *testing.T) {
	ks := NewMemoryKeyStore()
	if _, err := ks.Sign("did:web:nobody", nonZeroDigest()); err == nil {
		t.Error("Sign unknown DID must error")
	}
	if _, err := ks.SignEntry("did:web:nobody", nonZeroDigest()); err == nil {
		t.Error("SignEntry unknown DID must error")
	}
}

// StageNextKey keeps the retiring key active + signable until
// CommitRotation promotes the new key — the old-key-signs chain of
// custody RotationHistorySource verifies.
func TestMemoryKeyStore_StagedRotation(t *testing.T) {
	ks := NewMemoryKeyStore()
	if _, err := ks.Generate(testDID, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	oldPub, _ := ks.PublicKey(testDID)

	staged, err := ks.StageNextKey(testDID, 1)
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if bytes.Equal(staged.PublicKey, oldPub) {
		t.Fatal("staged key must differ from current")
	}

	// Pre-commit: old key still active + signs.
	cur, _ := ks.PublicKey(testDID)
	if !bytes.Equal(cur, oldPub) {
		t.Error("current key changed before CommitRotation")
	}
	digest := sha256.Sum256([]byte("rotation entry naming the new key"))
	sig, _ := ks.SignEntry(testDID, digest)
	oldPK, _ := signatures.ParsePubKey(oldPub)
	if err := signatures.VerifyEntry(digest, sig, oldPK); err != nil {
		t.Fatalf("pre-commit signature must verify under the OLD key: %v", err)
	}

	// Post-commit: staged key is active.
	if _, err := ks.CommitRotation(testDID); err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	cur2, _ := ks.PublicKey(testDID)
	if !bytes.Equal(cur2, staged.PublicKey) {
		t.Error("staged key not promoted after CommitRotation")
	}
	sig2, _ := ks.SignEntry(testDID, digest)
	newPK, _ := signatures.ParsePubKey(staged.PublicKey)
	if err := signatures.VerifyEntry(digest, sig2, newPK); err != nil {
		t.Fatalf("post-commit signature must verify under the NEW key: %v", err)
	}
}

func TestMemoryKeyStore_CommitRotation_NoPending(t *testing.T) {
	ks := NewMemoryKeyStore()
	ks.Generate(testDID, "signing")
	if _, err := ks.CommitRotation(testDID); err == nil {
		t.Fatal("CommitRotation with no pending must error")
	}
}

func TestMemoryKeyStore_ImportSecp256k1_Deterministic(t *testing.T) {
	ks := NewMemoryKeyStore()
	priv, _ := secp256k1.GeneratePrivateKey()
	info, err := ks.ImportSecp256k1(testDID, "signing", priv)
	if err != nil {
		t.Fatalf("ImportSecp256k1: %v", err)
	}
	if !bytes.Equal(info.PublicKey, priv.PubKey().SerializeUncompressed()) {
		t.Error("imported pubkey mismatch")
	}
	if _, err := ks.ImportSecp256k1(testDID, "signing", nil); err == nil {
		t.Error("nil key must error")
	}
}

func TestMemoryKeyStore_List_Destroy_Export(t *testing.T) {
	ks := NewMemoryKeyStore()
	ks.Generate("did:web:a", "signing")
	ks.Generate("did:web:b", "signing")
	if got := len(ks.List()); got != 2 {
		t.Errorf("List = %d, want 2", got)
	}

	priv, err := ks.ExportForEscrow("did:web:a")
	if err != nil {
		t.Fatalf("ExportForEscrow: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("escrow scalar len = %d, want 32", len(priv))
	}

	if err := ks.Destroy("did:web:a"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := ks.Sign("did:web:a", nonZeroDigest()); err == nil {
		t.Error("Sign after Destroy must error")
	}
	if _, err := ks.ExportForEscrow("did:web:nobody"); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Errorf("ExportForEscrow unknown DID: got %v", err)
	}
}

func TestMemoryKeyStore_ImplementsInterface(t *testing.T) {
	var _ KeyStore = (*MemoryKeyStore)(nil)
}
