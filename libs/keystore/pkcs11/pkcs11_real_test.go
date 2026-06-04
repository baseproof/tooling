//go:build pkcs11

/*
FILE PATH: libs/keystore/pkcs11/pkcs11_real_test.go

DESCRIPTION:

	Real-token PKCS#11 conformance test. Built only with `-tags pkcs11`
	AND when SOFTHSM_LIB + SOFTHSM_PIN are present in the environment;
	otherwise the test skips. Run locally with:

	  export SOFTHSM2_CONF=$PWD/softhsm.conf
	  softhsm2-util --init-token --slot 0 --label test --pin 1234 --so-pin 1234
	  SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so SOFTHSM_PIN=1234 \
	    SOFTHSM_SLOT=$(softhsm2-util --show-slots | awk '/^Slot/{slot=$2} /Initialized:.*yes/{print slot; exit}') \
	    go test -tags pkcs11 ./api/exchange/keystore/pkcs11/...

	The test exercises the same RunSecp256k1Conformance suite the
	Vault and Memory backends pass, so wire shapes are guaranteed
	interchangeable across all three production backends.
*/
package pkcs11

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/baseproof/tooling/libs/keystore"
)

func TestPKCS11_RealToken_Conformance(t *testing.T) {
	lib := os.Getenv("SOFTHSM_LIB")
	pin := os.Getenv("SOFTHSM_PIN")
	if lib == "" || pin == "" {
		t.Skip("SOFTHSM_LIB and SOFTHSM_PIN must both be set; run against a provisioned SoftHSMv2 token")
	}
	slot := uint(0)
	if s := os.Getenv("SOFTHSM_SLOT"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("SOFTHSM_SLOT parse: %v", err)
		}
		slot = uint(v)
	}
	ks, err := New(Config{LibraryPath: lib, SlotID: slot, PIN: pin})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ks.Close()

	keystore.RunSecp256k1Conformance(t, ks)
}

func TestPKCS11_New_RequiresLibrary(t *testing.T) {
	if _, err := New(Config{PIN: "x"}); err == nil {
		t.Error("expected error for missing library path")
	}
}

func TestPKCS11_New_RequiresPIN(t *testing.T) {
	if _, err := New(Config{LibraryPath: "/lib"}); err == nil {
		t.Error("expected error for missing PIN")
	}
}

func TestPKCS11_LoadPINFile_Missing(t *testing.T) {
	if _, err := LoadPINFile("/no/such/file/__"); err == nil {
		t.Error("expected error for missing PIN file")
	}
}

func TestPKCS11_ExportForEscrow_Refuses(t *testing.T) {
	ks := &KeyStore{}
	if _, err := ks.ExportForEscrow("did"); err == nil {
		t.Error("expected ExportForEscrow to refuse")
	}
}

func TestPKCS11_LeftPad32(t *testing.T) {
	if got := leftPad32([]byte{1, 2, 3}); len(got) != 32 || got[29] != 1 {
		t.Errorf("leftPad32 wrong: %x", got)
	}
}

// TestPKCS11_LabelForTier_Encoding pins the label format. Stable
// because operators may grep for these on the token (e.g.
// `softhsm2-util --show-slots --pin ... | grep baseproof:`).
func TestPKCS11_LabelForTier_Encoding(t *testing.T) {
	got := string(labelForTier("did:web:test:judge", 7))
	want := "baseproof:did:web:test:judge#tier-7"
	if got != want {
		t.Errorf("labelForTier = %q, want %q", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Real-token staged rotation tests (skipped without SoftHSM env).
//
// These pin the SDK's old-key-signs chain-of-custody invariant
// against a real PKCS#11 token: after StageNextKey the Sign path
// must continue to produce signatures verifying under the OLD
// public key, and only CommitRotation flips the active tier.
// ─────────────────────────────────────────────────────────────────────

func TestPKCS11_StagedRotation_OldKeySigns(t *testing.T) {
	ks := openRealOrSkip(t)
	defer cleanRealKey(t, ks, "did:web:test:rotation-old")
	defer ks.Close()

	const did = "did:web:test:rotation-old"
	oldInfo, err := ks.Generate(did, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	oldPub := append([]byte(nil), oldInfo.PublicKey...)

	pending, err := ks.StageNextKey(did, 2)
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if pending.RotationTier != 2 {
		t.Errorf("RotationTier = %d, want 2", pending.RotationTier)
	}
	if string(pending.PublicKey) == string(oldPub) {
		t.Error("pending key must differ from old key")
	}

	// PublicKey during the staged window returns the OLD key.
	got, err := ks.PublicKey(did)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if string(got) != string(oldPub) {
		t.Error("staged-window PublicKey != OLD key")
	}

	// Sign during the staged window must recover the OLD pubkey.
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sig, err := ks.Sign(did, digest)
	if err != nil {
		t.Fatalf("Sign during stage: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	if err := recoverPubKeyEquals(sig, digest[:], oldPub); err != nil {
		t.Error("staged-window signature did not recover OLD pubkey: ", err)
	}
}

func TestPKCS11_StagedRotation_CommitPromotes(t *testing.T) {
	ks := openRealOrSkip(t)
	defer cleanRealKey(t, ks, "did:web:test:rotation-commit")
	defer ks.Close()

	const did = "did:web:test:rotation-commit"
	if _, err := ks.Generate(did, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pending, err := ks.StageNextKey(did, 2)
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	committed, err := ks.CommitRotation(did)
	if err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	if string(committed.PublicKey) != string(pending.PublicKey) {
		t.Error("committed PublicKey != pending PublicKey")
	}

	// Post-commit Sign recovers the NEW pubkey.
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i + 0x55)
	}
	sig, err := ks.Sign(did, digest)
	if err != nil {
		t.Fatalf("Sign post-commit: %v", err)
	}
	if err := recoverPubKeyEquals(sig, digest[:], pending.PublicKey); err != nil {
		t.Error("post-commit signature did not recover NEW pubkey: ", err)
	}
}

func TestPKCS11_StagedRotation_DoubleStage(t *testing.T) {
	ks := openRealOrSkip(t)
	defer cleanRealKey(t, ks, "did:web:test:rotation-dbl")
	defer ks.Close()

	const did = "did:web:test:rotation-dbl"
	if _, err := ks.Generate(did, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ks.StageNextKey(did, 2); err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if _, err := ks.StageNextKey(did, 3); err == nil {
		t.Error("expected second StageNextKey to fail before CommitRotation")
	}
}

func TestPKCS11_StagedRotation_TierMustAdvance(t *testing.T) {
	ks := openRealOrSkip(t)
	defer cleanRealKey(t, ks, "did:web:test:rotation-tier")
	defer ks.Close()

	const did = "did:web:test:rotation-tier"
	if _, err := ks.Generate(did, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// tier <= currentTier is rejected.
	if _, err := ks.StageNextKey(did, 1); err == nil {
		t.Error("expected StageNextKey to reject tier 1 (== currentTier)")
	}
}

func TestPKCS11_StagedRotation_NoCurrent(t *testing.T) {
	ks := openRealOrSkip(t)
	defer ks.Close()
	if _, err := ks.StageNextKey("did:web:never:generated", 2); err == nil {
		t.Error("expected error staging with no current key")
	}
}

func TestPKCS11_CommitRotation_NoPending(t *testing.T) {
	ks := openRealOrSkip(t)
	defer cleanRealKey(t, ks, "did:web:test:rotation-nopending")
	defer ks.Close()

	const did = "did:web:test:rotation-nopending"
	if _, err := ks.Generate(did, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ks.CommitRotation(did); err == nil {
		t.Error("expected error committing with no pending rotation")
	}
}

func TestPKCS11_StagedRotation_DestroyClearsBothTiers(t *testing.T) {
	ks := openRealOrSkip(t)
	defer ks.Close()

	const did = "did:web:test:rotation-destroy"
	if _, err := ks.Generate(did, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ks.StageNextKey(did, 2); err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if err := ks.Destroy(did); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// Sign + PublicKey should now error (both tiers gone).
	if _, err := ks.Sign(did, [32]byte{1}); err == nil {
		t.Error("Sign after Destroy should error")
	}
	ks.mu.RLock()
	_, hasKey := ks.keysSec[did]
	_, hasPending := ks.pendingSec[did]
	_, hasTier := ks.currentTier[did]
	ks.mu.RUnlock()
	if hasKey || hasPending || hasTier {
		t.Errorf("Destroy left state: key=%v pending=%v tier=%v",
			hasKey, hasPending, hasTier)
	}
}

// openRealOrSkip is the shared boilerplate for real-token tests.
// Skips when SOFTHSM_LIB / SOFTHSM_PIN aren't both set.
func openRealOrSkip(t *testing.T) *KeyStore {
	t.Helper()
	lib := os.Getenv("SOFTHSM_LIB")
	pin := os.Getenv("SOFTHSM_PIN")
	if lib == "" || pin == "" {
		t.Skip("SOFTHSM_LIB and SOFTHSM_PIN must both be set")
	}
	slot := uint(0)
	if s := os.Getenv("SOFTHSM_SLOT"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("SOFTHSM_SLOT parse: %v", err)
		}
		slot = uint(v)
	}
	ks, err := New(Config{LibraryPath: lib, SlotID: slot, PIN: pin})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ks
}

// cleanRealKey best-effort destroys a DID's keys + clears in-memory
// state, leaving the token clean between runs even if a test
// aborted before Destroy.
func cleanRealKey(t *testing.T, ks *KeyStore, did string) {
	t.Helper()
	_ = ks.Destroy(did)
}

// recoverPubKeyEquals returns nil iff RecoverCompact on the
// 65-byte SignCompact yields the given uncompressed pubkey. Kept
// inline so the rotation tests can pin the chain-of-custody
// invariant without dragging in the SDK's verify path.
func recoverPubKeyEquals(sig, digest, wantPub []byte) error {
	pub, _, err := decredecdsa.RecoverCompact(sig, digest)
	if err != nil {
		return err
	}
	if got := pub.SerializeUncompressed(); string(got) != string(wantPub) {
		return fmt.Errorf("recovered pubkey mismatch")
	}
	return nil
}
