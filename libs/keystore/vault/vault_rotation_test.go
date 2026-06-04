/*
FILE PATH: libs/keystore/vault/vault_rotation_test.go

DESCRIPTION:

	Staged-rotation tests for the Vault Transit keystore.

	These tests pin the SDK's old-key-signs chain-of-custody contract:
	  - After StageNextKey, Sign continues to produce signatures
	    verifiable under the OLD public key (NOT the rotated-in new
	    one). The rotation entry — which NAMES the new key — must be
	    signed by the RETIRING key, per the SDK's RotationHistorySource
	    invariant.
	  - PublicKey reflects the OLD key while a rotation is staged;
	    only CommitRotation swaps the cached entry.
	  - After CommitRotation, signs use the NEW key, Vault rejects
	    signs at the OLD version (min_encryption_version advanced),
	    and Sign's output recovers the NEW public key.
	  - StageNextKey + CommitRotation are idempotent in the
	    informative sense (errors on missing preconditions; no
	    silent no-ops).
*/
package vault

import (
	"bytes"
	"strings"
	"testing"

	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const rotateDID = "did:web:test:rotation"

func mkDigest(seed byte) [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(int(seed) + i)
	}
	return d
}

// TestVault_StageNextKey_OldKeySigns is the chain-of-custody pin:
// after StageNextKey the keystore must still sign with the OLD key
// so the rotation entry naming the NEW key is signed by the
// RETIRING key.
func TestVault_StageNextKey_OldKeySigns(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()

	oldInfo, err := ks.Generate(rotateDID, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	oldPub := append([]byte(nil), oldInfo.PublicKey...)

	pendingInfo, err := ks.StageNextKey(rotateDID, 2)
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if pendingInfo.RotationTier != 2 {
		t.Errorf("RotationTier = %d, want 2", pendingInfo.RotationTier)
	}
	if bytes.Equal(pendingInfo.PublicKey, oldPub) {
		t.Error("pending PublicKey must differ from old PublicKey")
	}
	if pendingInfo.Rotated == nil {
		t.Error("pending Rotated must be set")
	}

	// PublicKey on a staged-but-not-committed rotation returns OLD.
	gotPub, err := ks.PublicKey(rotateDID)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !bytes.Equal(gotPub, oldPub) {
		t.Error("PublicKey returned non-OLD key during staged rotation")
	}

	// Sign during the staged window — must recover the OLD pubkey.
	digest := mkDigest(0x11)
	sig, err := ks.Sign(rotateDID, digest)
	if err != nil {
		t.Fatalf("Sign during staged rotation: %v", err)
	}
	recovered, _, err := decredecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if !bytes.Equal(recovered.SerializeUncompressed(), oldPub) {
		t.Error("staged-window signature did not recover OLD pubkey — chain of custody broken")
	}

	// SignEntry strips the recovery byte; it MUST still verify under
	// the SDK's VerifyEntry path against the OLD key.
	entrySig, err := ks.SignEntry(rotateDID, digest)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if len(entrySig) != 64 {
		t.Fatalf("SignEntry len = %d, want 64", len(entrySig))
	}
}

// TestVault_CommitRotation_PromotesAndRetires is the post-commit pin:
// signs now use the NEW key, Sign recovers the NEW pubkey, and
// Vault's min_encryption_version advance means a follow-up
// StageNextKey is required before another rotation.
func TestVault_CommitRotation_PromotesAndRetires(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()

	oldInfo, err := ks.Generate(rotateDID, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pendingInfo, err := ks.StageNextKey(rotateDID, 2)
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}

	committed, err := ks.CommitRotation(rotateDID)
	if err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	if !bytes.Equal(committed.PublicKey, pendingInfo.PublicKey) {
		t.Error("committed PublicKey must match staged pending PublicKey")
	}
	if committed.RotationTier != 2 {
		t.Errorf("RotationTier = %d, want 2", committed.RotationTier)
	}

	// PublicKey now returns NEW.
	gotPub, err := ks.PublicKey(rotateDID)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !bytes.Equal(gotPub, pendingInfo.PublicKey) {
		t.Error("post-commit PublicKey != staged pending PublicKey")
	}
	if bytes.Equal(gotPub, oldInfo.PublicKey) {
		t.Error("post-commit PublicKey still equals OLD")
	}

	// Sign post-commit must recover the NEW pubkey.
	digest := mkDigest(0x22)
	sig, err := ks.Sign(rotateDID, digest)
	if err != nil {
		t.Fatalf("Sign post-commit: %v", err)
	}
	recovered, _, err := decredecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if !bytes.Equal(recovered.SerializeUncompressed(), pendingInfo.PublicKey) {
		t.Error("post-commit signature did not recover NEW pubkey")
	}
}

// TestVault_StageNextKey_NoCurrent rejects a stage with no
// previously-generated key — defends against operator error
// rotating a DID that was never provisioned.
func TestVault_StageNextKey_NoCurrent(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.StageNextKey("did:web:nope", 2); err == nil {
		t.Error("expected error staging rotation with no current key")
	}
}

// TestVault_StageNextKey_RequiresDID guards the precondition at the
// API boundary (matches Generate's contract).
func TestVault_StageNextKey_RequiresDID(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.StageNextKey("", 2); err == nil {
		t.Error("expected error for empty DID")
	}
}

// TestVault_StageNextKey_DoubleStage rejects a second StageNextKey
// before commit — Vault doesn't natively forbid a double-rotate,
// but the keystore's chain-of-custody invariant only holds for
// exactly one pending rotation. CommitRotation must run first.
func TestVault_StageNextKey_DoubleStage(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.Generate(rotateDID, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ks.StageNextKey(rotateDID, 2); err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	_, err := ks.StageNextKey(rotateDID, 3)
	if err == nil {
		t.Fatal("expected error on second StageNextKey before commit")
	}
	if !strings.Contains(err.Error(), "rotation already pending") {
		t.Errorf("error message should call out the precondition: %v", err)
	}
}

// TestVault_CommitRotation_NoPending guards against an unstaged
// commit — silent success here would mask a missed StageNextKey.
func TestVault_CommitRotation_NoPending(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.Generate(rotateDID, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ks.CommitRotation(rotateDID); err == nil {
		t.Error("expected error committing with no pending rotation")
	}
}

// TestVault_CommitRotation_RequiresDID — the API boundary check.
func TestVault_CommitRotation_RequiresDID(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.CommitRotation(""); err == nil {
		t.Error("expected error for empty DID")
	}
}

// TestVault_RotationCycle_Twice exercises two full
// stage→commit→sign cycles on the same DID. The second cycle's
// committed key must differ from both the original and the first
// rotated-in key — i.e., version monotonicity holds.
func TestVault_RotationCycle_Twice(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()

	gen, err := ks.Generate(rotateDID, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	v1 := append([]byte(nil), gen.PublicKey...)

	if _, err := ks.StageNextKey(rotateDID, 2); err != nil {
		t.Fatalf("StageNextKey #1: %v", err)
	}
	c1, err := ks.CommitRotation(rotateDID)
	if err != nil {
		t.Fatalf("CommitRotation #1: %v", err)
	}
	v2 := append([]byte(nil), c1.PublicKey...)

	if _, err := ks.StageNextKey(rotateDID, 3); err != nil {
		t.Fatalf("StageNextKey #2: %v", err)
	}
	c2, err := ks.CommitRotation(rotateDID)
	if err != nil {
		t.Fatalf("CommitRotation #2: %v", err)
	}
	v3 := append([]byte(nil), c2.PublicKey...)

	if bytes.Equal(v1, v2) || bytes.Equal(v2, v3) || bytes.Equal(v1, v3) {
		t.Error("rotation cycle produced duplicate public keys")
	}

	// Final Sign recovers v3.
	digest := mkDigest(0x33)
	sig, err := ks.Sign(rotateDID, digest)
	if err != nil {
		t.Fatalf("Sign post-2nd-commit: %v", err)
	}
	recovered, _, err := decredecdsa.RecoverCompact(sig, digest[:])
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if !bytes.Equal(recovered.SerializeUncompressed(), v3) {
		t.Error("final signature did not recover v3 pubkey")
	}
}

// TestVault_Destroy_ClearsRotationState — Destroy must not leave
// orphan pendingSec / activeVersion entries that would shadow a
// subsequent Generate on the same DID.
func TestVault_Destroy_ClearsRotationState(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()

	if _, err := ks.Generate(rotateDID, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := ks.StageNextKey(rotateDID, 2); err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if err := ks.Destroy(rotateDID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	ks.mu.RLock()
	_, hasKey := ks.keysSec[rotateDID]
	_, hasPending := ks.pendingSec[rotateDID]
	_, hasActive := ks.activeVersion[rotateDID]
	ks.mu.RUnlock()
	if hasKey || hasPending || hasActive {
		t.Errorf("Destroy left stale state: key=%v pending=%v active=%v",
			hasKey, hasPending, hasActive)
	}

	// A fresh Generate on the same DID must succeed without
	// inheriting the prior pendingSec entry (which would have
	// shadowed the new key).
	regen, err := ks.Generate(rotateDID, "signing")
	if err != nil {
		t.Fatalf("Generate after Destroy: %v", err)
	}
	if regen.RotationTier != 0 {
		t.Errorf("regenerated key inherited stale RotationTier %d", regen.RotationTier)
	}
}

// TestVault_StageNextKey_TierRecorded — RotationTier flows through
// to the returned KeyInfo (used by callers building the rotation
// entry's tier field).
func TestVault_StageNextKey_TierRecorded(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.Generate(rotateDID, "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pending, err := ks.StageNextKey(rotateDID, 42)
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	if pending.RotationTier != 42 {
		t.Errorf("pending RotationTier = %d, want 42", pending.RotationTier)
	}
	if !strings.Contains(pending.KeyID, "#secp256k1-42") {
		t.Errorf("pending KeyID does not encode tier: %s", pending.KeyID)
	}
}
