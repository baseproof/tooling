/*
FILE PATH: libs/keystore/vault/vault_secp256k1.go

DESCRIPTION:

	secp256k1 surface for the Vault Transit backend. The protocol curve
	is secp256k1 with SignCompact wire format (recoveryByte || R || S,
	65 bytes); Vault returns DER-marshaled (R, S) so we recover the
	byte by trying both v values against the known public key.

	S is canonicalized to low form (BIP-62) so the recovery byte
	matches what the SDK and Privy emit — keeping the wire shape
	consistent across custody backends.
*/
package vault

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/baseproof/tooling/libs/keystore"
)

func (k *KeyStore) Generate(did, purpose string) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("vault: Generate: did required")
	}
	name := keyName(did, keystore.CurveSecp256k1)
	if err := k.createKey(name, "ecdsa-p256k1"); err != nil {
		return nil, err
	}
	pub, err := k.fetchPublicKey(name, keystore.CurveSecp256k1)
	if err != nil {
		return nil, err
	}
	info := &keystore.KeyInfo{
		KeyID:     fmt.Sprintf("%s#secp256k1-1", did),
		DID:       did,
		Purpose:   purpose,
		Curve:     keystore.CurveSecp256k1,
		PublicKey: pub,
		Created:   time.Now().UTC(),
	}
	k.mu.Lock()
	k.keysSec[did] = info
	k.activeVersion[did] = 1 // newly-created Transit key is at v1
	k.mu.Unlock()
	return info, nil
}

func (k *KeyStore) Sign(did string, digest [32]byte) ([]byte, error) {
	name := keyName(did, keystore.CurveSecp256k1)
	// Sign with the keystore's recorded active version (not Vault's
	// latest) so a staged rotation keeps signing with the OLD key
	// until CommitRotation. activeVersion is set to 1 at Generate
	// time and updated in CommitRotation; an unrecorded version
	// (== 0) falls back to "latest" inside signDERAt.
	k.mu.RLock()
	version := k.activeVersion[did]
	k.mu.RUnlock()
	r, s, err := k.signDERAt(name, digest[:], version)
	if err != nil {
		return nil, err
	}
	pub, err := k.PublicKey(did)
	if err != nil {
		return nil, fmt.Errorf("vault: Sign: %w", err)
	}
	return packCompact(r, s, digest[:], pub)
}

// SignEntry returns the 64-byte R‖S SigAlgoECDSA signature by stripping
// the leading recovery byte from the 65-byte SignCompact — the wire shape
// the SDK's VerifyEntry consumes for on-log entries.
func (k *KeyStore) SignEntry(did string, digest [32]byte) ([]byte, error) {
	compact, err := k.Sign(did, digest)
	if err != nil {
		return nil, err
	}
	if len(compact) != 65 {
		return nil, fmt.Errorf("vault: SignEntry: unexpected compact len %d", len(compact))
	}
	return compact[1:], nil
}

// StageNextKey rotates the Vault Transit key for did and stashes the
// new-version metadata as pending. The Vault server's "latest version"
// pointer advances; the keystore explicitly continues to sign with the
// OLD version (via the activeVersion map + signDERAt) so the rotation
// entry — which NAMES the new key — is signed by the RETIRING key. The
// SDK's rotation model requires this old-key-signs chain of custody.
//
// tier is recorded in the new KeyInfo's RotationTier field for caller
// diagnostics; it does NOT control Vault's version (Vault assigns the
// next monotonic integer).
//
// Errors if no key exists for did, or if a pending rotation already
// stands (CommitRotation must run first). Returns the pending KeyInfo
// without mutating activeVersion — Sign continues to use the OLD key
// until CommitRotation.
func (k *KeyStore) StageNextKey(did string, tier int) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("vault: StageNextKey: did required")
	}
	k.mu.RLock()
	current, hasCurrent := k.keysSec[did]
	_, hasPending := k.pendingSec[did]
	k.mu.RUnlock()
	if !hasCurrent {
		return nil, fmt.Errorf("vault: StageNextKey: no current key for %s (call Generate first)", did)
	}
	if hasPending {
		return nil, fmt.Errorf("vault: StageNextKey: rotation already pending for %s (CommitRotation first)", did)
	}

	name := keyName(did, keystore.CurveSecp256k1)

	// Vault rotate: POST /v1/<mount>/keys/<name>/rotate. The
	// server creates a new version and returns the updated key
	// metadata. We immediately fetch the metadata to learn the
	// new version number.
	if err := k.rotateKey(name); err != nil {
		return nil, fmt.Errorf("vault: StageNextKey: rotate: %w", err)
	}

	newVersion, newPub, err := k.fetchLatestVersionAndKey(name, keystore.CurveSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("vault: StageNextKey: fetch new version: %w", err)
	}

	now := time.Now().UTC()
	rotated := now
	pendingInfo := &keystore.KeyInfo{
		KeyID:        fmt.Sprintf("%s#secp256k1-%d", did, tier),
		DID:          did,
		Purpose:      current.Purpose,
		Curve:        keystore.CurveSecp256k1,
		PublicKey:    newPub,
		Created:      now,
		Rotated:      &rotated,
		RotationTier: tier,
	}

	k.mu.Lock()
	k.pendingSec[did] = &pendingRotation{info: pendingInfo, version: newVersion}
	k.mu.Unlock()

	return pendingInfo, nil
}

// CommitRotation promotes the pending Vault key version to active
// and advances min_encryption_version + min_decryption_version on the
// Vault key so the OLD version can no longer sign. The retired
// version's bytes remain accessible for VERIFY (min_decryption_version
// matches min_encryption_version), letting downstream consumers
// continue to verify signatures produced BEFORE the rotation; new
// signatures use only the new version.
//
// Errors if no pending rotation stands. Idempotent on success
// (subsequent calls without staging error).
func (k *KeyStore) CommitRotation(did string) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("vault: CommitRotation: did required")
	}
	k.mu.RLock()
	pending, ok := k.pendingSec[did]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("vault: CommitRotation: no pending rotation for %s", did)
	}

	name := keyName(did, keystore.CurveSecp256k1)
	// Advance min_encryption_version so OLD version can no longer
	// sign. The default min_decryption_version is 1; raising it to
	// the new version means OLD signatures can no longer be
	// verified via Vault, but they remain verifiable using the
	// stored public key bytes (which downstream verifiers already
	// have). For maximum compatibility we leave min_decryption_version
	// at 0 (Vault default — every version is decryptable) and only
	// advance min_encryption_version.
	if err := k.updateKeyConfig(name, pending.version); err != nil {
		return nil, fmt.Errorf("vault: CommitRotation: update config: %w", err)
	}

	k.mu.Lock()
	k.keysSec[did] = pending.info
	k.activeVersion[did] = pending.version
	delete(k.pendingSec, did)
	k.mu.Unlock()

	return pending.info, nil
}

func (k *KeyStore) PublicKey(did string) ([]byte, error) {
	k.mu.RLock()
	info, ok := k.keysSec[did]
	k.mu.RUnlock()
	if ok {
		out := make([]byte, len(info.PublicKey))
		copy(out, info.PublicKey)
		return out, nil
	}
	pub, err := k.fetchPublicKey(keyName(did, keystore.CurveSecp256k1), keystore.CurveSecp256k1)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// packCompact converts (R, S) + the 32-byte digest + known pubkey
// into the 65-byte SignCompact wire form: tries both v values (0 / 1),
// returns the variant that recovers the matching public key.
func packCompact(r, s *big.Int, digest, knownPub []byte) ([]byte, error) {
	rBytes := leftPad32(r.Bytes())
	sBytes := leftPad32(s.Bytes())
	for v := byte(0); v <= 1; v++ {
		compact := make([]byte, 65)
		compact[0] = v + 27
		copy(compact[1:33], rBytes)
		copy(compact[33:65], sBytes)
		pub, _, err := decredecdsa.RecoverCompact(compact, digest)
		if err != nil {
			continue
		}
		if bytes.Equal(pub.SerializeUncompressed(), knownPub) {
			return compact, nil
		}
	}
	return nil, fmt.Errorf("vault: packCompact: no recovery byte matched")
}

func leftPad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// canonicalizeS normalizes S to its low form (BIP-62 / Ethereum's malleability
// fix) using the secp256k1 curve order. Vault returns the raw signature
// from Go's stdlib ECDSA, which permits high-S values; the SDK and Privy
// emit low-S, and the recovery byte we compute is for low-S.
func canonicalizeS(s *big.Int) *big.Int {
	curveOrder := secp256k1.S256().N
	half := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(half) > 0 {
		return new(big.Int).Sub(curveOrder, s)
	}
	return s
}
