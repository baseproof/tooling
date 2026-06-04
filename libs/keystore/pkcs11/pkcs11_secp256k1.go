//go:build pkcs11

/*
FILE PATH: libs/keystore/pkcs11/pkcs11_secp256k1.go

DESCRIPTION:

	secp256k1 surface for the PKCS#11 backend. PKCS#11 returns raw
	R||S from CKM_ECDSA — no recovery byte. We follow the same recipe
	as the Vault backend: canonicalize S to low form (BIP-62) then
	try both v values against the known public key.

	CKA_EC_PARAMS is the secp256k1 OID (1.3.132.0.10) DER-encoded;
	CKA_EXTRACTABLE is forced false on the private key so escrow
	paths cannot bypass the token.
*/
package pkcs11

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	mpkcs11 "github.com/miekg/pkcs11"

	decredsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/baseproof/tooling/libs/keystore"
)

// secp256k1OIDDER is the DER-encoded OID 1.3.132.0.10 (secp256k1)
// passed verbatim as CKA_EC_PARAMS at key-pair generation.
var secp256k1OIDDER = []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a}

func (k *KeyStore) Generate(did, purpose string) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("pkcs11: Generate: did required")
	}
	pub, err := k.generateAtTier(did, 1)
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
	k.currentTier[did] = 1
	k.mu.Unlock()
	return info, nil
}

// generateAtTier provisions a secp256k1 key pair on the token under
// CKA_LABEL = labelForTier(did, tier) and returns the uncompressed
// public key bytes. Used by both Generate (tier=1) and
// StageNextKey (tier=N>1) — the only difference between those
// callers is what they do with the resulting KeyInfo afterward.
func (k *KeyStore) generateAtTier(did string, tier int) ([]byte, error) {
	lbl := labelForTier(did, tier)
	pubTpl := []*mpkcs11.Attribute{
		mpkcs11.NewAttribute(mpkcs11.CKA_CLASS, mpkcs11.CKO_PUBLIC_KEY),
		mpkcs11.NewAttribute(mpkcs11.CKA_KEY_TYPE, mpkcs11.CKK_EC),
		mpkcs11.NewAttribute(mpkcs11.CKA_TOKEN, true),
		mpkcs11.NewAttribute(mpkcs11.CKA_VERIFY, true),
		mpkcs11.NewAttribute(mpkcs11.CKA_LABEL, lbl),
		mpkcs11.NewAttribute(mpkcs11.CKA_EC_PARAMS, secp256k1OIDDER),
	}
	privTpl := []*mpkcs11.Attribute{
		mpkcs11.NewAttribute(mpkcs11.CKA_CLASS, mpkcs11.CKO_PRIVATE_KEY),
		mpkcs11.NewAttribute(mpkcs11.CKA_KEY_TYPE, mpkcs11.CKK_EC),
		mpkcs11.NewAttribute(mpkcs11.CKA_TOKEN, true),
		mpkcs11.NewAttribute(mpkcs11.CKA_PRIVATE, true),
		mpkcs11.NewAttribute(mpkcs11.CKA_SIGN, true),
		mpkcs11.NewAttribute(mpkcs11.CKA_SENSITIVE, true),
		mpkcs11.NewAttribute(mpkcs11.CKA_EXTRACTABLE, false),
		mpkcs11.NewAttribute(mpkcs11.CKA_LABEL, lbl),
	}
	pubH, _, err := k.ctx.GenerateKeyPair(k.session,
		[]*mpkcs11.Mechanism{mpkcs11.NewMechanism(mpkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubTpl, privTpl)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: GenerateKeyPair: %w", err)
	}
	return k.fetchECPoint(pubH)
}

func (k *KeyStore) Sign(did string, digest [32]byte) ([]byte, error) {
	pub, err := k.PublicKey(did)
	if err != nil {
		return nil, err
	}
	privH, err := k.findPrivateKey(did)
	if err != nil {
		return nil, err
	}
	if err := k.ctx.SignInit(k.session,
		[]*mpkcs11.Mechanism{mpkcs11.NewMechanism(mpkcs11.CKM_ECDSA, nil)},
		privH); err != nil {
		return nil, fmt.Errorf("pkcs11: SignInit: %w", err)
	}
	raw, err := k.ctx.Sign(k.session, digest[:])
	if err != nil {
		return nil, fmt.Errorf("pkcs11: Sign: %w", err)
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("pkcs11: Sign: unexpected sig len %d", len(raw))
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := canonicalizeS(new(big.Int).SetBytes(raw[32:]))
	return packCompact(r, s, digest[:], pub)
}

// SignEntry returns the 64-byte R‖S SigAlgoECDSA signature by stripping
// the leading recovery byte from the 65-byte SignCompact (S is already
// low-S canonicalized above). This is the wire shape the SDK's VerifyEntry
// consumes for on-log entries.
func (k *KeyStore) SignEntry(did string, digest [32]byte) ([]byte, error) {
	compact, err := k.Sign(did, digest)
	if err != nil {
		return nil, err
	}
	if len(compact) != 65 {
		return nil, fmt.Errorf("pkcs11: SignEntry: unexpected compact len %d", len(compact))
	}
	return compact[1:], nil
}

// StageNextKey provisions the DID's NEXT secp256k1 key on the token
// under a tier-suffixed CKA_LABEL — leaving the OLD (current-tier)
// key pair intact so Sign / SignEntry continue signing with the
// retiring key. The pending KeyInfo is stashed in pendingSec until
// CommitRotation promotes it.
//
// Errors if no key exists for did, or if a pending rotation already
// stands (CommitRotation must run first). tier is the rotation
// tier (must be > the current tier; passing a tier <= currentTier
// is an operator error and is rejected). Returns the pending
// KeyInfo without mutating currentTier.
func (k *KeyStore) StageNextKey(did string, tier int) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("pkcs11: StageNextKey: did required")
	}
	k.mu.RLock()
	current, hasCurrent := k.keysSec[did]
	curTier := k.currentTier[did]
	_, hasPending := k.pendingSec[did]
	k.mu.RUnlock()
	if !hasCurrent {
		return nil, fmt.Errorf("pkcs11: StageNextKey: no current key for %s (call Generate first)", did)
	}
	if hasPending {
		return nil, fmt.Errorf("pkcs11: StageNextKey: rotation already pending for %s (CommitRotation first)", did)
	}
	if tier <= curTier {
		return nil, fmt.Errorf("pkcs11: StageNextKey: tier %d must be > current tier %d", tier, curTier)
	}

	pub, err := k.generateAtTier(did, tier)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: StageNextKey: %w", err)
	}

	now := time.Now().UTC()
	rotated := now
	pendingInfo := &keystore.KeyInfo{
		KeyID:        fmt.Sprintf("%s#secp256k1-%d", did, tier),
		DID:          did,
		Purpose:      current.Purpose,
		Curve:        keystore.CurveSecp256k1,
		PublicKey:    pub,
		Created:      now,
		Rotated:      &rotated,
		RotationTier: tier,
	}

	k.mu.Lock()
	k.pendingSec[did] = &pendingRotation{info: pendingInfo, tier: tier}
	k.mu.Unlock()

	return pendingInfo, nil
}

// CommitRotation promotes the pending key to active: destroys the
// OLD key pair on the token (so it can no longer sign), advances
// currentTier, and moves pendingSec → keysSec. Errors if no pending
// rotation stands.
//
// The destruction is best-effort — if the token returns an error
// on DestroyObject (unlikely for a key we own + just generated)
// we still complete the promotion. The orphaned object would be
// reachable only via an old-tier label that no live code path uses.
func (k *KeyStore) CommitRotation(did string) (*keystore.KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("pkcs11: CommitRotation: did required")
	}
	k.mu.RLock()
	pending, ok := k.pendingSec[did]
	curTier := k.currentTier[did]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("pkcs11: CommitRotation: no pending rotation for %s", did)
	}

	// Destroy the OLD tier's key pair. Best-effort: see docstring.
	_ = k.destroyByLabel(labelForTier(did, curTier))

	k.mu.Lock()
	k.keysSec[did] = pending.info
	k.currentTier[did] = pending.tier
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
	pubH, err := k.findPublicKey(did)
	if err != nil {
		return nil, err
	}
	return k.fetchECPoint(pubH)
}

// canonicalizeS / packCompact mirror the vault backend: PKCS#11 also
// has no recovery byte in the raw R||S output.
func canonicalizeS(s *big.Int) *big.Int {
	curveOrder := decredsecp.S256().N
	half := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(half) > 0 {
		return new(big.Int).Sub(curveOrder, s)
	}
	return s
}

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
	return nil, fmt.Errorf("pkcs11: packCompact: no recovery byte matched")
}

func leftPad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
