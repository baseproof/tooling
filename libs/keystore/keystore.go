/*
FILE PATH: exchange/keystore/keystore.go

DESCRIPTION:

	Key custody for the Judicial Network's own institutional actors —
	automated Court Clerks, Publisher Daemons, Notary services, the
	ledger/institutional system DIDs. The keystore never exports private
	keys except the dedicated escrow path; it signs digests and returns
	signatures (the AWS-KMS / PKCS#11 model).

	# ONE CURVE: secp256k1

	The Baseproof protocol curve is secp256k1 ECDSA — every on-log entry
	signature is secp256k1 (SigAlgoECDSA), every EVM/Web3 actor and
	did:pkh identity is secp256k1, and the ledger's VerifyEntry expects
	secp256k1. JN institutional actors sign with the same curve as the
	human Web3 users they interoperate with. (Layer-4 witness quorums use
	BLS12-381; that is a separate plane, not this keystore.)

	# TWO SIGNATURE SHAPES, ONE CURVE

	  - SignEntry → 64-byte R‖S, low-S normalized. The SigAlgoECDSA wire
	    shape the SDK's VerifyEntry consumes for log entries. The signed
	    value is sha256(envelope.SigningPayload(entry)) (attestation/
	    signatures.go computes exactly this digest on the verify side).
	  - Sign → 65-byte recoverable SignCompact (v‖R‖S). The shape Privy
	    emits and EIP-1271 / SCW ecrecover paths consume; the keystore/
	    signer adapter byte-swaps it to Ethereum r‖s‖v.

	# STAGED ROTATION (old-key-signs)

	A key rotation is authorized by the key it RETIRES (the SDK rotation
	model + verification.RotationHistorySource chain-of-custody check), so
	the retiring key must stay signable while the rotation entry — which
	names the NEW key — is built and signed. StageNextKey provisions the
	next key as PENDING (current stays active); CommitRotation promotes it
	once the rotation entry is on the log.

	Production path: external user-DID signing routes through the
	IdentityProvider (Privy embedded wallets, secp256k1); this keystore
	holds JN's institutional/system DIDs.

KEY DEPENDENCIES:
  - github.com/decred/dcrd/dcrec/secp256k1/v4 (curve operations).
  - baseproof/crypto/signatures: SignEntry (64-byte SigAlgoECDSA wire).
*/
package keystore

import (
	"fmt"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/baseproof/baseproof/crypto/signatures"
)

// CurveSecp256k1 is the only curve this keystore manages. Recorded in
// KeyInfo.Curve for diagnostics + wire compatibility with consumers that
// branch on it.
const CurveSecp256k1 = "secp256k1"

// KeyStore is secp256k1-only key custody for JN institutional DIDs.
type KeyStore interface {
	// Generate provisions a new secp256k1 keypair for the DID and returns
	// its KeyInfo (PublicKey = 65-byte uncompressed, 0x04 prefix).
	Generate(did string, purpose string) (*KeyInfo, error)

	// PublicKey returns the DID's 65-byte uncompressed secp256k1 key.
	PublicKey(did string) ([]byte, error)

	// Sign returns a 65-byte recoverable SignCompact (v‖R‖S) over the
	// 32-byte digest — the Privy/SCW/ecrecover wire shape. The keystore
	// does NOT hash again; the caller passes the typed-data digest.
	Sign(did string, digest [32]byte) ([]byte, error)

	// SignEntry returns the 64-byte R‖S (low-S) SigAlgoECDSA signature
	// over the 32-byte digest — the wire shape the SDK's VerifyEntry
	// consumes for on-log entries. Caller passes
	// sha256(envelope.SigningPayload(entry)).
	SignEntry(did string, digest [32]byte) ([]byte, error)

	// StageNextKey provisions the DID's NEXT secp256k1 key as PENDING and
	// returns its KeyInfo. The current key stays active + signable so the
	// rotation entry (which names the new key) can be signed by the
	// RETIRING key — the old-key-signs chain of custody. CommitRotation
	// promotes the pending key.
	StageNextKey(did string, tier int) (*KeyInfo, error)

	// CommitRotation promotes the pending key from StageNextKey to active,
	// discarding the retired key. Errors if no rotation is pending.
	CommitRotation(did string) (*KeyInfo, error)

	// List returns all managed keys.
	List() []*KeyInfo

	// Destroy permanently deletes a DID's key material (expungement).
	Destroy(did string) error

	// ExportForEscrow returns the raw 32-byte secp256k1 private scalar for
	// Shamir escrow splitting. Only callable during escrow ops; HSM/Vault
	// backends reject this (non-extractable keys).
	ExportForEscrow(did string) ([]byte, error)
}

// KeyInfo describes a managed secp256k1 key without exposing the private
// material. PublicKey is the 65-byte uncompressed (0x04 prefix) form.
type KeyInfo struct {
	KeyID        string     `json:"key_id"`
	DID          string     `json:"did"`
	Purpose      string     `json:"purpose"` // "signing" | "encryption" | "delegation"
	Curve        string     `json:"curve"`   // always CurveSecp256k1
	PublicKey    []byte     `json:"public_key"`
	Created      time.Time  `json:"created"`
	Rotated      *time.Time `json:"rotated,omitempty"`
	RotationTier int        `json:"rotation_tier,omitempty"`
}

// MemoryKeyStore is an in-memory secp256k1 implementation for
// development, tests, and the network-api default backend.
type MemoryKeyStore struct {
	mu      sync.RWMutex
	keys    map[string]*managedSecpKey
	pending map[string]*managedSecpKey // staged rotations awaiting CommitRotation
}

type managedSecpKey struct {
	info       *KeyInfo
	privateKey *secp256k1.PrivateKey
}

// NewMemoryKeyStore creates an in-memory secp256k1 key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys:    make(map[string]*managedSecpKey),
		pending: make(map[string]*managedSecpKey),
	}
}

func newManagedKey(did, purpose, keyID string, priv *secp256k1.PrivateKey) *managedSecpKey {
	return &managedSecpKey{
		info: &KeyInfo{
			KeyID:     keyID,
			DID:       did,
			Purpose:   purpose,
			Curve:     CurveSecp256k1,
			PublicKey: priv.PubKey().SerializeUncompressed(),
			Created:   time.Now().UTC(),
		},
		privateKey: priv,
	}
}

func (m *MemoryKeyStore) Generate(did string, purpose string) (*KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("keystore: Generate: did required")
	}
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("keystore: Generate: %w", err)
	}
	mk := newManagedKey(did, purpose, fmt.Sprintf("%s#secp256k1-1", did), priv)
	m.mu.Lock()
	m.keys[did] = mk
	m.mu.Unlock()
	return mk.info, nil
}

// ImportSecp256k1 binds a caller-supplied private key to the DID. Used by
// escrow recovery, deterministic test fixtures, and ledger bootstrap.
func (m *MemoryKeyStore) ImportSecp256k1(did, purpose string, priv *secp256k1.PrivateKey) (*KeyInfo, error) {
	if did == "" {
		return nil, fmt.Errorf("keystore: ImportSecp256k1: did required")
	}
	if priv == nil {
		return nil, fmt.Errorf("keystore: ImportSecp256k1: nil key")
	}
	mk := newManagedKey(did, purpose, fmt.Sprintf("%s#secp256k1-1", did), priv)
	m.mu.Lock()
	m.keys[did] = mk
	m.mu.Unlock()
	return mk.info, nil
}

func (m *MemoryKeyStore) PublicKey(did string) ([]byte, error) {
	m.mu.RLock()
	mk, ok := m.keys[did]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}
	out := make([]byte, len(mk.info.PublicKey))
	copy(out, mk.info.PublicKey)
	return out, nil
}

// Sign returns the 65-byte recoverable SignCompact (v‖R‖S).
func (m *MemoryKeyStore) Sign(did string, digest [32]byte) ([]byte, error) {
	m.mu.RLock()
	mk, ok := m.keys[did]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}
	return ecdsa.SignCompact(mk.privateKey, digest[:], false), nil
}

// SignEntry returns the 64-byte R‖S (low-S) SigAlgoECDSA signature via the
// SDK's signatures.SignEntry — guaranteed to verify under VerifyEntry.
func (m *MemoryKeyStore) SignEntry(did string, digest [32]byte) ([]byte, error) {
	m.mu.RLock()
	mk, ok := m.keys[did]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}
	return signatures.SignEntry(digest, mk.privateKey.ToECDSA())
}

func (m *MemoryKeyStore) StageNextKey(did string, tier int) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.keys[did]
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("keystore: StageNextKey: %w", err)
	}
	mk := newManagedKey(did, cur.info.Purpose, fmt.Sprintf("%s#secp256k1-%d", did, tier), priv)
	now := time.Now().UTC()
	mk.info.Rotated = &now
	mk.info.RotationTier = tier
	m.pending[did] = mk
	return mk.info, nil
}

func (m *MemoryKeyStore) CommitRotation(did string) (*KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mk, ok := m.pending[did]
	if !ok {
		return nil, fmt.Errorf("keystore: no pending rotation for %s", did)
	}
	m.keys[did] = mk
	delete(m.pending, did)
	return mk.info, nil
}

func (m *MemoryKeyStore) List() []*KeyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*KeyInfo, 0, len(m.keys))
	for _, mk := range m.keys {
		out = append(out, mk.info)
	}
	return out
}

func (m *MemoryKeyStore) Destroy(did string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, hasKey := m.keys[did]
	_, hasPending := m.pending[did]
	if !hasKey && !hasPending {
		return fmt.Errorf("keystore: no key for %s", did)
	}
	delete(m.keys, did)
	delete(m.pending, did)
	return nil
}

func (m *MemoryKeyStore) ExportForEscrow(did string) ([]byte, error) {
	m.mu.RLock()
	mk, ok := m.keys[did]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("keystore: no key for %s", did)
	}
	return mk.privateKey.Serialize(), nil
}
