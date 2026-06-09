package loadgen

// Deterministic identity derivation.
//
// The legacy backfill CLI minted every root's keypair with a fresh CSPRNG
// (did.GenerateDIDKeySecp256k1 → crypto/rand) and RETAINED it for the whole run
// so a later amendment could re-sign under the same key (Path A's same-signer
// rule). That retention is O(roots) live heap — the larger half of the backfill
// OOM at scale.
//
// Instead we DERIVE each root's identity as a pure function of (runSeed,
// rootIndex). Nothing is retained: an amendment to root i re-derives root i's key
// on demand. Memory for keys becomes O(1), and — because the derivation is a pure
// function of the seed — the entire run (which roots exist, which key signs each)
// is byte-for-byte REPRODUCIBLE from the seed alone. The expected-state oracle no
// longer needs to carry private material; rootIndex is sufficient.
//
// Construction: HKDF-SHA256(secret=seed, info=domain‖rootIndex‖counter) → a
// 32-byte secp256k1 scalar → *ecdsa.PrivateKey. The compressed public key is
// wrapped in a spec-compliant did:key by the SDK encoder, so the resulting DID is
// self-certifying (it embeds the very key that signs) and the ledger admits a
// signature under it exactly as it would a randomly-generated one — the only
// change is WHERE the entropy comes from. The counter handles the (≈2⁻¹²⁸)
// out-of-range-scalar case without breaking determinism.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/hkdf"

	sdkdid "github.com/baseproof/baseproof/did"
)

// keyDomain is the HKDF info-string domain separator. Versioned so a future
// change to the derivation can never collide with a v1 run's keyspace.
const keyDomain = "baseproof/loadgen/secp256k1-root/v1"

// Identity is one deterministically-derived signer: a root entity's keypair and
// its self-certifying did:key. Derived on demand from (seed, Index); never
// retained beyond the bounded amend window.
type Identity struct {
	Index uint64
	DID   string
	Priv  *ecdsa.PrivateKey
}

// seedBytes renders an int64 run seed as the 8-byte big-endian HKDF secret, so
// the CLI's -seed flag and any in-process caller agree on the keyspace.
func seedBytes(seed int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(seed))
	return b[:]
}

// deriveScalar expands the seed into a 32-byte candidate scalar for (idx,
// counter). counter is bumped only on the astronomically rare invalid-scalar
// retry, so counter==0 is the deterministic norm.
func deriveScalar(seed []byte, idx, counter uint64) [32]byte {
	info := make([]byte, 0, len(keyDomain)+16)
	info = append(info, keyDomain...)
	var idxc [16]byte
	binary.BigEndian.PutUint64(idxc[0:8], idx)
	binary.BigEndian.PutUint64(idxc[8:16], counter)
	info = append(info, idxc[:]...)

	r := hkdf.New(sha256.New, seed, nil, info)
	var scalar [32]byte
	// hkdf.New's reader never errors for a 32-byte read well under its output cap.
	_, _ = io.ReadFull(r, scalar[:])
	return scalar
}

// identityFromScalar builds the *ecdsa.PrivateKey + self-certifying did:key for a
// 32-byte secp256k1 scalar, reusing the SDK's compression + did:key encoding (no
// crypto reimplemented). ok=false only for the zero scalar (an invalid key).
func identityFromScalar(scalar [32]byte) (priv *ecdsa.PrivateKey, did string, ok bool) {
	k := secp256k1.PrivKeyFromBytes(scalar[:]) // interprets bytes mod n
	if k == nil || k.Key.IsZero() {
		return nil, "", false
	}
	compressed := k.PubKey().SerializeCompressed() // standard 33-byte sec1
	return k.ToECDSA(), sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), true
}

// deriveIdentity returns the secp256k1 identity for root index idx under seed. It
// is a pure function of (seed, idx): the same inputs always yield the same DID +
// private key, on this machine or any other. seed is the HKDF secret (see
// seedBytes for the int64 rendering).
func deriveIdentity(seed []byte, idx uint64) (Identity, error) {
	// A zero scalar (≈2⁻¹²⁸) is the only invalid outcome. Bump the counter and
	// re-expand if so, so a derivation never fails yet stays deterministic.
	for counter := uint64(0); counter < 64; counter++ {
		if priv, did, ok := identityFromScalar(deriveScalar(seed, idx, counter)); ok {
			return Identity{Index: idx, DID: did, Priv: priv}, nil
		}
	}
	return Identity{}, fmt.Errorf("loadgen: could not derive a valid secp256k1 scalar for root %d after 64 counters (impossible absent a broken HKDF)", idx)
}

// IdentityFromScalar builds a signing Identity from a raw 32-byte secp256k1
// scalar — a client's saved key — using the same did:key encoding as the derived
// identities, so a key generated here and reloaded later resolves to the same
// DID. Index is left 0 (a raw key carries no derivation index).
func IdentityFromScalar(scalar []byte) (Identity, error) {
	if len(scalar) != 32 {
		return Identity{}, fmt.Errorf("loadgen: secp256k1 scalar must be 32 bytes, got %d", len(scalar))
	}
	var s [32]byte
	copy(s[:], scalar)
	priv, did, ok := identityFromScalar(s)
	if !ok {
		return Identity{}, fmt.Errorf("loadgen: invalid secp256k1 scalar (zero)")
	}
	return Identity{DID: did, Priv: priv}, nil
}
