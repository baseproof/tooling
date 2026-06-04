/*
FILE PATH: internal/witkey/witkey.go

DESCRIPTION:

	secp256k1 witness-key generation, on-disk PEM I/O, and did:key
	derivation — the single source of truth for how a standalone
	witness's signing key is created, stored, loaded, and named.

WHY secp256k1 (NOT stdlib P-256):

	Witnesses cosign tree heads under the Baseproof protocol, whose
	witness/cosign layer is secp256k1 end-to-end: the ledger's
	witness.KeysFromDIDs resolver, cosign.NewECDSAWitnessKeySet, and
	the judicial network's witness sets all require secp256k1 keys
	(did:key:zQ3s…). A P-256 witness key produces a did:key the
	ledger's secp256k1 resolver rejects ("x coordinate not on the
	secp256k1 curve").

	Go's crypto/x509 cannot marshal secp256k1 (it is not a stdlib
	elliptic curve), so the key is stored as its raw 32-byte scalar
	in a PEM envelope and reconstructed via the SDK's secp256k1
	primitives (signatures.PrivKeyFromBytes). All curve math routes
	through the SDK — this package only owns the envelope.
*/
package witkey

import (
	"crypto/ecdsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
)

// PEMType is the PEM block type for a witness secp256k1 private key.
// Distinct from stdlib "EC PRIVATE KEY" (SEC1) so a P-256 key written
// by an older build fails loudly rather than parsing as the wrong curve.
const PEMType = "BASEPROOF SECP256K1 PRIVATE KEY"

const scalarLen = 32

// Generate returns a fresh secp256k1 private key (the SDK's GenerateKey).
func Generate() (*ecdsa.PrivateKey, error) {
	return signatures.GenerateKey()
}

// EncodePEM serializes priv as a PEM block carrying its 32-byte big-endian
// scalar.
func EncodePEM(priv *ecdsa.PrivateKey) []byte {
	var scalar [scalarLen]byte
	priv.D.FillBytes(scalar[:]) // left-padded; secp256k1 D always fits in 32B
	return pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: scalar[:]})
}

// LoadPEM reads a witness secp256k1 key from a PEM file.
func LoadPEM(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("witkey: read %q: %w", path, err)
	}
	return DecodePEM(data)
}

// DecodePEM parses a witness secp256k1 key from PEM bytes. Fail-closed on a
// missing block, the wrong block type (e.g. a legacy P-256 "EC PRIVATE KEY"),
// or a scalar of the wrong length.
func DecodePEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("witkey: no PEM block (file empty or malformed)")
	}
	if block.Type != PEMType {
		return nil, fmt.Errorf("witkey: PEM type %q, want %q (regenerate the key — secp256k1, not P-256)", block.Type, PEMType)
	}
	if len(block.Bytes) != scalarLen {
		return nil, fmt.Errorf("witkey: scalar is %d bytes, want %d", len(block.Bytes), scalarLen)
	}
	return signatures.PrivKeyFromBytes(block.Bytes)
}

// DID derives the secp256k1 did:key (did:key:zQ3s…) for priv — the identity
// the ledger resolves via witness.KeysFromDIDs and the JN binds its witness
// sets to.
func DID(priv *ecdsa.PrivateKey) (string, error) {
	uncompressed := signatures.PubKeyBytes(&priv.PublicKey)
	compressed, err := signatures.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		return "", fmt.Errorf("witkey: compress pubkey: %w", err)
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), nil
}
