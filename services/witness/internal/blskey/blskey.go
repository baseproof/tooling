/*
FILE PATH: internal/blskey/blskey.go

DESCRIPTION:

	BLS12-381 witness-key generation, on-disk PEM I/O, proof-of-possession,
	and on-log endpoint-declaration assembly — the BLS sibling of
	internal/witkey, the single source of truth for how a standalone BLS
	witness's signing key is created, stored, loaded, and declared.

WHY A SEPARATE SCHEME (NOT secp256k1):

	A BLS witness cosigns tree heads under crypto/cosign's SchemeBLS (0x02):
	a 48-byte G1 signature aggregated K-of-N, verified against a 96-byte G2
	public key. Unlike secp256k1 witnesses, a BLS key CANNOT be a did:key —
	the did:key multicodec carries no slot for the per-key proof-of-possession
	the rogue-key defense requires (witness.KeysFromDIDs is secp256k1-only).

	So a BLS witness is NOT a genesis did:key witness; it joins the verifying
	set ON-LOG via an BP-ENTRY-WITNESS-ENDPOINT-V1 declaration (SDK v1.54)
	carrying {SchemeTag, PublicKey, ProofOfPossession}, resolved by consumers
	through network.ResolveWitnessKeyAt + crosslog.BuildWitnessSetsForPolicy.
	EndpointDeclaration builds exactly that record.

KEY STORAGE:

	gnark's fr.Element is the BLS private scalar. Go's crypto/x509 cannot
	marshal it, so — mirroring witkey — the key is stored as its raw 32-byte
	big-endian scalar in a PEM envelope and reconstructed via fr.Element.
	A distinct PEM type guards against loading a secp256k1 witkey as BLS.
*/
package blskey

import (
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"
)

// PEMType is the PEM block type for a witness BLS12-381 private key.
// Distinct from witkey.PEMType ("BASEPROOF SECP256K1 PRIVATE KEY") so loading
// a secp256k1 key as BLS (or vice versa) fails loudly at the type check.
const PEMType = "BASEPROOF BLS12381 PRIVATE KEY"

// scalarLen is the fr.Element wire size (the BLS private scalar).
const scalarLen = fr.Bytes // 32

// Generate returns a fresh BLS12-381 keypair (private scalar + G2 public key).
func Generate() (*fr.Element, *bls12381.G2Affine, error) {
	return signatures.GenerateBLSKey()
}

// PubKey derives the G2 public key from a private scalar (sk·G2), matching the
// derivation crypto/cosign.NewBLSWitnessSigner uses for its PubKeyID — so a
// key loaded from disk yields the same on-log identity it signs under.
func PubKey(priv *fr.Element) *bls12381.G2Affine {
	var pk bls12381.G2Affine
	pk.ScalarMultiplicationBase(priv.BigInt(new(big.Int)))
	return &pk
}

// EncodePEM serializes priv as a PEM block carrying its 32-byte big-endian scalar.
func EncodePEM(priv *fr.Element) []byte {
	scalar := priv.Bytes() // [32]byte, canonical big-endian
	return pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: scalar[:]})
}

// LoadPEM reads a witness BLS key from a PEM file.
func LoadPEM(path string) (*fr.Element, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("blskey: read %q: %w", path, err)
	}
	return DecodePEM(data)
}

// DecodePEM parses a witness BLS key from PEM bytes. Fail-closed on a missing
// block, the wrong block type (e.g. a secp256k1 witkey), the wrong scalar
// length, or a non-canonical scalar (≥ the fr modulus).
func DecodePEM(data []byte) (*fr.Element, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("blskey: no PEM block (file empty or malformed)")
	}
	if block.Type != PEMType {
		return nil, fmt.Errorf("blskey: PEM type %q, want %q (regenerate the key — BLS12-381, not secp256k1)", block.Type, PEMType)
	}
	if len(block.Bytes) != scalarLen {
		return nil, fmt.Errorf("blskey: scalar is %d bytes, want %d", len(block.Bytes), scalarLen)
	}
	var priv fr.Element
	if err := priv.SetBytesCanonical(block.Bytes); err != nil {
		return nil, fmt.Errorf("blskey: non-canonical scalar: %w", err)
	}
	return &priv, nil
}

// PubKeyID returns the witness's stable on-log identifier: SHA-256 of the
// 96-byte compressed G2 public key. Identical to the PubKeyID
// crypto/cosign.NewBLSWitnessSigner derives, so consumers resolving by
// PubKeyID bind to the same key this daemon signs under.
func PubKeyID(pub *bls12381.G2Affine) [32]byte {
	return sha256.Sum256(signatures.BLSPubKeyBytes(pub))
}

// EndpointDeclaration builds the on-log BP-ENTRY-WITNESS-ENDPOINT-V1 record by
// which a BLS witness self-declares its key to the network: PubKeyID bound to
// the 96-byte G2 key, a freshly computed 48-byte G1 proof-of-possession, and
// the witness's service endpoints. The returned record is Validate-clean
// (SchemeBLS ⇒ key+PoP present, PubKeyID == SHA-256(PublicKey)); encode it with
// network.EncodeWitnessEndpointDeclarationPayload and submit it on-log so
// auditors/relying parties resolve the witness via network.ResolveWitnessKeyAt.
//
// endpoints must be non-empty (the SDK rejects an endpoint-less declaration) —
// at minimum the witness's own /v1/cosign base URL under an Baseproof service type.
func EndpointDeclaration(priv *fr.Element, endpoints map[string]string) (network.WitnessEndpointDeclaration, error) {
	pub := PubKey(priv)
	pubBytes := signatures.BLSPubKeyBytes(pub)
	pop, err := signatures.SignBLSPoP(pub, priv)
	if err != nil {
		return network.WitnessEndpointDeclaration{}, fmt.Errorf("blskey: proof-of-possession: %w", err)
	}
	d := network.WitnessEndpointDeclaration{
		PubKeyID:          PubKeyID(pub),
		Endpoints:         endpoints,
		SchemeTag:         signatures.SchemeBLS,
		PublicKey:         pubBytes,
		ProofOfPossession: pop,
	}
	if err := d.Validate(); err != nil {
		return network.WitnessEndpointDeclaration{}, fmt.Errorf("blskey: declaration invalid: %w", err)
	}
	return d, nil
}
