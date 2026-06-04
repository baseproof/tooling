/*
FILE PATH: libs/keystore/signer/signer.go

DESCRIPTION:

	keys/v1.Signer adapter that wraps any keystore.KeyStore and
	exposes a controlling-EOA-shaped Sign + Address surface for
	external SCW party signing flows.

	Why this exists
	───────────────
	The SDK's keys/v1.Signer interface is defined for
	Baseproof-Smart-Contract-Wallet (SCW) party signers — every
	isValidSignature path on the SCW recovers an EOA from a 65-byte
	Ethereum-format (r || s || v) signature. Production deployments
	custody the controlling key in Vault Transit or a SoftHSM token,
	not on disk; this adapter is the seam that lets external SCW
	flows route Sign(digest) calls through whichever custody backend
	the deployment chose.

	Wire-shape translation
	──────────────────────
	keystore.KeyStore.SignSecp256k1 returns 65-byte SignCompact
	[v+27 || r || s] (the wire format Privy emits and the SDK
	consumes for Baseproof log-entry envelopes). The SCW path wants
	Ethereum-format [r || s || v]. The two encodings carry the same
	information; the adapter byte-swaps without re-signing.

	Address derivation
	──────────────────
	Address is derived once at New time via signatures.AddressFromPubkey
	over the keystore's stored 65-byte uncompressed public key. The
	keystore's public key is fetched once (the constructor performs
	the only PublicKeySecp256k1 round-trip); subsequent Sign calls
	bypass the public-key fetch.
*/
package signer

import (
	"fmt"

	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
	keysv1 "github.com/baseproof/baseproof/keys/v1"

	"github.com/baseproof/tooling/libs/keystore"
)

// Adapter is a keys/v1.Signer backed by a keystore.KeyStore + a DID.
// One Adapter per (keystore, DID) pair — the address is cached at
// construction so Sign is a single keystore round-trip.
type Adapter struct {
	ks   keystore.KeyStore
	did  string
	addr keysv1.EthereumAddressBytes
}

// New constructs an Adapter. Performs one PublicKeySecp256k1 round-
// trip against the keystore to derive the EOA address. Returns an
// error if the keystore has no secp256k1 key for the DID.
func New(ks keystore.KeyStore, did string) (*Adapter, error) {
	if ks == nil {
		return nil, fmt.Errorf("signer: nil keystore")
	}
	if did == "" {
		return nil, fmt.Errorf("signer: empty DID")
	}
	pub, err := ks.PublicKey(did)
	if err != nil {
		return nil, fmt.Errorf("signer: PublicKey: %w", err)
	}
	addr, err := sdksigs.AddressFromPubkey(pub)
	if err != nil {
		return nil, fmt.Errorf("signer: AddressFromPubkey: %w", err)
	}
	return &Adapter{ks: ks, did: did, addr: addr}, nil
}

// Sign produces a 65-byte Ethereum-format (r || s || v) signature
// over the given 32-byte digest, suitable for an SCW's
// isValidSignature recovery. The keystore signs in SignCompact
// [v+27 || r || s] form; we byte-swap to Ethereum order without
// re-signing.
func (a *Adapter) Sign(digest [32]byte) ([]byte, error) {
	if a == nil || a.ks == nil {
		return nil, fmt.Errorf("signer: nil Adapter")
	}
	compact, err := a.ks.Sign(a.did, digest)
	if err != nil {
		return nil, fmt.Errorf("signer: Sign: %w", err)
	}
	if len(compact) != 65 {
		return nil, fmt.Errorf("signer: Sign returned %d bytes, want 65", len(compact))
	}
	out := make([]byte, sdksigs.EthereumSignatureLen)
	copy(out[0:32], compact[1:33])   // r
	copy(out[32:64], compact[33:65]) // s
	out[64] = compact[0]             // v (27 or 28)
	return out, nil
}

// Address returns the controlling EOA's 20-byte Ethereum address.
// Stable across the Adapter's lifetime.
func (a *Adapter) Address() keysv1.EthereumAddressBytes {
	if a == nil {
		var zero keysv1.EthereumAddressBytes
		return zero
	}
	return a.addr
}

// DID returns the keystore-side DID this Adapter was bound to. Useful
// for diagnostics; the caller usually doesn't need it.
func (a *Adapter) DID() string {
	if a == nil {
		return ""
	}
	return a.did
}

// Compile-time check that Adapter satisfies keys/v1.Signer.
var _ keysv1.Signer = (*Adapter)(nil)
