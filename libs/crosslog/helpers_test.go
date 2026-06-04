package crosslog

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
)

// testNetworkID returns a deterministic non-zero cosign NetworkID. A zero
// NetworkID is rejected by the cosign preamble, so every fixture binds to
// this value.
func testNetworkID() cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 1)
	}
	return nid
}

// signedEntry builds a minimal entry whose Header.SignerDID is signer, signs
// sha256(SigningPayload) with priv as a secp256k1 SigAlgoECDSA signature, and
// embeds it — exactly the production embed model. SigningPayload excludes the
// signatures section, so embedding after signing does not change the digest.
func signedEntry(t *testing.T, signer string, priv *ecdsa.PrivateKey) *envelope.Entry {
	t.Helper()
	e := &envelope.Entry{Header: envelope.ControlHeader{SignerDID: signer}}
	digest := sha256.Sum256(envelope.SigningPayload(e))
	sig, err := signatures.SignEntry(digest, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	e.Signatures = []envelope.Signature{{
		SignerDID: signer,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	return e
}

// secpKey returns a fresh secp256k1 private key and its 65-byte uncompressed
// public-key bytes (the rotation-record / initial-key wire shape).
func secpKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, signatures.PubKeyBytes(&priv.PublicKey)
}
