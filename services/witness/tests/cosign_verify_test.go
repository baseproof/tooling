// FILE PATH: tests/cosign_verify_test.go
//
// Proves the witness↔ledger cosign contract end to end, in process:
// a secp256k1 witness key (generated the way gen-fixtures generates
// one) signs a tree head, and that cosignature verifies against the
// witness set a ledger would build from the witness's did:key via
// witness.KeysFromDIDs.
//
// This is the "real fleet cosigning" guarantee the daemon's black-box
// e2e test does NOT check — that test only asserts the signature is
// non-empty. Here we close the loop cryptographically.
//
// REGRESSION GUARD: witness.KeysFromDIDs accepts secp256k1 did:key
// ONLY. If the witness ever reverts to P-256, KeysFromDIDs rejects the
// DID and this test fails at set construction — long before a broken
// witness reaches a deployment.
package tests

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

func TestWitnessCosignatureVerifiesViaKeysFromDIDs(t *testing.T) {
	// Witness side: a fresh secp256k1 key (same primitive gen-fixtures
	// and the daemon use).
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Derive the did:key the same way gen-fixtures does.
	uncompressed := signatures.PubKeyBytes(&priv.PublicKey)
	compressed, err := signatures.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		t.Fatalf("compress pubkey: %v", err)
	}
	did := sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)

	// Ledger side: build the witness set from the DID alone.
	keys, err := witness.KeysFromDIDs([]string{did})
	if err != nil {
		t.Fatalf("KeysFromDIDs (would reject a P-256 witness): %v", err)
	}

	var nid cosign.NetworkID
	nid[0] = 0x7a // any non-zero network id; signer and set must agree.

	set, err := cosign.NewWitnessKeySet(keys, nid, 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	// Witness signs a tree head over the same NetworkID.
	th := types.TreeHead{
		RootHash:    [32]byte{1, 2, 3},
		SMTRoot:     [32]byte{4, 5, 6},
		ReceiptRoot: [32]byte{}, // empty-batch: zero root is cosigned as-is
		TreeSize:    42,
	}
	signer := cosign.NewECDSAWitnessSigner(priv)
	sig, err := signer.Sign(context.Background(), cosign.NewTreeHeadPayload(th), nid, cosign.HashAlgoSHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	head := types.CosignedTreeHead{TreeHead: th, Signatures: []types.WitnessSignature{sig}}
	if valid := cosign.VerifyTreeHeadCosignatures(head, set); valid != 1 {
		t.Fatalf("valid cosignatures = %d, want 1 (signature did not verify against the KeysFromDIDs set)", valid)
	}
	if set.Quorum() != 1 {
		t.Errorf("quorum = %d, want 1", set.Quorum())
	}

	// Negative control: cosignatures are domain-separated by network,
	// so the same signature must NOT verify under a different
	// NetworkID.
	var other cosign.NetworkID
	other[0] = 0x7b
	otherSet, err := cosign.NewWitnessKeySet(keys, other, 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet(other): %v", err)
	}
	if n := cosign.VerifyTreeHeadCosignatures(head, otherSet); n != 0 {
		t.Errorf("cross-network verify = %d, want 0 (network domain separation broken)", n)
	}
}
