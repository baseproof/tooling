// FILE PATH: libs/witnessrotation/internal/rottest/rottest.go
//
// Shared rotation-test fixtures for the witnessrotation packages' suites.
// Everything trust-shaped comes from the SDK's blessed kit (witnesstest) or
// the SDK's own signing primitives — these helpers only assemble, never
// re-derive a production recipe.
package rottest

import (
	"crypto/ecdsa"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

// NetID is a fixed non-zero network id (NewWitnessKeySet rejects zero).
func NetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// CosignHead produces a K-of-N cosigned tree head signed by the supplied set's
// private keys — a real witness-cosigned head for verify steps.
func CosignHead(
	t *testing.T, head types.TreeHead,
	keys []types.WitnessPublicKey, privs []*ecdsa.PrivateKey, sigCount int, netID cosign.NetworkID,
) types.CosignedTreeHead {
	t.Helper()
	payload := cosign.NewTreeHeadPayload(head)
	sigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sb, err := cosign.SignECDSA(payload, netID, cosign.HashAlgoSHA256, privs[i])
		if err != nil {
			t.Fatalf("SignECDSA head: %v", err)
		}
		sigs[i] = types.WitnessSignature{
			PubKeyID:  keys[i].ID,
			SchemeTag: signatures.SchemeECDSA,
			SigBytes:  sb,
		}
	}
	return types.CosignedTreeHead{TreeHead: head, Signatures: sigs}
}

// FullTreeHead returns a TreeHead with all commitment roots populated —
// cosign's dual-commitment binding rejects an all-zero RootHash/SMTRoot.
func FullTreeHead(size uint64) types.TreeHead {
	return types.TreeHead{
		RootHash:    [32]byte{0x01, 0xC0, 0x5C},
		SMTRoot:     [32]byte{0x02, 0x5A, 0x7B},
		ReceiptRoot: [32]byte{0x03, 0x4C, 0x7D},
		TreeSize:    size,
	}
}
