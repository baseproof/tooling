package gossipverify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

func vgNetworkID() cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 7)
	}
	return nid
}

// vgWitnesses is a K-of-N ECDSA witness keyset plus its signers, for producing
// real cosignatures over tree heads and rotation payloads.
type vgWitnesses struct {
	set     *cosign.WitnessKeySet
	signers []cosign.WitnessSigner
	keys    []types.WitnessPublicKey
	nid     cosign.NetworkID
}

func newVGWitnesses(t *testing.T, n, k int) vgWitnesses {
	t.Helper()
	nid := vgNetworkID()
	keys := make([]types.WitnessPublicKey, n)
	signers := make([]cosign.WitnessSigner, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		signers[i] = cosign.NewECDSAWitnessSigner(priv)
		pub := signatures.PubKeyBytes(&priv.PublicKey)
		keys[i] = types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
	}
	set, err := cosign.NewECDSAWitnessKeySet(keys, nid, k)
	if err != nil {
		t.Fatalf("NewECDSAWitnessKeySet: %v", err)
	}
	return vgWitnesses{set: set, signers: signers, keys: keys, nid: nid}
}

func (w vgWitnesses) cosignedHead(t *testing.T, size uint64, root byte) types.CosignedTreeHead {
	t.Helper()
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{
		TreeSize:    size,
		RootHash:    [32]byte{root},
		SMTRoot:     [32]byte{0xBB},
		ReceiptRoot: [32]byte{0xCC},
	}}
	for _, s := range w.signers {
		sig, err := s.Sign(context.Background(), cosign.NewTreeHeadPayload(head.TreeHead), w.nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("witness Sign: %v", err)
		}
		head.Signatures = append(head.Signatures, sig)
	}
	return head
}

// buildRotation builds a valid SAME-scheme witness rotation cur → newKeys,
// signed by the current witnesses. Same scheme (ECDSA→ECDSA) means no dual-sign
// is required by witness.VerifyRotation.
func (w vgWitnesses) buildRotation(t *testing.T, newKeys []types.WitnessPublicKey) types.WitnessRotation {
	t.Helper()
	payload := cosign.NewRotationPayloadSHA256(witness.ComputeSetHash(newKeys))
	sigs := make([]types.WitnessSignature, 0, len(w.signers))
	for _, s := range w.signers {
		sig, err := s.Sign(context.Background(), payload, w.nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("rotation Sign: %v", err)
		}
		sigs = append(sigs, sig)
	}
	return types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(w.keys),
		NewSet:            newKeys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: sigs,
		SchemeTagNew:      signatures.SchemeECDSA,
	}
}

// wireFinding is the encode-capable finding shape the helper accepts.
type wireFinding interface {
	gossip.Event
	EncodeWireBody() (json.RawMessage, error)
}

// signedEventForFinding wraps a finding's wire body in a gossip.SignedEvent.
// Tier-1 envelope authenticity is exercised separately via stubEnvelope, so the
// envelope signature fields are left empty here.
func signedEventForFinding(t *testing.T, originator string, f wireFinding) gossip.SignedEvent {
	t.Helper()
	raw, err := f.EncodeWireBody()
	if err != nil {
		t.Fatalf("EncodeWireBody: %v", err)
	}
	return gossip.SignedEvent{Kind: f.Kind(), Originator: originator, Body: raw}
}

// stubEnvelope is a test EnvelopeVerifier with a fixed verdict.
type stubEnvelope struct{ err error }

func (s stubEnvelope) VerifyEnvelope(_ context.Context, _ gossip.SignedEvent) error { return s.err }
