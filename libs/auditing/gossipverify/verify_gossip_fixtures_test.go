package gossipverify

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"
)

func vgNetworkID() cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 7)
	}
	return nid
}

// vgWitnesses is a K-of-N ECDSA witness keyset plus its signers, for producing
// real cosignatures over tree heads and rotation payloads. Backed by the SDK
// fixture kit; set/keys alias the kit's fields, signers wrap its private keys.
type vgWitnesses struct {
	ws      *witnesstest.Set
	set     *cosign.WitnessKeySet
	signers []cosign.WitnessSigner
	keys    []types.WitnessPublicKey
	nid     cosign.NetworkID
}

func newVGWitnesses(t *testing.T, n, k int) vgWitnesses {
	t.Helper()
	nid := vgNetworkID()
	ws := witnesstest.NewSet(t, nid, n, k)
	signers := make([]cosign.WitnessSigner, n)
	for i, priv := range ws.Privs {
		signers[i] = cosign.NewECDSAWitnessSigner(priv)
	}
	return vgWitnesses{ws: ws, set: ws.KeySet, signers: signers, keys: ws.Keys, nid: nid}
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

// buildRotation mints a valid SAME-scheme witness rotation w → next through
// the production assembly path: every current witness authorizes and every
// joiner countersigns (Step-6 consent). It takes the TARGET KIT (not bare
// keys) because consent requires the new set's private keys; a rotation to
// the same kit has zero joiners and is valid once minted.
func (w vgWitnesses) buildRotation(t *testing.T, next vgWitnesses) types.WitnessRotation {
	t.Helper()
	return witnesstest.MintRotation(t, w.nid, w.ws, next.ws, len(w.keys))
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
