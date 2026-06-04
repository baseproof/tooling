// slasher_positionaware_test.go — proves the position-aware fallback closes the
// historical-equivocation-unslashed gap (ZT-SCN-02, slashing path): an
// equivocation cosigned by a since-rotated set that is ABSENT from the static
// WitnessSets is silently dropped by the legacy slasher, but slashed when a
// position-aware resolver supplies the era-correct reconstructed set.
package equivocation

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

func slNetworkID() cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 11)
	}
	return nid
}

type slWitnesses struct {
	set     *cosign.WitnessKeySet
	signers []cosign.WitnessSigner
	nid     cosign.NetworkID
}

func newSlWitnesses(t *testing.T, n, k int) slWitnesses {
	t.Helper()
	nid := slNetworkID()
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
	return slWitnesses{set: set, signers: signers, nid: nid}
}

func (w slWitnesses) cosignedHead(t *testing.T, size uint64, root byte) types.CosignedTreeHead {
	t.Helper()
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{
		TreeSize: size, RootHash: [32]byte{root}, SMTRoot: [32]byte{0xBB}, ReceiptRoot: [32]byte{0xCC},
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

// stubEraResolver returns a fixed set for any SetAt — models reconstruction
// resolving the historic era set.
type stubEraResolver struct {
	set *cosign.WitnessKeySet
	err error
}

func (r stubEraResolver) SetAt(context.Context, string, types.LogPosition) (*cosign.WitnessKeySet, error) {
	return r.set, r.err
}

func TestSlasher_PositionAware_SlashesHistoricalEquivocation(t *testing.T) {
	const n, k = 3, 2
	historic := newSlWitnesses(t, n, k) // cosigned the equivocation; since rotated away
	modern := newSlWitnesses(t, n, k)   // the only set in the static config

	const endpoint = "https://ledger.davidson.example/court"
	const targetLog = "did:web:davidson.log"

	mkFinding := func() *findings.EquivocationFinding {
		proof := witness.EquivocationProof{
			TreeSize:   100,
			HeadA:      historic.cosignedHead(t, 100, 0xAA),
			HeadB:      historic.cosignedHead(t, 100, 0xBB),
			ValidSigsA: n, ValidSigsB: n,
		}
		f, err := findings.NewEquivocationFinding(proof, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		f.TargetLogDID = targetLog
		return f
	}

	// Legacy (static-only): the historic equivocation fails against the modern
	// set and is SILENTLY DROPPED — the ledger goes unslashed.
	blind, err := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{targetLog: modern.set},
		Threshold:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := blind.Apply(context.Background(), mkFinding()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if blind.IsSlashed(endpoint) {
		t.Fatal("static-only slasher slashed a historic equivocation it cannot verify — unexpected")
	}

	// Position-aware: the resolver supplies the historic era set → slashed.
	aware, err := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{targetLog: modern.set},
		Resolver:    stubEraResolver{set: historic.set},
		Threshold:   1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := aware.Apply(context.Background(), mkFinding()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !aware.IsSlashed(endpoint) {
		t.Fatal("position-aware slasher must slash a historical equivocation via the reconstructed era set")
	}
}
