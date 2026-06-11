package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkdid "github.com/baseproof/baseproof/did"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// fakeStandaloneGather implements sdkbundle.StandaloneGather with a REAL genesis
// bootstrap (so the embedded-trust derivation is exercised) and canned proof
// sections (so no live ledger is needed). The canned sections carry no real
// cosignatures — which is exactly the point of the Zero-Trust test below.
type fakeStandaloneGather struct {
	doc     *network.BootstrapDocument
	quorumK int
}

func (f *fakeStandaloneGather) FetchGenesisBootstrap(context.Context) (*network.BootstrapDocument, int, error) {
	return f.doc, f.quorumK, nil
}
func (f *fakeStandaloneGather) FetchEntry(context.Context, uint64) ([]byte, time.Time, error) {
	return []byte("entry-wire-bytes"), time.Unix(1700000000, 0).UTC(), nil
}
func (f *fakeStandaloneGather) FetchCosignedHead(context.Context, uint64) (types.CosignedTreeHead, error) {
	return types.CosignedTreeHead{}, nil
}
func (f *fakeStandaloneGather) FetchInclusionProof(context.Context, uint64, uint64) (types.MerkleProof, error) {
	return types.MerkleProof{}, nil
}
func (f *fakeStandaloneGather) FetchSMTProof(context.Context, uint64, [32]byte) (types.SMTProof, error) {
	return types.SMTProof{}, nil
}
func (f *fakeStandaloneGather) FetchWitnessRotationChain(context.Context, uint64) ([]sdkbundle.RotationElement, error) {
	return nil, nil
}

func mustBootstrapDoc(t *testing.T) *network.BootstrapDocument {
	t.Helper()
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("gen witness key: %v", err)
	}
	return &network.BootstrapDocument{
		ProtocolVersion:             "1",
		ExchangeDID:                 "did:web:exchange.example",
		NetworkName:                 "verify-test-net",
		GenesisWitnessSet:           []string{kp.DID},
		GenesisQuorumK:              1, // REQUIRED since rc4; N=1 ⇒ K=1 (2K>N)
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
}

// TestVerify_V2_ZeroTrust is the headline Zero-Trust property: a v2 proof that is
// structurally well-formed (round-trips through Encode/Decode) but carries NO
// real cosignatures MUST be rejected — fail-closed. It also pins the decode, the
// embedded-trust-root derivation, the --pin mismatch path, and malformed input.
func TestVerify_V2_ZeroTrust(t *testing.T) {
	ctx := context.Background()
	doc := mustBootstrapDoc(t)

	proof, err := sdkbundle.BuildStandalone(ctx, &fakeStandaloneGather{doc: doc, quorumK: 1}, 1)
	if err != nil {
		t.Fatalf("BuildStandalone: %v", err)
	}
	if proof.Format != sdkbundle.FormatV2 {
		t.Fatalf("format = %q, want v2", proof.Format)
	}

	// Serialize → file (the portable artifact); confirm a lossless v2 round-trip.
	raw, err := sdkbundle.EncodeStandalone(proof)
	if err != nil {
		t.Fatalf("EncodeStandalone: %v", err)
	}
	dec, err := sdkbundle.DecodeStandalone(raw)
	if err != nil {
		t.Fatalf("DecodeStandalone: %v", err)
	}
	if dec.Format != sdkbundle.FormatV2 || dec.NetworkID != proof.NetworkID {
		t.Fatalf("round-trip changed the proof: format=%q nid=%x", dec.Format, dec.NetworkID)
	}

	path := filepath.Join(t.TempDir(), "x.proof")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// ZERO TRUST: no real cosignatures ⇒ MUST fail closed.
	if _, _, err := verifyProofFile(ctx, path, ""); err == nil {
		t.Error("a proof with no real cosignatures verified — ZT / fail-closed is broken")
	}

	// The embedded-trust derivation works (network id from the proof's own
	// bootstrap), even though the proof then fails the crypto gate.
	tr, derr := trustRootFromProof(dec)
	if derr != nil {
		t.Fatalf("derive trust root: %v", derr)
	}
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc IDs: %v", err)
	}
	if _, ok := tr[cosign.NetworkID(ids.NetworkID)]; !ok {
		t.Errorf("derived trust root is missing the proof's own network id")
	}

	// --pin to a different network fails closed before any crypto.
	if _, _, err := verifyProofFile(ctx, path, strings.Repeat("00", 32)); err == nil {
		t.Error("pin mismatch was accepted — fail-closed broken")
	}

	// Malformed bytes ⇒ decode error.
	bad := filepath.Join(t.TempDir(), "bad.proof")
	_ = os.WriteFile(bad, []byte("not a proof"), 0o644)
	if _, _, err := verifyProofFile(ctx, bad, ""); err == nil {
		t.Error("malformed proof was accepted")
	}
}
