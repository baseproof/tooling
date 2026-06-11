package networkbundle

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

func testBootstrap(t *testing.T) (*network.BootstrapDocument, string) {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	doc := &network.BootstrapDocument{
		ProtocolVersion: "1", ExchangeDID: "did:web:exchange.example", NetworkName: "tooling-test",
		GenesisWitnessSet:           []string{kp.DID},
		GenesisQuorumK:              1, // REQUIRED since rc4; N=1 ⇒ K=1 (2K>N)
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy:      network.SignaturePolicy{AllowedEntrySigSchemes: []uint16{0x0001}, AllowedCosignSchemeTags: []uint8{0x01}, MinSignaturesPerEntry: 1},
	}
	return doc, kp.DID
}

func TestBuild_GenesisOnly(t *testing.T) {
	doc, did0 := testBootstrap(t)
	nb, err := Build(doc, "https://ledger.example:8443", Vocabulary{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if nb.Endpoint != "https://ledger.example:8443" {
		t.Errorf("endpoint = %q", nb.Endpoint)
	}
	if nb.TrustRoot.QuorumK != 1 {
		t.Errorf("quorumK = %d, want 1", nb.TrustRoot.QuorumK)
	}
	if len(nb.TrustRoot.GenesisWitnessDIDs) != 1 || nb.TrustRoot.GenesisWitnessDIDs[0] != did0 {
		t.Errorf("witness DIDs = %v, want [%s]", nb.TrustRoot.GenesisWitnessDIDs, did0)
	}
	if nb.Witnesses == nil || nb.Witnesses.Size() != 1 {
		t.Errorf("witness set not derived from the bootstrap")
	}
	if nb.Citable() {
		t.Error("a genesis-only bundle (no CitedMemberKey) must not be citable")
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if nb.TrustRoot.BootstrapDocumentHash != sha256.Sum256(canonical) {
		t.Error("BootstrapDocumentHash != sha256(canonical bytes)")
	}
}

func TestBuild_WithVocabulary(t *testing.T) {
	doc, _ := testBootstrap(t)
	key := [32]byte{0xAB}
	sr := types.LogPosition{LogDID: "did:web:net", Sequence: 30}
	nb, err := Build(doc, "https://x", Vocabulary{
		GovernanceSchemas:    map[string]types.LogPosition{"signature_policy_chain": {LogDID: "did:web:net", Sequence: 12}},
		SignerRotationSchema: &sr,
		CitedMemberKey:       key,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !nb.Citable() || nb.CitedMemberKey != key {
		t.Errorf("citable=%v key=%x, want citable with key %x", nb.Citable(), nb.CitedMemberKey, key)
	}
	if nb.SignerRotationSchema == nil || *nb.SignerRotationSchema != sr {
		t.Errorf("signer rotation schema not carried")
	}
}

func TestBuild_NilDoc(t *testing.T) {
	if _, err := Build(nil, "https://x", Vocabulary{}); err == nil {
		t.Error("Build(nil) should error")
	}
}

// TestBuild_QuorumFromConstitution pins K single-sourcing (#74): the produced
// bundle's QuorumK — in the trust root AND the derived witness key set — is the
// constitutional doc.GenesisQuorumK, with no caller-supplied K to disagree.
func TestBuild_QuorumFromConstitution(t *testing.T) {
	dids := make([]string, 3)
	for i := range dids {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		dids[i] = kp.DID
	}
	doc := &network.BootstrapDocument{
		ProtocolVersion: "1", ExchangeDID: "did:web:exchange.example", NetworkName: "tooling-test",
		GenesisWitnessSet:           dids,
		GenesisQuorumK:              2, // constitutional K; N=3 ⇒ 2K>N
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy:      network.SignaturePolicy{AllowedEntrySigSchemes: []uint16{0x0001}, AllowedCosignSchemeTags: []uint8{0x01}, MinSignaturesPerEntry: 1},
	}
	nb, err := Build(doc, "https://ledger.example:8443", Vocabulary{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if nb.TrustRoot.QuorumK != doc.GenesisQuorumK {
		t.Errorf("TrustRoot.QuorumK = %d, want the constitutional %d", nb.TrustRoot.QuorumK, doc.GenesisQuorumK)
	}
	if nb.Witnesses.Quorum() != doc.GenesisQuorumK {
		t.Errorf("witness set quorum = %d, want the constitutional %d", nb.Witnesses.Quorum(), doc.GenesisQuorumK)
	}
}
