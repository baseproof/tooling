package main

/*
kinds_test.go — the kind seam (#77 DoD): the one-shot signs EXACTLY the payload
kind it was asked for, refuses kinds it does not understand, and the
genesis-auditor leg verifies the declaration (DID present AND public key
matching the held key) before signing. New consent kinds extend the switch
explicitly; nothing falls through.
*/

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

// writeAuditorConstitution writes an unendorsed require constitution declaring
// one genesis auditor (the supplied key) and one witness, returning paths/ids.
func writeAuditorConstitution(t *testing.T, dir string) (bootstrapPath, auditorKeyPath, auditorDID, witnessKeyPath string) {
	t.Helper()
	wKey, wDID := mkWitness(t, dir, "w1")
	aPriv, err := witkey.Generate()
	if err != nil {
		t.Fatalf("auditor keygen: %v", err)
	}
	auditorKeyPath = filepath.Join(dir, "auditor.pem")
	if err := os.WriteFile(auditorKeyPath, witkey.EncodePEM(aPriv), 0o600); err != nil {
		t.Fatalf("write auditor key: %v", err)
	}
	aPub, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&aPriv.PublicKey))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	auditorDID = "did:web:auditor.example"

	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:kinds.example",
		NetworkName:       "kinds-net",
		GenesisWitnessSet: []string{wDID},
		GenesisQuorumK:    1,
		GenesisTreeHead:   network.GenesisTreeHead{RootHash: strings.Repeat("0", 64)},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: false, CostMode: "uncharged",
		},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes: []uint16{1}, AllowedCosignSchemeTags: []uint8{1}, MinSignaturesPerEntry: 1,
		},
		GenesisEndorsementPolicy: network.GenesisEndorsementRequire,
		GenesisAuditors: []network.GenesisAuditor{{
			AuditorDID:  auditorDID,
			PublicKey:   hex.EncodeToString(aPub),
			SchemeTag:   1,
			FindingsURL: "https://auditor.example/findings",
			Scope:       1,
		}},
		GenesisAuditorEndorsementPolicy: network.GenesisEndorsementRequire,
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bootstrapPath = filepath.Join(dir, "unendorsed.json")
	if err := os.WriteFile(bootstrapPath, body, 0o644); err != nil {
		t.Fatalf("write unendorsed: %v", err)
	}
	return bootstrapPath, auditorKeyPath, auditorDID, wKey
}

func TestEndorse_UnknownKindRefused(t *testing.T) {
	dir := t.TempDir()
	bootstrapPath, _, _, wKey := writeAuditorConstitution(t, dir)
	if _, _, err := endorse(wKey, bootstrapPath, "rotation-consent", ""); err == nil {
		t.Fatal("an unknown endorsement kind was signed — the kind seam must refuse, not guess")
	} else if !strings.Contains(err.Error(), "unknown endorsement kind") {
		t.Fatalf("refusal came from the wrong place: %v", err)
	}
}

func TestEndorse_AuditorKind_FullCeremonySeals(t *testing.T) {
	dir := t.TempDir()
	bootstrapPath, aKey, aDID, wKey := writeAuditorConstitution(t, dir)

	we, _, err := endorse(wKey, bootstrapPath, kindGenesisWitness, "")
	if err != nil {
		t.Fatalf("witness endorse: %v", err)
	}
	ae, _, err := endorse(aKey, bootstrapPath, kindGenesisAuditor, aDID)
	if err != nil {
		t.Fatalf("auditor endorse: %v", err)
	}

	raw, _ := os.ReadFile(bootstrapPath)
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	doc.GenesisEndorsements = []network.GenesisEndorsement{we}
	doc.GenesisAuditorEndorsements = []network.GenesisEndorsement{ae}
	served, err := network.EndorsedBootstrapBytes(doc)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := network.LoadSelfVerifiedBootstrap(served); err != nil {
		t.Fatalf("witness+auditor ceremony failed first contact: %v", err)
	}
}

func TestEndorse_AuditorKind_Refusals(t *testing.T) {
	dir := t.TempDir()
	bootstrapPath, aKey, aDID, wKey := writeAuditorConstitution(t, dir)

	// Missing -auditor-did.
	if _, _, err := endorse(aKey, bootstrapPath, kindGenesisAuditor, ""); err == nil {
		t.Fatal("auditor endorse without -auditor-did was signed")
	}
	// A DID not in the declaration.
	if _, _, err := endorse(aKey, bootstrapPath, kindGenesisAuditor, "did:web:imposter.example"); err == nil {
		t.Fatal("an undeclared auditor DID was endorsed")
	}
	// The declared DID but the WRONG key (the witness's): the declaration's
	// public key must match the held key.
	if _, _, err := endorse(wKey, bootstrapPath, kindGenesisAuditor, aDID); err == nil {
		t.Fatal("an endorsement was signed under a declaration whose key does not match")
	} else if !strings.Contains(err.Error(), "DIFFERENT public key") {
		t.Fatalf("key-mismatch refusal came from the wrong place: %v", err)
	}
}
