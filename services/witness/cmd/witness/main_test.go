// FILE PATH: main_test.go
//
// Unit tests for the witness daemon's two file-loaders. Both run
// against on-disk fixtures under t.TempDir(); no network, no
// running daemon.
//
// The main() function itself isn't unit-tested directly because
// it owns flag.Parse + signal.NotifyContext + ListenAndServe —
// pure I/O composition. tests/daemon_e2e_test.go covers the
// full flag-to-listen path via os/exec + http.Client.
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/witness/internal/witkey"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
)

// writePEMKey writes a fresh secp256k1 witness key (witkey PEM) to path —
// the Baseproof witness/cosign curve the daemon loads.
func writePEMKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := witkey.Generate()
	if err != nil {
		t.Fatalf("witkey.Generate: %v", err)
	}
	if err := os.WriteFile(path, witkey.EncodePEM(priv), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return priv
}

// ─────────────────────────────────────────────────────────────────
// loadECPrivateKey
// ─────────────────────────────────────────────────────────────────

func TestLoadECPrivateKey_HappyPath(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "witness.pem")
	want := writePEMKey(t, keyPath)

	got, err := loadECPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("loadECPrivateKey: %v", err)
	}
	if got.D.Cmp(want.D) != 0 {
		t.Errorf("loaded key D differs from written key — round-trip broken")
	}
}

func TestLoadECPrivateKey_FileNotExist(t *testing.T) {
	_, err := loadECPrivateKey(filepath.Join(t.TempDir(), "missing.pem"))
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadECPrivateKey_EmptyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(keyPath, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	_, err := loadECPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error on empty PEM file")
	}
}

func TestLoadECPrivateKey_BadPEM(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(keyPath, []byte("not a pem block"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	_, err := loadECPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error on malformed PEM")
	}
}

func TestLoadECPrivateKey_RejectsNonECPEM(t *testing.T) {
	// Valid PEM block but wrong type.
	keyPath := filepath.Join(t.TempDir(), "wrong-type.pem")
	body := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte{0x30, 0x82, 0x01, 0x00},
	})
	if err := os.WriteFile(keyPath, body, 0o600); err != nil {
		t.Fatalf("write wrong-type: %v", err)
	}
	_, err := loadECPrivateKey(keyPath)
	if err == nil {
		t.Fatal("expected error on non-EC PEM")
	}
}

// ─────────────────────────────────────────────────────────────────
// loadBootstrap
// ─────────────────────────────────────────────────────────────────

// validBootstrapJSON returns a minimal valid network bootstrap
// document body. The DID list is intentionally non-empty — empty
// genesis_witness_set is rejected by the SDK's IDs() validator,
// which the standalone-witness daemon calls at boot.
func validBootstrapJSON(t *testing.T) []byte {
	t.Helper()
	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:test-ledger.example",
		NetworkName:       "unit-test",
		GenesisWitnessSet: []string{"did:key:z6MkUnitTestWitness"},
		GenesisQuorumK:    1, // REQUIRED since rc4; N=1 ⇒ K=1 (2K>N)
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: false,
			CostMode:       "uncharged",
		},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal valid bootstrap: %v", err)
	}
	return body
}

func TestLoadBootstrap_HappyPath(t *testing.T) {
	bsPath := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(bsPath, validBootstrapJSON(t), 0o644); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}

	doc, err := loadBootstrap(bsPath)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	if doc.NetworkName != "unit-test" {
		t.Errorf("doc.NetworkName = %q, want unit-test", doc.NetworkName)
	}
	if len(doc.GenesisWitnessSet) != 1 {
		t.Errorf("doc.GenesisWitnessSet len = %d, want 1", len(doc.GenesisWitnessSet))
	}
}

func TestLoadBootstrap_FileNotExist(t *testing.T) {
	_, err := loadBootstrap(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatal("expected error on missing file")
	}
}

func TestLoadBootstrap_BadJSON(t *testing.T) {
	bsPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bsPath, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	_, err := loadBootstrap(bsPath)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestLoadBootstrap_DerivesNonZeroNetworkID(t *testing.T) {
	bsPath := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(bsPath, validBootstrapJSON(t), 0o644); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}
	doc, err := loadBootstrap(bsPath)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	identity, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs(): %v", err)
	}
	var zero [32]byte
	if identity.NetworkID == zero {
		t.Fatal("derived NetworkID is zero — SDK contract broken")
	}
}

// ─────────────────────────────────────────────────────────────────────
// #75 Phase B — fail-closed first contact with the mounted constitution
// ─────────────────────────────────────────────────────────────────────

// mintRequireBootstrap writes a require-policy constitution (single witness key
// held by the test) to disk in BOTH forms: fully endorsed, and STRIPPED of its
// endorsements (the canonical-only strip-attack shape — the policy survives
// inside the canonical bytes; the endorsements do not).
func mintRequireBootstrap(t *testing.T) (endorsedPath, strippedPath string) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:phaseb.example",
		NetworkName:       "phaseb-require",
		GenesisWitnessSet: []string{sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)},
		GenesisQuorumK:    1,
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		GenesisAdmissionPolicy:   network.GenesisAdmissionPolicy{GatingRequired: false, CostMode: "uncharged"},
		GenesisSignaturePolicy:   network.SignaturePolicy{AllowedEntrySigSchemes: []uint16{1}, AllowedCosignSchemeTags: []uint8{1}, MinSignaturesPerEntry: 1},
		GenesisEndorsementPolicy: network.GenesisEndorsementRequire,
	}
	end, err := network.EndorseGenesis(doc, priv)
	if err != nil {
		t.Fatalf("EndorseGenesis: %v", err)
	}
	doc.GenesisEndorsements = []network.GenesisEndorsement{end}

	dir := t.TempDir()
	served, err := network.EndorsedBootstrapBytes(doc)
	if err != nil {
		t.Fatalf("EndorsedBootstrapBytes: %v", err)
	}
	endorsedPath = filepath.Join(dir, "endorsed.json")
	if err := os.WriteFile(endorsedPath, served, 0o644); err != nil {
		t.Fatal(err)
	}
	stripped, err := doc.CanonicalBytes() // policy inside, endorsements gone
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	strippedPath = filepath.Join(dir, "stripped.json")
	if err := os.WriteFile(strippedPath, stripped, 0o644); err != nil {
		t.Fatal(err)
	}
	return endorsedPath, strippedPath
}

// TestLoadBootstrap_RequireCeremonyVerified [#75-B]: the witness boots a
// require constitution whose ceremony verifies — and REFUSES the same
// constitution stripped of its endorsements (a witness must not cosign for a
// network whose constitution it cannot verify).
func TestLoadBootstrap_RequireCeremonyVerified(t *testing.T) {
	endorsed, stripped := mintRequireBootstrap(t)

	if _, err := loadBootstrap(endorsed); err != nil {
		t.Fatalf("endorsed require constitution must load: %v", err)
	}
	if _, err := loadBootstrap(stripped); err == nil {
		t.Fatal("STRIPPED require constitution loaded — the strip attack boots a witness silently")
	}
}

// TestLoadBootstrap_LegacyPolicyBootsWithoutCeremony [#75-B]: a constitution
// with no endorsement policy keeps booting with no endorsements — the opt-out
// stays honest.
func TestLoadBootstrap_LegacyPolicyBootsWithoutCeremony(t *testing.T) {
	raw := validBootstrapJSON(t)
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBootstrap(path); err != nil {
		t.Fatalf("legacy (no-policy) constitution must keep booting: %v", err)
	}
}
