package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkcryptosigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	sdkwitness "github.com/baseproof/baseproof/witness"
)

// TestWitnessKeys_Secp256k1_CosignResolvable is the regression for the
// P-256-witness mismatch: init-network must mint secp256k1 witnesses whose DIDs
// the ledger accepts at boot via witness.KeysFromDIDs (secp256k1-only) and whose
// PEM the tooling witness daemon can load (witkey block type). A P-256 DID
// (the old behaviour) is rejected by KeysFromDIDs.
func TestWitnessKeys_Secp256k1_CosignResolvable(t *testing.T) {
	dir := t.TempDir()
	var dids []string
	for i := 1; i <= 3; i++ {
		path := filepath.Join(dir, fmt.Sprintf("witness-%d.pem", i))
		priv, gen, err := loadOrGenerateWitnessKey(path)
		if err != nil {
			t.Fatalf("generate witness %d: %v", i, err)
		}
		if !gen {
			t.Errorf("witness %d: first call should report generated", i)
		}
		did, err := secp256k1DIDKey(priv)
		if err != nil {
			t.Fatalf("derive witness DID: %v", err)
		}
		if !strings.HasPrefix(did, "did:key:z") {
			t.Errorf("witness DID %q is not a did:key", did)
		}
		dids = append(dids, did)
	}

	// THE regression: the ledger resolves the genesis witness set through this
	// exact call at boot (quorum.LoadWitnessKeys → witness.KeysFromDIDs). P-256
	// DIDs fail here; secp256k1 DIDs pass.
	if _, err := sdkwitness.KeysFromDIDs(dids); err != nil {
		t.Fatalf("witness.KeysFromDIDs rejected init-network witness DIDs (P-256 regression?): %v", err)
	}

	// PEM is witkey-compatible (the witness daemon loads this exact block type).
	raw, err := os.ReadFile(filepath.Join(dir, "witness-1.pem"))
	if err != nil {
		t.Fatalf("read witness PEM: %v", err)
	}
	if !strings.Contains(string(raw), witnessPEMType) {
		t.Errorf("witness PEM block type is not %q:\n%s", witnessPEMType, raw)
	}
	// Idempotent reload.
	if _, gen, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witness-1.pem")); err != nil || gen {
		t.Errorf("reload should be idempotent (generated=%v err=%v)", gen, err)
	}
}

// TestLoadOrGenerateLedgerSignerKey_Idempotent: first call generates + writes a
// 32-byte hex scalar and returns a secp256k1 did:key; a second call loads the
// same file and re-derives the identical DID.
func TestLoadOrGenerateLedgerSignerKey_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger-signer.key")

	did1, gen1, err := loadOrGenerateLedgerSignerKey(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !gen1 {
		t.Error("first call must report generated=true")
	}
	if !strings.HasPrefix(did1, "did:key:z") {
		t.Errorf("did %q is not a did:key", did1)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if dec, derr := hex.DecodeString(strings.TrimSpace(string(raw))); derr != nil || len(dec) != 32 {
		t.Fatalf("key file is not a 32-byte hex scalar (len=%d err=%v)", len(dec), derr)
	}

	did2, gen2, err := loadOrGenerateLedgerSignerKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if gen2 {
		t.Error("second call must report generated=false (idempotent)")
	}
	if did2 != did1 {
		t.Errorf("reload did = %q, want %q", did2, did1)
	}
}

// TestLedgerSignerKey_MatchesLedgerLoader proves cross-tool consistency: the hex
// init-network writes is loadable by the LEDGER's exact loader primitive
// (signatures.PrivKeyFromBytes) and derives the SAME did:key the ledger computes
// (PubKeyBytes → CompressSecp256k1Pubkey → EncodeDIDKey/secp256k1). If these
// drift, the ledger would advertise a different originator than init-network
// printed and gossip verification would break.
func TestLedgerSignerKey_MatchesLedgerLoader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger-signer.key")
	genDID, _, err := loadOrGenerateLedgerSignerKey(path)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	scalar, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}

	// Exactly what cmd/ledger loadOrGenerateLedgerSigner + didKeyFromSecp256k1Priv do.
	priv, err := sdkcryptosigs.PrivKeyFromBytes(scalar)
	if err != nil {
		t.Fatalf("PrivKeyFromBytes (ledger loader primitive): %v", err)
	}
	uncompressed := sdkcryptosigs.PubKeyBytes(&priv.PublicKey)
	compressed, err := sdkcryptosigs.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		t.Fatalf("CompressSecp256k1Pubkey: %v", err)
	}
	ledgerDID := sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)

	if ledgerDID != genDID {
		t.Fatalf("ledger-derived did %q != init-network did %q — generator/loader drift", ledgerDID, genDID)
	}
}

// TestBuildBootstrapDoc_PassesGenesisValidation is the regression for the
// init-network bug shipped in v1.52.0: the doc omitted GenesisSignaturePolicy,
// which the SDK requires since v1.31 (it is hashed into the NetworkID, and
// validate() rejects the empty zero value as an "admit-nothing" policy). The
// tool wrote its keys fine, then exited non-zero on doc.IDs() — so it could not
// bootstrap a network at all (in any gating mode). This builds the same document
// main() builds and asserts it passes the SDK's validation.
func TestBuildBootstrapDoc_PassesGenesisValidation(t *testing.T) {
	dir := t.TempDir()
	priv, _, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witness-1.pem"))
	if err != nil {
		t.Fatalf("witness key: %v", err)
	}
	did, err := secp256k1DIDKey(priv)
	if err != nil {
		t.Fatalf("witness DID: %v", err)
	}
	addr, _, err := loadOrGenerateAdmissionAuthority(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatalf("admission authority: %v", err)
	}

	for _, gating := range []string{"off", "require"} {
		doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", gating, []string{did}, addr, 1)
		// doc.IDs() runs the SDK's validate() — exactly init-network's gate. A
		// missing genesis_signature_policy fails here, which is the regression.
		if _, err := doc.IDs(); err != nil {
			t.Fatalf("gating=%s: bootstrap failed SDK validation "+
				"(regression: genesis_signature_policy must be set): %v", gating, err)
		}
		if len(doc.GenesisSignaturePolicy.AllowedEntrySigSchemes) == 0 ||
			len(doc.GenesisSignaturePolicy.AllowedCosignSchemeTags) == 0 {
			t.Fatalf("gating=%s: genesis_signature_policy not populated", gating)
		}
	}
}

// TestBuildBootstrapDoc_MinSignaturesConfigurable pins the -min-signatures
// surface: a configured floor threads into GenesisSignaturePolicy and survives
// the SDK's NetworkID-deriving validation, while a 0 floor is rejected by
// doc.IDs() (network.validateGenesisSignaturePolicy). The CLI's own [1, 64]
// guard is the first line; this asserts the SDK floor binds even if that guard
// were bypassed — the "always > 0" guarantee is locked into the NetworkID.
func TestBuildBootstrapDoc_MinSignaturesConfigurable(t *testing.T) {
	dir := t.TempDir()
	priv, _, err := loadOrGenerateWitnessKey(filepath.Join(dir, "witnesses", "witness-1.pem"))
	if err != nil {
		t.Fatalf("witness key: %v", err)
	}
	did, err := secp256k1DIDKey(priv)
	if err != nil {
		t.Fatalf("witness DID: %v", err)
	}
	addr, _, err := loadOrGenerateAdmissionAuthority(filepath.Join(dir, "admission.key"))
	if err != nil {
		t.Fatalf("admission authority: %v", err)
	}

	// A configured non-default floor threads through and validates.
	doc := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", []string{did}, addr, 3)
	if got := doc.GenesisSignaturePolicy.MinSignaturesPerEntry; got != 3 {
		t.Fatalf("MinSignaturesPerEntry = %d, want 3 (flag did not thread)", got)
	}
	if _, err := doc.IDs(); err != nil {
		t.Fatalf("min-signatures=3 must pass SDK validation: %v", err)
	}

	// A 0 floor is rejected by the SDK at NetworkID derivation, regardless of
	// the CLI guard — this is the genesis half of the "always > 0" invariant.
	zero := buildBootstrapDoc("did:web:state:tn:davidson", "clarity-test", "require", []string{did}, addr, 0)
	if _, err := zero.IDs(); err == nil {
		t.Fatal("min-signatures=0 must be rejected by doc.IDs() (admit-unsigned floor)")
	}
}
