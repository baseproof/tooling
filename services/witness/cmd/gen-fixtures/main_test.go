// FILE PATH: cmd/gen-fixtures/main_test.go
//
// Unit tests for the gen-fixtures CLI's core function. Each test
// runs against t.TempDir() — no network, no daemon.
package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/witness/internal/blskey"
	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

// devNull discards all writes — used to silence run()'s stdout
// during tests without polluting test output.
func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// testSecp256k1DIDKey mints a fresh secp256k1 did:key (did:key:zQ3s…) — the shape
// gen-fixtures decodes for a -genesis-auditor-did.
func testSecp256k1DIDKey(t *testing.T) string {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)
}

// A -genesis-auditor-did is decoded into a valid genesis_auditors entry (DID,
// public key from the did:key, ECDSA, non-zero scope, findings URL), and the
// resulting bootstrap canonicalizes (mints a NetworkID) cleanly.
func TestRun_GenesisAuditors_Emitted(t *testing.T) {
	dir := t.TempDir()
	auditorDID := testSecp256k1DIDKey(t)
	const url = "https://auditor.example/v1/findings"
	if err := run(dir, "", defaultLogDID, defaultNetworkName, 1, "ecdsa", auditorDID, url, "require", devNull(t)); err != nil {
		t.Fatalf("run: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "network-bootstrap.json"))
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse bootstrap: %v", err)
	}
	if len(doc.GenesisAuditors) != 1 {
		t.Fatalf("genesis_auditors = %d, want 1", len(doc.GenesisAuditors))
	}
	ga := doc.GenesisAuditors[0]
	if ga.AuditorDID != auditorDID {
		t.Errorf("auditor_did = %q, want %q", ga.AuditorDID, auditorDID)
	}
	if ga.FindingsURL != url {
		t.Errorf("findings_url = %q, want %q", ga.FindingsURL, url)
	}
	if ga.SchemeTag != 0x01 {
		t.Errorf("scheme_tag = %d, want 1 (ECDSA)", ga.SchemeTag)
	}
	if ga.Scope == 0 {
		t.Error("scope must be non-zero (recognized for at least one finding kind)")
	}
	if _, err := doc.IDs(); err != nil {
		t.Fatalf("bootstrap with genesis auditor must canonicalize: %v", err)
	}
}

// -genesis-auditor-did without a findings URL is a hard config error (the SDK
// requires a non-empty URL on every auditor registration).
func TestRun_GenesisAuditors_RequireFindingsURL(t *testing.T) {
	if err := run(t.TempDir(), "", defaultLogDID, defaultNetworkName, 1, "ecdsa", testSecp256k1DIDKey(t), "", "require", devNull(t)); err == nil {
		t.Fatal("expected error: -genesis-auditor-did set without -genesis-auditor-findings-url")
	}
}

// A non-secp256k1 did:key cannot be an ECDSA genesis auditor — rejected.
func TestRun_GenesisAuditors_RejectsNonSecp256k1(t *testing.T) {
	if err := run(t.TempDir(), "", defaultLogDID, defaultNetworkName, 1, "ecdsa",
		"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", "https://x.example/f", "require", devNull(t)); err == nil {
		t.Fatal("expected error for a non-secp256k1 (ed25519) genesis auditor did:key")
	}
}

func TestRun_SingleWitness_HappyPath(t *testing.T) {
	dir := t.TempDir()
	err := run(dir, "", defaultLogDID, defaultNetworkName, 1, "ecdsa", "", "", "require", devNull(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	keyPath := filepath.Join(dir, "witnesses", "witness-1.pem")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key at %s: %v", keyPath, err)
	}

	bsPath := filepath.Join(dir, "network-bootstrap.json")
	body, err := os.ReadFile(bsPath)
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal bootstrap: %v", err)
	}
	if len(doc.GenesisWitnessSet) != 1 {
		t.Errorf("GenesisWitnessSet len = %d, want 1", len(doc.GenesisWitnessSet))
	}
	if doc.NetworkName != defaultNetworkName {
		t.Errorf("NetworkName = %q, want %q", doc.NetworkName, defaultNetworkName)
	}
	if doc.ExchangeDID != defaultLogDID {
		t.Errorf("ExchangeDID = %q, want %q", doc.ExchangeDID, defaultLogDID)
	}
	if _, err := doc.IDs(); err != nil {
		t.Errorf("doc.IDs() rejected the produced bootstrap: %v", err)
	}
}

func TestRun_MultiWitness(t *testing.T) {
	dir := t.TempDir()
	const n = 3
	if err := run(dir, "", defaultLogDID, defaultNetworkName, n, "ecdsa", "", "", "require", devNull(t)); err != nil {
		t.Fatalf("run: %v", err)
	}
	for i := 1; i <= n; i++ {
		p := filepath.Join(dir, "witnesses", "witness-"+itoa(i)+".pem")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected key at %s: %v", p, err)
		}
	}
	body, err := os.ReadFile(filepath.Join(dir, "network-bootstrap.json"))
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.GenesisWitnessSet) != n {
		t.Errorf("GenesisWitnessSet len = %d, want %d", len(doc.GenesisWitnessSet), n)
	}
	seen := map[string]bool{}
	for _, did := range doc.GenesisWitnessSet {
		if !strings.HasPrefix(did, "did:key:z") {
			t.Errorf("witness DID %q does not start with did:key:z", did)
		}
		if seen[did] {
			t.Errorf("duplicate DID in GenesisWitnessSet: %q", did)
		}
		seen[did] = true
	}
}

func TestRun_Idempotent_PreservesKeys(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "", defaultLogDID, defaultNetworkName, 2, "ecdsa", "", "", "require", devNull(t)); err != nil {
		t.Fatalf("first run: %v", err)
	}
	keyPath := filepath.Join(dir, "witnesses", "witness-1.pem")
	first, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key after first run: %v", err)
	}
	// Second run with same args — keys must not be regenerated.
	if err := run(dir, "", defaultLogDID, defaultNetworkName, 2, "ecdsa", "", "", "require", devNull(t)); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key after second run: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("witness key changed across runs — idempotency broken")
	}
}

func TestRun_RejectsZeroWitnesses(t *testing.T) {
	if err := run(t.TempDir(), "", defaultLogDID, defaultNetworkName, 0, "ecdsa", "", "", "require", devNull(t)); err == nil {
		t.Fatal("expected error for -witnesses=0")
	}
}

func TestRun_RejectsEmptyLogDID(t *testing.T) {
	if err := run(t.TempDir(), "", "", defaultNetworkName, 1, "ecdsa", "", "", "require", devNull(t)); err == nil {
		t.Fatal("expected error for empty -log-did")
	}
}

func TestRun_RejectsEmptyNetworkName(t *testing.T) {
	if err := run(t.TempDir(), "", defaultLogDID, "", 1, "ecdsa", "", "", "require", devNull(t)); err == nil {
		t.Fatal("expected error for empty -network-name")
	}
}

func TestRun_CustomBootstrapPath(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "sub", "custom-bootstrap.json")
	if err := run(dir, custom, defaultLogDID, defaultNetworkName, 1, "ecdsa", "", "", "require", devNull(t)); err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("expected bootstrap at custom path %s: %v", custom, err)
	}
}

// The witness keys + DIDs must be secp256k1 — the Baseproof witness/cosign
// curve — AND the generated genesis DIDs must resolve through the SAME SDK
// function the ledger calls (witness.KeysFromDIDs). This is the regression
// guard for the P-256 did:key the ledger previously rejected with
// "x coordinate not on the secp256k1 curve".
func TestRun_GeneratedKeysAreSecp256k1AndLedgerResolvable(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "", defaultLogDID, defaultNetworkName, 2, "ecdsa", "", "", "require", devNull(t)); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Key file is a witkey secp256k1 PEM, not a stdlib P-256 "EC PRIVATE KEY".
	body, err := os.ReadFile(filepath.Join(dir, "witnesses", "witness-1.pem"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != witkey.PEMType {
		t.Fatalf("PEM type = %v, want %q", block, witkey.PEMType)
	}
	if _, err := witkey.DecodePEM(body); err != nil {
		t.Fatalf("decode secp256k1 key: %v", err)
	}

	// The bootstrap's genesis witness DIDs resolve via the ledger-side
	// resolver — the exact path that failed before this fix.
	bootstrap, err := os.ReadFile(filepath.Join(dir, "network-bootstrap.json"))
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(bootstrap, &doc); err != nil {
		t.Fatalf("unmarshal bootstrap: %v", err)
	}
	keys, err := witness.KeysFromDIDs(doc.GenesisWitnessSet)
	if err != nil {
		t.Fatalf("ledger-side witness.KeysFromDIDs rejected generated DIDs: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("resolved %d witness keys, want 2", len(keys))
	}
}

// TestRun_BLSScheme pins -scheme=bls: the bootstrap admits cosign scheme 0x02
// alongside ECDSA, the genesis set is a resolvable ECDSA anchor, and each BLS
// witness key loads as a blskey (the witnesses join the verifying set on-log).
func TestRun_BLSScheme(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "", defaultLogDID, defaultNetworkName, 2, "bls", "", "", "require", devNull(t)); err != nil {
		t.Fatalf("run(bls): %v", err)
	}

	var doc network.BootstrapDocument
	body, err := os.ReadFile(filepath.Join(dir, "network-bootstrap.json"))
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal bootstrap: %v", err)
	}
	// BLS admitted (0x02) alongside ECDSA (0x01).
	if got := doc.GenesisSignaturePolicy.AllowedCosignSchemeTags; len(got) != 2 || got[0] != 0x01 || got[1] != 0x02 {
		t.Fatalf("AllowedCosignSchemeTags = %v, want [1 2]", got)
	}
	// Genesis set is the resolvable ECDSA anchor.
	if _, err := witness.KeysFromDIDs(doc.GenesisWitnessSet); err != nil {
		t.Fatalf("genesis anchor must resolve via KeysFromDIDs: %v", err)
	}
	if _, err := witkey.LoadPEM(filepath.Join(dir, "witnesses", "genesis-anchor.pem")); err != nil {
		t.Fatalf("anchor must be a secp256k1 witkey: %v", err)
	}
	// Each BLS witness key loads as a blskey (joins on-log, not in genesis set).
	for i := 1; i <= 2; i++ {
		path := filepath.Join(dir, "witnesses", fmt.Sprintf("witness-%d.bls.pem", i))
		if _, err := blskey.LoadPEM(path); err != nil {
			t.Fatalf("bls witness #%d must load as a BLS key: %v", i, err)
		}
	}
}

func TestRun_RejectsUnknownScheme(t *testing.T) {
	if err := run(t.TempDir(), "", defaultLogDID, defaultNetworkName, 1, "rsa", "", "", "require", devNull(t)); err == nil {
		t.Fatal("unknown -scheme must be rejected")
	}
}

// itoa is a tiny stdlib-free int→string used so test loops don't
// pull in strconv solely for fixture names.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Compile-time check that devNull's return value satisfies the
// stdout argument's io.Writer-via-*os.File contract.
var _ io.Writer = (*os.File)(nil)

// TestRun_FixtureIsBornEndorsed pins #77 A6: the default mint binds the require
// policy into the NetworkID, self-endorses N-of-N with the keys it minted, and
// the WRITTEN file passes the self-pin first-contact door — so a JN/e2e network
// bootstrapped from fixtures clears the same gate as a production mint.
func TestRun_FixtureIsBornEndorsed(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "", defaultLogDID, defaultNetworkName, 3, "ecdsa", "", "", "require", devNull(t)); err != nil {
		t.Fatalf("run: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "network-bootstrap.json"))
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	doc, err := network.LoadSelfVerifiedBootstrap(raw)
	if err != nil {
		t.Fatalf("fixture failed the self-pin first-contact door: %v", err)
	}
	if !doc.RequiresEndorsement() {
		t.Fatal("fixture is not require-policy — A6 demands fixtures born endorsed")
	}
	if len(doc.GenesisEndorsements) != 3 {
		t.Fatalf("fixture carries %d endorsements, want 3 (N-of-N)", len(doc.GenesisEndorsements))
	}
}

// TestRun_EndorsementPolicyOff keeps the escape hatch honest: "off" emits no
// policy and no endorsements, and the file still loads.
func TestRun_EndorsementPolicyOff(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "", defaultLogDID, defaultNetworkName, 1, "ecdsa", "", "", "off", devNull(t)); err != nil {
		t.Fatalf("run: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "network-bootstrap.json"))
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	doc, err := network.LoadSelfVerifiedBootstrap(raw)
	if err != nil {
		t.Fatalf("off-policy fixture failed first contact: %v", err)
	}
	if doc.RequiresEndorsement() || len(doc.GenesisEndorsements) != 0 {
		t.Fatal("off policy leaked a require policy or endorsements")
	}
}
