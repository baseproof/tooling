/*
[Item 6] The governance-tool K demotion proven THROUGH the cmd itself — not only
at the shared helper (quorum.ReconcileFlagK has its own table test): the built
binary, given a real constitution and a -quorum that disagrees with its
NetworkID-bound genesis_quorum_k, exits non-zero naming both values, BEFORE any
key material or network access is touched. admission-authority is the class
representative; audit and signature-policy funnel through the same helper.
*/
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	sdknetwork "github.com/baseproof/baseproof/network"
)

func TestQuorumFlagMismatch_FatalThroughTheCmd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary; skipped under -short")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "admission-authority")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// A real constitution: 3 witnesses, constitutional K=2.
	dids := make([]string, 3)
	for i := range dids {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		dids[i] = sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)
	}
	doc := sdknetwork.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:item6.example",
		NetworkName:       "item6-net",
		GenesisWitnessSet: dids,
		GenesisQuorumK:    2,
		GenesisTreeHead: sdknetwork.GenesisTreeHead{
			RootHash: strings.Repeat("0", 64),
		},
		GenesisAdmissionPolicy: sdknetwork.GenesisAdmissionPolicy{GatingRequired: false, CostMode: "uncharged"},
		GenesisSignaturePolicy: sdknetwork.SignaturePolicy{
			AllowedEntrySigSchemes: []uint16{1}, AllowedCosignSchemeTags: []uint8{1}, MinSignaturesPerEntry: 1,
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	bsPath := filepath.Join(dir, "bootstrap.json")
	if err := os.WriteFile(bsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// -quorum 3 disagrees with the constitutional 2 → fatal at the reconcile,
	// before -g-key is ever opened (the path below does not exist).
	cmd := exec.Command(bin,
		"-bootstrap", bsPath,
		"-g-key", filepath.Join(dir, "never-opened.key"),
		"-quorum", "3",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a -quorum disagreeing with the constitution must be fatal; output:\n%s", out)
	}
	msg := string(out)
	for _, want := range []string{"disagrees with the constitutional genesis_quorum_k=2", "-quorum"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("fatal message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "never-opened.key") {
		t.Fatalf("the key file was touched — the reconcile must fire first:\n%s", msg)
	}
}
