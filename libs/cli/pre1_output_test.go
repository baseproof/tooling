/*
FILE PATH: libs/cli/pre1_output_test.go

DESCRIPTION:

	PRE-1's machine-output contract, pinned end to end:

	  - ONE envelope ({schema_version, kind, data}) on stdout for every read
	    verb's --output json; an unknown --output value is a usage error;
	  - the five read verbs emit their kinds with correct data: verify,
	    network-list (with pin + active status surfaced), network-show,
	    witnesses (against a live stub), info (against the fake network —
	    identity matching the fake's id);
	  - stdout purity holds: json mode emits EXACTLY the envelope (the
	    PRE-0b stderr discipline keeps informational chatter out);
	  - verify's exit-code CLASSES: a valid proof verifies (and emits the
	    envelope); a pin mismatch and an uncosigned proof are
	    ErrVerificationFailed (exit 1: the proof is the problem); a missing
	    file and malformed bytes are ErrVerifyUsage (exit 2: the invocation
	    is the problem).
*/
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
)

// captureStdout runs fn and returns everything it wrote to stdout.
func captureStdout(t *testing.T, fn func() error) ([]byte, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return out, runErr
}

// decodeEnvelope asserts the one-envelope contract and returns data bytes.
func decodeEnvelope(t *testing.T, out []byte, wantKind string) json.RawMessage {
	t.Helper()
	var env struct {
		SchemaVersion string          `json:"schema_version"`
		Kind          string          `json:"kind"`
		Data          json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("stdout is not ONE json envelope: %v\n%s", err, out)
	}
	if env.SchemaVersion != EnvelopeSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", env.SchemaVersion, EnvelopeSchemaVersion)
	}
	if env.Kind != wantKind {
		t.Fatalf("kind = %q, want %q", env.Kind, wantKind)
	}
	return env.Data
}

func TestEmitOutput_UnknownModeIsUsageError(t *testing.T) {
	err := emitOutput("yaml", "x", nil, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "table|json") {
		t.Fatalf("unknown --output must name the contract: %v", err)
	}
}

// ─── network list / show ─────────────────────────────────────────────

func TestNetworkList_JSONEnvelope(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatal(err)
	}
	// A legacy, unpinned network beside it.
	if err := saveNetwork("legacy", &ClientBundle{NetworkID: strings.Repeat(pinIDb, 32), Endpoint: "https://b1"}); err != nil {
		t.Fatal(err)
	}
	if err := setActiveNetwork("alpha"); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error {
		return RunNetwork(context.Background(), []string{"list", "--output=json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var data NetworkListData
	if err := json.Unmarshal(decodeEnvelope(t, out, "network-list"), &data); err != nil {
		t.Fatal(err)
	}
	if data.Active != "alpha" || len(data.Networks) != 2 {
		t.Fatalf("data = %+v", data)
	}
	byName := map[string]NetworkListEntry{}
	for _, e := range data.Networks {
		byName[e.Name] = e
	}
	if !byName["alpha"].Pinned || !byName["alpha"].Active || byName["alpha"].NetworkID != strings.Repeat(pinIDa, 32) {
		t.Errorf("alpha entry = %+v", byName["alpha"])
	}
	if byName["legacy"].Pinned || byName["legacy"].Active {
		t.Errorf("legacy entry = %+v", byName["legacy"])
	}
}

func TestNetworkShow_JSONEnvelope(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return RunNetwork(context.Background(), []string{"show", "--output=json", "alpha"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var data NetworkShowData
	if err := json.Unmarshal(decodeEnvelope(t, out, "network-show"), &data); err != nil {
		t.Fatal(err)
	}
	if data.Name != "alpha" || !data.Pinned || data.PinNetworkID != strings.Repeat(pinIDa, 32) ||
		data.Bundle == nil || data.Bundle.Endpoint != "https://a1" {
		t.Fatalf("data = %+v", data)
	}
}

// ─── witnesses ───────────────────────────────────────────────────────

func TestWitnesses_JSONEnvelope(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/current", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(wireWitnessSetFull{
			SetHash: strings.Repeat("cd", 32), SchemeTag: 1, EffectiveSeq: 0,
			Keys: []wireWitnessKeyFull{{ID: strings.Repeat("ab", 32), PublicKey: "02aa", SchemeTag: 1}},
		})
	})
	srv := httptest.NewServer(mux) // labels 404s — tolerated as optional
	defer srv.Close()

	path := writeBundle(t, ClientBundle{NetworkID: strings.Repeat(pinIDa, 32), Endpoint: srv.URL})
	out, err := captureStdout(t, func() error {
		return RunWitnesses(context.Background(), []string{"--bundle", path, "--output=json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var data WitnessesData
	if err := json.Unmarshal(decodeEnvelope(t, out, "witnesses"), &data); err != nil {
		t.Fatal(err)
	}
	if data.Scope != "current" || data.SetHash != strings.Repeat("cd", 32) ||
		len(data.Witnesses) != 1 || data.Witnesses[0].ID != strings.Repeat("ab", 32) {
		t.Fatalf("data = %+v", data)
	}
}

// ─── info ────────────────────────────────────────────────────────────

func TestInfo_JSONEnvelope(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	fake := newFakeNet(t, nil, false)
	path := writeBundle(t, ClientBundle{
		NetworkID: fake.nid, Endpoint: fake.url, LogDID: "did:web:test-log",
		QuorumK: 1, BootstrapHash: fake.nid, // the pin IS the id (J6)
	})
	out, err := captureStdout(t, func() error {
		return RunInfo(context.Background(), []string{"--bundle", path, "--output=json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Endpoint string `json:"endpoint"`
		Identity struct {
			NetworkID string `json:"network_id"`
		} `json:"identity"`
		QuorumK int `json:"quorum_k"`
	}
	if err := json.Unmarshal(decodeEnvelope(t, out, "info"), &data); err != nil {
		t.Fatal(err)
	}
	if data.Endpoint != fake.url || data.Identity.NetworkID != fake.nid || data.QuorumK != 1 {
		t.Fatalf("data = %+v (fake nid %s)", data, fake.nid)
	}
}

// ─── verify: envelope + the exit-code classes ────────────────────────

func TestVerify_JSONEnvelope_RealProof(t *testing.T) {
	ctx := context.Background()
	g, _, seq := mustRealGather(t, 3, 2)
	proof, err := generateProof(ctx, g, seq)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "real.proof")
	if err := writeProofFile(proof, path); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error {
		return RunVerify(ctx, []string{"--output=json", path})
	})
	if err != nil {
		t.Fatalf("a real proof must verify: %v", err)
	}
	var data VerifyData
	if err := json.Unmarshal(decodeEnvelope(t, out, "verify"), &data); err != nil {
		t.Fatal(err)
	}
	if !data.Verified || data.QuorumNeed != 2 || data.QuorumHave < 2 || data.NetworkID == "" || data.Pinned {
		t.Fatalf("data = %+v", data)
	}
	if len(data.Sections) == 0 {
		t.Error("verified_sections must list what was checked")
	}
}

func TestVerify_ExitCodeClasses(t *testing.T) {
	ctx := context.Background()
	doc := mustBootstrapDoc(t)
	proof, err := sdkbundle.BuildStandalone(ctx, &fakeStandaloneGather{doc: doc}, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sdkbundle.EncodeStandalone(proof)
	if err != nil {
		t.Fatal(err)
	}
	uncosigned := filepath.Join(t.TempDir(), "uncosigned.proof")
	if err := os.WriteFile(uncosigned, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	// THE PROOF IS THE PROBLEM (exit 1): failed crypto, and pin mismatch.
	if err := RunVerify(ctx, []string{uncosigned}); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("an uncosigned proof is a VERIFICATION failure: %v", err)
	}
	if err := RunVerify(ctx, []string{"--pin", strings.Repeat("00", 32), uncosigned}); !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("a pin mismatch is a VERIFICATION failure: %v", err)
	}

	// THE INVOCATION IS THE PROBLEM (exit 2): missing file, malformed bytes,
	// malformed pin, bad usage.
	if err := RunVerify(ctx, []string{filepath.Join(t.TempDir(), "absent.proof")}); !errors.Is(err, ErrVerifyUsage) {
		t.Errorf("a missing file is a USAGE failure: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.proof")
	_ = os.WriteFile(bad, []byte("not a proof"), 0o644)
	if err := RunVerify(ctx, []string{bad}); !errors.Is(err, ErrVerifyUsage) {
		t.Errorf("malformed bytes are a USAGE failure: %v", err)
	}
	if err := RunVerify(ctx, []string{"--pin", "zz", uncosigned}); !errors.Is(err, ErrVerifyUsage) {
		t.Errorf("a malformed --pin is a USAGE failure: %v", err)
	}
	if err := RunVerify(ctx, []string{}); !errors.Is(err, ErrVerifyUsage) {
		t.Errorf("no arguments is a USAGE failure: %v", err)
	}
}
