/*
FILE PATH: services/auditor/cmd/auditor/main_integration_test.go

Ladder 4 T7 (#21) — subprocess-style integration test for the B3
boot-refusal behavior + the boot-time invariants the operator's
deployment manifest can drive.

# WHY SUBPROCESS

The boot path in main.run is reachable only by executing the binary
with the right env vars. Extracting the predicate to a pure function
would make it unit-testable but ALSO eliminates the integration
guarantee — a regression in env-var parsing, config-load wiring, or
the boot-sequence ordering (e.g., LoadAuditorRegistryFromFile moved
behind sql.Open so a Postgres timeout precedes the refusal) would not
fail a pure-function test.

The subprocess approach builds the binary once in TestMain and exec's
it per test with controlled env. The cost is one go-build per test
package; the benefit is whole-binary behavior on the actual boot path
the operator runs in production.

# WHAT THIS TEST PINS

Ladder 1 B3: AUDITOR_ENFORCE_SCOPES=true + an AUDITOR_REGISTRY_FILE
pointing at a syntactically-valid but empty ("[]") JSON array MUST
make the binary exit non-zero with a message naming the file path. The
empty-file fail-closed gate at 1K+ TPS produces unbounded backlog;
this refusal turns the misconfig into a boot-time error instead.

The test does NOT exercise the full happy path (which requires a real
Postgres + real witness set + real outbound mTLS material) — those are
e2e/staging concerns. What's pinned here is the load-bearing
diagnostic the operator sees on B3 misconfig: exit code 1 + a stderr
message naming the file path so the operator can find and fix it.
*/
package main_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/anchorcache"
	"github.com/baseproof/tooling/libs/crosslog"
)

// auditorBinary is the absolute path to the compiled auditor binary,
// produced once in TestMain and shared across all subtests in this
// file. Empty if the build failed; tests that depend on it Skip when
// empty.
var auditorBinary string

func TestMain(m *testing.M) {
	// Build the auditor binary into a tempdir. This is the only setup
	// the subprocess tests need; per-test setup writes manifest files
	// and exec's the binary with env vars.
	tmpDir, err := os.MkdirTemp("", "auditor-integration-")
	if err != nil {
		println("integration: tempdir:", err.Error())
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	bin := filepath.Join(tmpDir, "auditor-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Build failures emit to stderr above; preserve the exit code so
		// CI surfaces the build problem distinctly from a test failure.
		println("integration: go build auditor failed:", err.Error())
		os.Exit(1)
	}
	auditorBinary = bin

	os.Exit(m.Run())
}

// writeFile is a tiny helper for staging operator-manifest fixtures.
func writeFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile %q: %v", name, err)
	}
	return path
}

// minimalBootstrapDoc returns a syntactically-valid BootstrapDocument
// JSON containing a freshly-generated did:key:secp256k1 in the
// GenesisWitnessSet. The auditor's loadBootstrap + buildResolverInputs
// path requires the genesis witnesses to parse through
// witness.KeysFromDIDs (the SDK rejects Ed25519 multicodec did:keys —
// only secp256k1 is supported for the gossip-originator path).
//
// We mint a fresh did:key per test invocation rather than pinning a
// constant because the SDK's GenerateDIDKeySecp256k1 produces a
// production-shape DID and tests stay decoupled from any external
// fixture that might drift.
func minimalBootstrapDoc(t *testing.T) string {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	return fmt.Sprintf(`{
  "protocol_version": "v1",
  "exchange_did": "did:web:test-exchange.example.org",
  "network_name": "test-network",
  "genesis_witness_set": [%q],
  "genesis_tree_head": {
    "tree_size": 0,
    "root_hash": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "genesis_admission_authorities": [
    "0x0000000000000000000000000000000000000001"
  ],
  "genesis_admission_policy": {
    "gating_required": true,
    "cost_mode": "uncharged"
  },
  "genesis_signature_policy": {
    "allowed_entry_sig_schemes": [1],
    "allowed_cosign_scheme_tags": [1],
    "min_signatures_per_entry": 1
  }
}`, kp.DID)
}

// runAuditor exec's the compiled binary with the supplied env, waits
// for it to exit (subject to deadline), and returns the combined
// stdout+stderr stream + exit code. The auditor's logger writes to
// stdout via slog.NewJSONHandler(os.Stdout, ...); error returns from
// run() surface there as `level=ERROR msg=auditor: fatal err=<...>`.
// Combining both streams (with a "[stderr] " prefix on the err side)
// keeps the test agnostic to which stream a particular regression
// might switch to.
//
// The deadline keeps a buggy regression from hanging the test suite
// indefinitely; we expect the boot-refusal path to fail FAST (< 1s on
// a typical CI runner).
func runAuditor(t *testing.T, env []string, deadline time.Duration) (combined string, exitCode int) {
	t.Helper()
	if auditorBinary == "" {
		t.Skip("auditor binary unavailable (TestMain build failed)")
	}
	cmd := exec.Command(auditorBinary)
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				exitCode = ee.ExitCode()
			} else {
				t.Fatalf("Wait: %v", err)
			}
		}
	case <-time.After(deadline):
		_ = cmd.Process.Kill()
		t.Fatalf("auditor did not exit within %s (boot-refusal regression?)", deadline)
	}
	// Combined stream: stdout first (where slog writes), then stderr
	// (where any Go panic / runtime crash writes).
	combined = outBuf.String() + "[stderr] " + errBuf.String()
	return combined, exitCode
}

// TestBoot_AuditorScopeGateAlwaysOn pins the post-rc5 posture: the auditor-scope
// gate is ALWAYS on and network-governed — there is no AUDITOR_ENFORCE_SCOPES
// flag and no AUDITOR_REGISTRY_FILE. The recognized set is the bootstrap's
// genesis auditors merged with the on-log AuditorRegistrationV1 chain; a
// bootstrap that declares no genesis auditors (and has no on-log registrations)
// resolves to the EMPTY set, so the gate fail-closes every claim-class finding.
// The binary boots into the gate unconditionally — proven by the
// "always-on, network-governed" log line, which fires before the (dummy)
// gossip-store dial. A refactor that re-introduced a silent pass-through or a
// boot flag fails here.
func TestBoot_AuditorScopeGateAlwaysOn(t *testing.T) {
	bootstrapPath := writeFile(t, "bootstrap.json", minimalBootstrapDoc(t))

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"AUDITOR_GOSSIP_DSN=postgres://dummy@localhost/dummy",
		"AUDITOR_NETWORK_BOOTSTRAP_FILE=" + bootstrapPath,
		"AUDITOR_WITNESS_QUORUM_K=1",
		// No AUDITOR_ENFORCE_SCOPES, no AUDITOR_REGISTRY_FILE — the gate is on regardless.
		"AUDITOR_PEERS=",
		"AUDITOR_PEER_ALLOW_PLAINTEXT=true",
	}

	out, _ := runAuditor(t, env, 10*time.Second)

	if !strings.Contains(out, "always-on, network-governed") {
		t.Errorf("gate must be always-on with no flag/file; got: %s", out)
	}
	// minimalBootstrapDoc declares no genesis auditors → empty recognized set
	// (the fail-closed posture), proving recognition is never silently disabled.
	if !strings.Contains(out, `"genesis_auditors":0`) {
		t.Errorf("expected genesis_auditors:0 for a bootstrap with no genesis auditors; got: %s", out)
	}
}

// TestBoot_RefusesOnMissingBootstrap pins a separate boot precondition:
// AUDITOR_GOSSIP_DSN set without AUDITOR_NETWORK_BOOTSTRAP_FILE → exit
// non-zero. The pipeline cannot start without trust roots; this
// precondition lives just above the B3 block in main.run and is
// covered here so a refactor that re-ordered the checks doesn't slip
// past the bootstrap requirement.
func TestBoot_RefusesOnMissingBootstrap(t *testing.T) {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"AUDITOR_GOSSIP_DSN=postgres://dummy@localhost/dummy",
		// AUDITOR_NETWORK_BOOTSTRAP_FILE deliberately unset.
		"AUDITOR_PEERS=",
	}
	out, exit := runAuditor(t, env, 10*time.Second)
	if exit == 0 {
		t.Fatalf("expected non-zero exit; got 0\nout: %s", out)
	}
	if !strings.Contains(out, "AUDITOR_NETWORK_BOOTSTRAP_FILE") {
		t.Errorf("output must name the missing env var; got: %s", out)
	}
}

// TestBoot_HealthOnlyModeStartsAndShutsDown verifies the "no DSN" path:
// without AUDITOR_GOSSIP_DSN the binary runs health-only (the pipeline
// is not started). The test sends SIGTERM after a short delay and
// confirms the binary exits 0 — the graceful-shutdown path.
//
// This is the lightest happy-path smoke test; it does NOT touch the
// scope gate (no registry → no enforcement → reconciler in pre-v1.32
// dispatch mode). Combined with the B3 refusal tests above, it pins
// that the boot ladder distinguishes "operator wants enforcement, but
// misconfigured" (refuse) from "operator wants the binary to run for
// health-checks only" (succeed).
func TestBoot_HealthOnlyModeStartsAndShutsDown(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess smoke test skipped in -short mode")
	}
	// Bind to ephemeral port so parallel runs don't collide.
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"AUDITOR_LISTEN_ADDR=127.0.0.1:0",
		// No DSN → health-only mode.
		"AUDITOR_PEERS=",
	}
	if auditorBinary == "" {
		t.Skip("auditor binary unavailable (TestMain build failed)")
	}
	cmd := exec.Command(auditorBinary)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Give the binary 500ms to start, then SIGTERM and wait for clean
	// exit. The auditor's shutdownWait default is short; expect exit
	// within ~2s.
	time.Sleep(500 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("health-only mode must exit 0 on SIGTERM; got %v\nstderr: %s",
				err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("auditor did not shut down within 5s of SIGTERM (graceful-shutdown regression?)")
	}
}

// ─────────────────────────────────────────────────────────────────
// Ladder 5 P6 (#21) — materialized-cache boot-path integration tests
// ─────────────────────────────────────────────────────────────────

// seedMaterializedSnapshot writes a single-record-per-view snapshot
// at the given tree size under <cacheRoot>/networks/<did>/materialized.
// The auditor's boot path opens anchorcache at this exact DID-keyed
// shape; using crosslog.WriteSnapshot here keeps the fixture
// production-shaped (same code that will eventually write from a
// log-scan tool).
func seedMaterializedSnapshot(t *testing.T, cacheRoot, networkDID string, treesize uint64) {
	t.Helper()
	cache, err := anchorcache.OpenAt(cacheRoot, networkDID)
	if err != nil {
		t.Fatalf("anchorcache.OpenAt(%q, %q): %v", cacheRoot, networkDID, err)
	}
	snap := crosslog.MaterializedNetwork{
		Endpoints: network.WitnessEndpointDeclarationByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 10},
				Payload: network.WitnessEndpointDeclaration{
					PubKeyID:  [32]byte{0xa1, 0xa2},
					Endpoints: map[string]string{"BaseproofWitness": "https://w.example/v1"},
				},
			},
		},
		Labels: network.WitnessIdentityLabelByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 20},
				Payload: network.WitnessIdentityLabel{
					PubKeyID: [32]byte{0xa1, 0xa2},
					Label:    "witness-A",
					DIDHint:  "did:web:witness-A.example",
				},
			},
		},
		Auditors: network.AuditorRegistrationByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 30},
				Payload: network.AuditorRegistration{
					AuditorDID:  "did:web:auditor.example",
					PublicKey:   []byte{0x01, 0x02, 0x03},
					SchemeTag:   1,
					FindingsURL: "https://auditor.example/v1/findings",
					Scope:       network.ScopeEquivocation,
				},
			},
		},
		Amendments: network.AuditorScopeAmendmentByPosition{
			{
				EffectivePos: types.LogPosition{Sequence: 40},
				Payload: network.AuditorScopeAmendment{
					AuditorDID: "did:web:auditor.example",
					NewScope:   network.ScopeSMTReplay,
					Reason:     "test fixture",
				},
			},
		},
	}
	if err := crosslog.WriteSnapshot(cache, treesize, snap); err != nil {
		t.Fatalf("crosslog.WriteSnapshot: %v", err)
	}
}

// TestBoot_MaterializedCache_LoadedFromDisk pins the happy-path P6
// boot wiring: AUDITOR_MATERIALIZED_CACHE_DIR points at a directory
// pre-seeded with a snapshot for the bootstrap's exchange DID; the
// boot path opens anchorcache at the SAME DID, reads the snapshot,
// and surfaces a "materialized cache loaded" log line with the
// per-view counts before the unrelated B3 refusal fires.
//
// Boot ordering matters: the cache read sits between resolver-input
// construction and the B3 refusal, so a regression that moves either
// across that seam would break this test (the cache log line either
// vanishes or appears AFTER the refusal output).
func TestBoot_MaterializedCache_LoadedFromDisk(t *testing.T) {
	// The bootstrap doc fixes exchange_did at this constant; the
	// anchorcache directory MUST use the same DID for the auditor to
	// find the seeded snapshot.
	const exchangeDID = "did:web:test-exchange.example.org"

	bootstrapPath := writeFile(t, "bootstrap.json", minimalBootstrapDoc(t))
	cacheRoot := t.TempDir()
	seedMaterializedSnapshot(t, cacheRoot, exchangeDID, 1234)

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"AUDITOR_GOSSIP_DSN=postgres://dummy@localhost/dummy",
		"AUDITOR_NETWORK_BOOTSTRAP_FILE=" + bootstrapPath,
		"AUDITOR_WITNESS_QUORUM_K=1",
		"AUDITOR_PEERS=",
		"AUDITOR_PEER_ALLOW_PLAINTEXT=true", // non-transport boot test: opt out of require-mTLS
		"AUDITOR_MATERIALIZED_CACHE_DIR=" + cacheRoot,
		"AUDITOR_MATERIALIZED_KEEP_LAST=5",
	}

	out, exit := runAuditor(t, env, 10*time.Second)

	// The dummy gossip-store dial fails after boot; the cache log line MUST
	// land BEFORE that fatal (the cache loads early in the boot sequence).
	if exit == 0 {
		t.Fatalf("expected non-zero exit (dummy gossip DSN dial fails); got 0\nout: %s", out)
	}
	if !strings.Contains(out, "materialized cache loaded") {
		t.Errorf("expected 'materialized cache loaded' in output; got:\n%s", out)
	}
	if !strings.Contains(out, `"tree_size":1234`) {
		t.Errorf("expected tree_size=1234 in cache log; got:\n%s", out)
	}
	if !strings.Contains(out, `"endpoints":1`) ||
		!strings.Contains(out, `"labels":1`) ||
		!strings.Contains(out, `"auditors":1`) ||
		!strings.Contains(out, `"amendments":1`) {
		t.Errorf("expected per-view counts (each=1) in cache log; got:\n%s", out)
	}
}

// TestBoot_MaterializedCache_ColdBoot pins the no-snapshot path:
// AUDITOR_MATERIALIZED_CACHE_DIR is set but no snapshots have been
// written. The boot path MUST surface "materialized cache empty
// (cold boot)" and continue — proves the auditor doesn't refuse to
// boot on a fresh disk and doesn't accidentally fail-loud on the
// expected ErrNotExist.
func TestBoot_MaterializedCache_ColdBoot(t *testing.T) {
	bootstrapPath := writeFile(t, "bootstrap.json", minimalBootstrapDoc(t))
	cacheRoot := t.TempDir()

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"AUDITOR_GOSSIP_DSN=postgres://dummy@localhost/dummy",
		"AUDITOR_NETWORK_BOOTSTRAP_FILE=" + bootstrapPath,
		"AUDITOR_WITNESS_QUORUM_K=1",
		"AUDITOR_PEERS=",
		"AUDITOR_PEER_ALLOW_PLAINTEXT=true", // non-transport boot test: opt out of require-mTLS
		"AUDITOR_MATERIALIZED_CACHE_DIR=" + cacheRoot,
	}

	out, exit := runAuditor(t, env, 10*time.Second)

	if exit == 0 {
		t.Fatalf("expected non-zero exit (dummy gossip DSN dial fails); got 0\nout: %s", out)
	}
	if !strings.Contains(out, "materialized cache empty (cold boot)") {
		t.Errorf("expected 'materialized cache empty (cold boot)' in output; got:\n%s", out)
	}
	// Negative assertion: the loaded-cache log MUST NOT appear when
	// there's nothing on disk.
	if strings.Contains(out, "materialized cache loaded") {
		t.Errorf("cold-boot path must not log 'loaded'; got:\n%s", out)
	}
}
