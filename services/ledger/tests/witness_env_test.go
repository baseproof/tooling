// FILE PATH: tests/witness_env_test.go
//
// Env-driven witness DISCOVERY for the at-scale validation profiles
// (soak, determinism). These profiles do NOT orchestrate a witness
// tier — they find an externally-run one through the SAME env contract
// the production ledger consumes (cmd/ledger/config.go,
// cmd/ledger/boot/wire/gossip.go::wireWitnessCosigner):
//
//	LEDGER_WITNESS_ENDPOINTS      CSV of witness cosign base URLs
//	LEDGER_WITNESS_QUORUM_K       K threshold (default 1)
//	LEDGER_NETWORK_BOOTSTRAP_FILE bootstrap JSON → NetworkID binding
//
// Stand a fleet up yourself (e.g. the tooling repo (services/witness)'s
// run-local.sh) and export the vars; the test connects to it. When
// LEDGER_WITNESS_ENDPOINTS is unset the run is NON-WITNESS: a warning
// is logged and enabled=false. Quorum is the intended default, but its
// absence is a warning, not a failure (per the validation contract).
package tests

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"

	opstore "github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// cosignerFromEnv builds a *witnessclient.HeadSync from the LEDGER_WITNESS_*
// env contract. Returns (cosigner, true) when LEDGER_WITNESS_ENDPOINTS is
// set; (nil, false) — after logging a NON-WITNESS warning — when it is not.
//
// Callers MUST assign the result to the builder.WitnessCosigner interface
// ONLY when enabled is true; passing a typed-nil *HeadSync would defeat the
// builder loop's `witness != nil` guard (builder/loop.go).
func cosignerFromEnv(t *testing.T, pool *pgxpool.Pool, logger *slog.Logger) (*witnessclient.HeadSync, bool) {
	t.Helper()

	endpoints := splitWitnessCSV(os.Getenv("LEDGER_WITNESS_ENDPOINTS"))
	if len(endpoints) == 0 {
		t.Logf("WITNESS: LEDGER_WITNESS_ENDPOINTS unset — running NON-WITNESS (no quorum). " +
			"Export LEDGER_WITNESS_ENDPOINTS (+ LEDGER_NETWORK_BOOTSTRAP_FILE and optional " +
			"LEDGER_WITNESS_QUORUM_K) pointing at an already-running witness fleet to exercise " +
			"the K-of-N cosign path.")
		return nil, false
	}

	quorumK := 1
	if v := os.Getenv("LEDGER_WITNESS_QUORUM_K"); v != "" {
		k, err := strconv.Atoi(v)
		if err != nil || k < 1 {
			t.Fatalf("WITNESS: LEDGER_WITNESS_QUORUM_K=%q must be a positive integer: %v", v, err)
		}
		quorumK = k
	}
	if quorumK > len(endpoints) {
		t.Fatalf("WITNESS: LEDGER_WITNESS_QUORUM_K=%d exceeds endpoint count %d", quorumK, len(endpoints))
	}

	netID := networkIDFromBootstrapEnv(t)

	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  endpoints,
		QuorumK:           quorumK,
		PerWitnessTimeout: 30 * time.Second,
		NetworkID:         netID,
		HTTPClient:        newTunedHTTPClient(30 * time.Second),
	}, opstore.NewTreeHeadStore(pool), logger)
	if err != nil {
		t.Fatalf("WITNESS: NewHeadSync(%v): %v", endpoints, err)
	}
	t.Logf("WITNESS: quorum enabled — %d endpoint(s), K=%d, networkID=%x…",
		len(endpoints), quorumK, netID[:8])
	return hs, true
}

// networkIDFromBootstrapEnv parses LEDGER_NETWORK_BOOTSTRAP_FILE into the
// cosign.NetworkID the witness fleet was provisioned with. The file is
// REQUIRED whenever LEDGER_WITNESS_ENDPOINTS is set — same rule the
// production config enforces (cmd/ledger/config.go).
func networkIDFromBootstrapEnv(t *testing.T) cosign.NetworkID {
	t.Helper()
	path := os.Getenv("LEDGER_NETWORK_BOOTSTRAP_FILE")
	if path == "" {
		t.Fatalf("WITNESS: LEDGER_NETWORK_BOOTSTRAP_FILE is required when LEDGER_WITNESS_ENDPOINTS is set")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("WITNESS: read bootstrap %q: %v", path, err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("WITNESS: parse bootstrap %q: %v", path, err)
	}
	identity, err := doc.IDs()
	if err != nil {
		t.Fatalf("WITNESS: bootstrap %q IDs(): %v", path, err)
	}
	return identity.NetworkID
}

// splitWitnessCSV splits a comma-separated env value, trimming blanks.
func splitWitnessCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
