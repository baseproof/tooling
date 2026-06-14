// FILE PATH: tests/witness_env_test.go
//
// Witness discovery for the at-scale validation profiles (soak,
// determinism). These profiles do NOT orchestrate a witness tier.
//
// PRE-11 Phase B (#114) RETIRED the env-driven witness dial-list
// (LEDGER_WITNESS_ENDPOINTS). The production cosigner now resolves
// witness URLs ONLY from on-log WitnessEndpointDeclaration records via
// witnessclient.WitnessEndpointResolver — there is no config dial-list
// to discover, and a static env list would be the silent-URL-substitution
// bypass that change closed. So env-based witness discovery is no longer
// possible: cosignerFromEnv now always reports NON-WITNESS.
//
// The hermetic in-process fixture path (newWitnessedTestHarnessN, wired
// through staticEndpointResolver) remains the way integration tests
// exercise the K-of-N cosign path.
package tests

import (
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// cosignerFromEnv previously built a *witnessclient.HeadSync from the
// LEDGER_WITNESS_* env contract. That contract was deleted in PRE-11
// Phase B (the on-log resolver is the SOLE witness-endpoint source), so
// there is nothing left to discover from the environment: this helper now
// always returns (nil, false) — the at-scale profiles run NON-WITNESS.
//
// The signature is retained so the soak / determinism harness call sites
// (which assign the result to the builder.WitnessCosigner interface ONLY
// when enabled is true) need no change; they simply never see enabled.
func cosignerFromEnv(t *testing.T, _ *pgxpool.Pool, _ *slog.Logger) (*witnessclient.HeadSync, bool) {
	t.Helper()
	t.Logf("WITNESS: env-based witness discovery (LEDGER_WITNESS_ENDPOINTS) was " +
		"retired in PRE-11 Phase B — witness URLs now resolve only from on-log " +
		"WitnessEndpointDeclaration records. Running NON-WITNESS. Use the in-process " +
		"witnessed harness (newWitnessedTestHarnessN) to exercise the K-of-N cosign path.")
	return nil, false
}
