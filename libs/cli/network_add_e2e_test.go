package cli

/*
network_add_e2e_test.go — #75 residual (item 2): the strip attack, pinned at
COMMAND altitude.

The strip-attack coverage that shipped with #75 was unit-level
(TestFetchBootstrap_StripAttackRefused drives fetchBootstrap directly). No
end-to-end path ever ran the actual `network add --from-ledger` command against a
require network — endorsed OR stripped. These tests close that: they stand a
ledger up (the two endpoints `network add --from-ledger` reads — /v1/network/
identity and /v1/network/bootstrap) serving a REQUIRE constitution, and drive the
real RunNetwork command end to end.

  - endorsed serve  → `network add` AUTHORS and stores the bundle (exit 0);
  - stripped serve  → `network add` REFUSES (the strip attack is dead at the
    command, not just at the fetch helper).

Optional endpoints (/v1/log-info, /v1/network/peers) 404; getJSONOptional
tolerates that by typed status, so the command path runs on the two endpoints
that matter.
*/

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveRequireLedger stands up the minimal ledger surface `network add
// --from-ledger` introspects: /v1/network/identity (the network id it pins the
// served bootstrap against) and /v1/network/bootstrap (the constitution, served
// here in whichever form the test chose — endorsed or stripped).
func serveRequireLedger(t *testing.T, bootstrapBody []byte, networkIDHex string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/identity", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"network_id":     networkIDHex,
			"network_did":    "did:bp:" + networkIDHex,
			"bootstrap_hash": networkIDHex,
		})
	})
	mux.HandleFunc("GET /v1/network/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bootstrapBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestNetworkAdd_FromLedger_RequireEndorsed_EndToEnd: the positive end-to-end
// path — a require network whose ledger serves the ENDORSED constitution is
// authored and stored by the real `network add --from-ledger` command.
func TestNetworkAdd_FromLedger_RequireEndorsed_EndToEnd(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	endorsed, _, pin := mintRequireNetwork(t)
	srv := serveRequireLedger(t, endorsed, pin)

	err := RunNetwork(context.Background(), []string{"add", "--from-ledger", srv.URL, "require-endorsed"})
	if err != nil {
		t.Fatalf("`network add --from-ledger` rejected an ENDORSED require network end to end: %v", err)
	}
}

// TestNetworkAdd_FromLedger_RequireStripped_EndToEnd: the strip attack at command
// altitude — a require network whose ledger serves the constitution WITHOUT its
// endorsements is refused by the real `network add --from-ledger` command, not
// just by the fetch helper.
func TestNetworkAdd_FromLedger_RequireStripped_EndToEnd(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	_, stripped, pin := mintRequireNetwork(t)
	srv := serveRequireLedger(t, stripped, pin)

	err := RunNetwork(context.Background(), []string{"add", "--from-ledger", srv.URL, "require-stripped"})
	if err == nil {
		t.Fatal("`network add --from-ledger` ACCEPTED a stripped require constitution end to end — the strip attack survives at the command")
	}
}
