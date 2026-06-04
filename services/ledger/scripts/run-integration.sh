#!/bin/bash
# scripts/run-integration.sh
#
# Canonical runner for the integration/ test suite. Delegates
# Postgres provisioning to `scripts/infra` (the unified test-infra
# orchestrator) and runs `go test -tags=integration -count=1`
# against ./integration/.
#
# Why this exists:
#   integration/ tests carry //go:build integration so they are
#   invisible to standard `go test ./...`. A developer typing
#   plain `go test` on a laptop without Docker should NOT see
#   a wall of red Postgres-connection errors. The build tag
#   keeps fast feedback fast; this script is the explicit opt-in
#   for the slow, infra-dependent tests.
#
# Usage:
#   ./scripts/run-integration.sh             # boot + run + leave up
#   ./scripts/run-integration.sh down        # tear down infra
#   ./scripts/run-integration.sh --teardown  # boot + run + tear down
#
# Postgres lifecycle:
#   - If BASEPROOF_TEST_DSN is preset, this script never touches Docker.
#   - Otherwise, it calls `scripts/infra` to provision the unified
#     test infra (Postgres + 2 witnesses + SeaweedFS). Tear-down
#     via `down` / `--teardown` likewise delegates.
#
# Verified: every test under integration/ runs once with -count=1
# to defeat go-test caching.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

case "${1:-}" in
    down)
        echo "== tearing down test infra =="
        exec "${REPO_ROOT}/scripts/infra" down
        ;;
esac

TEARDOWN=0
if [ "${1:-}" = "--teardown" ]; then
    TEARDOWN=1
fi

cd "${REPO_ROOT}"

# ── Postgres provisioning (delegated to scripts/infra) ───────────
infra_ensure_postgres_up

# ── Run integration tests ───────────────────────────────────────
echo
echo "== running integration tests =="
echo "   BASEPROOF_TEST_DSN=${BASEPROOF_TEST_DSN}"
echo

START_NS=$(date +%s%N)

# Integration suite — Ledger's HTTP-driven tests (`integration` tag).
# The witness daemon binary e2e moved to its own repository at
# github.com/baseproof/tooling; its tests run there.
# The cosign e2e against a docker-provisioned witness daemon still
# runs from this repo via scripts/run-e2e.sh (uses WITNESS_URL).
RC=0
go test -tags=integration -count=1 -v ./integration/ || RC=$?

END_NS=$(date +%s%N)
ELAPSED_S=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "== integration summary =="
cat <<EOF
{
  "wall_clock_seconds":  ${ELAPSED_S},
  "exit_status":         ${RC}
}
EOF

if [ "${TEARDOWN}" = "1" ]; then
    echo
    echo "== tearing down test infra =="
    "${REPO_ROOT}/scripts/infra" down
else
    echo
    echo "Test infra still running. Tear down when finished:"
    echo "  ./scripts/run-integration.sh down"
fi

exit ${RC}
