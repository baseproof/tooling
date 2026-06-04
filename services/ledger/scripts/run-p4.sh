#!/bin/bash
# scripts/run-p4.sh
#
# Runs the build-tag-isolated P4 production-realism + chaos test
# suite (tests/p4/, build tag `p4`).
#
# P4 tests are scenario-shaped — each test case asserts ONE
# production invariant under realistic load + adversarial conditions:
#
#   P4.2  advisory-lock split-brain   (THIS RUN)
#   P4.3  2-replica failover          (later commit)
#   P4.4  witness offline matrix      (later commit; awaits Backpressure
#                                       Stall implementation)
#   P4.5  cryptographic integrity master (later commit)
#   P4.1  multi-persona concurrent load (later commit)
#
# ── Postgres ─────────────────────────────────────────────────────────
#   If BASEPROOF_TEST_DSN is set, that DSN is used as-is (no docker).
#   If unset, this script auto-provisions Postgres in Docker using the
#   same compose file as scripts/run-local.sh and exports the canonical
#   testharness DSN. Tear down with `./scripts/run-p4.sh down`.
#
# ── Run knobs (env, with defaults) ──────────────────────────────────
#   BASEPROOF_P4_TEST_TIMEOUT          5m       go test process ceiling
#   BASEPROOF_P4_RUN                   ""       -run filter (default: all P4 tests)
#   BASEPROOF_P4_VERBOSE               1        passes -v to go test (default on)
#
# Quick start:
#
#   ./scripts/run-p4.sh
#
# With an existing Postgres:
#
#   export BASEPROOF_TEST_DSN=postgres://user:pw@host/db
#   ./scripts/run-p4.sh
#
# Run a single matrix cell:
#
#   BASEPROOF_P4_RUN=TestP4_AdvisoryLock_HandoffSequence ./scripts/run-p4.sh
#
# Tear down auto-provisioned containers:
#
#   ./scripts/run-p4.sh down

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

case "${1:-}" in
    down)
        echo "== tearing down test infra =="
        exec "${REPO_ROOT}/scripts/infra" down
        ;;
esac

cd "${REPO_ROOT}"

# ── Postgres: delegated to scripts/infra (or env-supplied DSN) ───
PROVISIONED_PG=0
if [ -z "${BASEPROOF_TEST_DSN:-}" ]; then
    infra_ensure_postgres_up
    PROVISIONED_PG=1
fi

TEST_TIMEOUT="${BASEPROOF_P4_TEST_TIMEOUT:-5m}"
RUN_FILTER="${BASEPROOF_P4_RUN:-}"
VERBOSE="${BASEPROOF_P4_VERBOSE:-1}"

if [ "${PROVISIONED_PG}" -eq 1 ]; then
    DSN_SOURCE="scripts/infra (auto-provisioned)"
else
    DSN_SOURCE="env BASEPROOF_TEST_DSN"
fi

echo
echo "== baseproof ledger P4 (production-realism + chaos) =="
echo "   dsn source:   ${DSN_SOURCE}"
echo "   test timeout: ${TEST_TIMEOUT}"
if [ -n "${RUN_FILTER}" ]; then
    echo "   run filter:   ${RUN_FILTER}"
fi
echo

GO_TEST_FLAGS=(
    -tags=p4
    -count=1
    -timeout "${TEST_TIMEOUT}"
)
if [ "${VERBOSE}" = "1" ]; then
    GO_TEST_FLAGS+=(-v)
fi
if [ -n "${RUN_FILTER}" ]; then
    GO_TEST_FLAGS+=(-run "${RUN_FILTER}")
fi

START_NS=$(date +%s%N)

go test "${GO_TEST_FLAGS[@]}" ./tests/p4/

END_NS=$(date +%s%N)
ELAPSED_S=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "== P4 summary =="
cat <<EOF
{
  "wall_clock_seconds":  ${ELAPSED_S},
  "dsn_source":          "${DSN_SOURCE}",
  "test_status":         "ok"
}
EOF

if [ "${PROVISIONED_PG}" -eq 1 ]; then
    echo
    echo "Test infra still running. Tear down when finished:"
    echo "  ./scripts/run-p4.sh down"
fi
