#!/bin/bash
# scripts/run-cursor-tests.sh
#
# Runs the SequenceCursor tests against the unified test infra.
# Delegates Postgres provisioning to `scripts/infra`; this script
# is a thin focus-on-this-test-subset shim over that infra.
#
# Usage:
#   ./scripts/run-cursor-tests.sh           # boot infra (if needed) + run
#   ./scripts/run-cursor-tests.sh down      # tear down infra
#
# Postgres lifecycle:
#   - If BASEPROOF_TEST_DSN is preset, this script never touches Docker.
#   - Otherwise, it invokes `scripts/infra up`. Tear-down delegates
#     to `scripts/infra down`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

if [ "${1:-}" = "down" ]; then
    echo "== tearing down test infra =="
    exec "${REPO_ROOT}/scripts/infra" down
fi

cd "${REPO_ROOT}"

# ── Postgres provisioning (delegated to scripts/infra) ───────────
infra_ensure_postgres_up

echo "== running cursor + sequence tests =="
echo "   BASEPROOF_TEST_DSN=${BASEPROOF_TEST_DSN}"
go test -v -count=1 -p 1 -timeout=120s \
    -run 'TestSequenceCursor|TestCursorReader' \
    ./store/ ./builder/

echo
echo "== done — to tear down: ./scripts/run-cursor-tests.sh down =="
