#!/usr/bin/env bash
#
# Run the embedded-Postgres integration tests (internal/embeddedpg,
# internal/dbintegration). Postgres refuses to run as root, so when invoked as
# root this re-execs the test run as a non-root user (default: ubuntu) with a
# usable Go environment. Outside a root sandbox it just runs `go test`.
#
# Usage:  scripts/run-db-integration.sh [packages...]
set -euo pipefail

PKGS="${*:-./internal/embeddedpg/... ./internal/dbintegration/...}"

if [ "$(id -u)" -ne 0 ]; then
  exec go test ${PKGS} -count=1 -timeout 300s
fi

RUNUSER="${DB_TEST_USER:-ubuntu}"
GOMC="$(go env GOMODCACHE)"
GOBIN_DIR="$(dirname "$(command -v go)")"
REPO="$(pwd)"

# Open just the traversal path to the (root-owned) module cache + repo, and give
# the non-root user a writable Go build cache + TMPDIR.
chmod a+x /root /root/go /root/go/pkg 2>/dev/null || true
chmod -R a+rX "${GOMC}" 2>/dev/null || true
chmod -R a+rX "${REPO}" 2>/dev/null || true
ENV="/tmp/dbtest-${RUNUSER}"
mkdir -p "${ENV}/gocache" "${ENV}/home" "${ENV}/tmp"
chmod -R 777 "${ENV}"

exec su "${RUNUSER}" -s /bin/bash -c "
  export PATH='${GOBIN_DIR}':\$PATH HOME='${ENV}/home' GOCACHE='${ENV}/gocache' GOMODCACHE='${GOMC}' TMPDIR='${ENV}/tmp'
  cd '${REPO}'
  go test ${PKGS} -count=1 -timeout 300s
"
