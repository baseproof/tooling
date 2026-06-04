#!/bin/bash
# scripts/run-local.sh
#
# Local-dev orchestrator for the standalone-witness daemon.
# Generates a K=N witness fixture set via `go run ./cmd/gen-fixtures`,
# builds the daemon binary, and spawns N copies as background
# processes with /healthz polling and PID-tracked teardown.
#
# This script does NOT require a ledger checkout. All fixtures
# (witness PEM keys + network bootstrap doc) are generated inside
# this module by cmd/gen-fixtures. The K=N witness fleet stands
# alone and can be pointed at by a separate ledger via
# LEDGER_WITNESS_ENDPOINTS / LEDGER_NETWORK_BOOTSTRAP_FILE.
#
# Usage:
#
#   ./scripts/run-local.sh                     # 1 witness on :19001
#   ./scripts/run-local.sh --witnesses 3       # 3 witnesses on :19001..:19003
#   ./scripts/run-local.sh --port-base 29001   # custom base port
#   ./scripts/run-local.sh clean               # rm -rf .run, then run
#   ./scripts/run-local.sh down                # kill PIDs in .run/witness-pids
#   ./scripts/run-local.sh -h
#
# Environment overrides (CLI flags take precedence):
#
#   WITNESS_COUNT       — same as --witnesses
#   WITNESS_PORT_BASE   — same as --port-base
#
# Output endpoints are written to .run/witness.env as `export
# LEDGER_*` lines (and echoed) so a ledger run can pick the fleet up
# with `eval "$(make -s print-env)"` — no hand-typed exports.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_DIR="${REPO_ROOT}/.run"
LOG_DIR="${RUN_DIR}/logs"
PIDS_FILE="${RUN_DIR}/witness-pids"
BOOTSTRAP_FILE="${RUN_DIR}/network-bootstrap.json"
BIN_PATH="${REPO_ROOT}/bin/standalone-witness"

# ── Defaults / env overrides ─────────────────────────────────────
WITNESS_COUNT="${WITNESS_COUNT:-1}"
PORT_BASE="${WITNESS_PORT_BASE:-19001}"
SUBCMD="run"
CLEAN=0

usage() {
    sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --witnesses)
            WITNESS_COUNT="${2:-}"
            shift 2
            ;;
        --port-base)
            PORT_BASE="${2:-}"
            shift 2
            ;;
        clean)
            CLEAN=1
            shift
            ;;
        down)
            SUBCMD="down"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument: $1" >&2
            echo "       use --help for usage." >&2
            exit 2
            ;;
    esac
done

if ! [[ "${WITNESS_COUNT}" =~ ^[0-9]+$ ]] || [ "${WITNESS_COUNT}" -lt 1 ]; then
    echo "FATAL: --witnesses must be a positive integer (got: ${WITNESS_COUNT})" >&2
    exit 2
fi
if ! [[ "${PORT_BASE}" =~ ^[0-9]+$ ]] || [ "${PORT_BASE}" -lt 1024 ] || [ "${PORT_BASE}" -gt 65000 ]; then
    echo "FATAL: --port-base must be an unprivileged port (1024-65000, got: ${PORT_BASE})" >&2
    exit 2
fi

# ── Tear-down ────────────────────────────────────────────────────
if [ "${SUBCMD}" = "down" ]; then
    if [ ! -f "${PIDS_FILE}" ]; then
        echo "no PID file at ${PIDS_FILE} — nothing to tear down."
        exit 0
    fi
    echo "== stopping spawned witness daemons =="
    while read -r pid; do
        [ -z "${pid}" ] && continue
        if kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            echo "  stopped pid=${pid}"
        else
            echo "  pid=${pid} already gone"
        fi
    done < "${PIDS_FILE}"
    rm -f "${PIDS_FILE}"
    exit 0
fi

# ── Preflight ───────────────────────────────────────────────────
if ! command -v go >/dev/null 2>&1; then
    echo "FATAL: 'go' not on PATH. install Go (see go.mod for the minimum version)." >&2
    exit 1
fi

cd "${REPO_ROOT}"

if [ "${CLEAN}" = "1" ]; then
    echo "== wiping ${RUN_DIR} =="
    rm -rf "${RUN_DIR}"
fi

# Port-collision check. We do this BEFORE generating fixtures or
# building the binary so the developer gets a fast, clear error.
check_port_free() {
    local port="$1"
    # Use bash's /dev/tcp pseudo-device for portability — works on
    # macOS and Linux without requiring lsof/nc/ss. A successful
    # open means the port is in use.
    if (echo > "/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        return 1
    fi
    return 0
}
for i in $(seq 1 "${WITNESS_COUNT}"); do
    port=$((PORT_BASE + i - 1))
    if ! check_port_free "${port}"; then
        echo "FATAL: port :${port} is in use." >&2
        echo "       choose a different --port-base, or stop the conflicting process." >&2
        exit 1
    fi
done

# ── Generate fixtures ───────────────────────────────────────────
echo "== generating fixtures (${WITNESS_COUNT} witness key(s)) =="
go run ./cmd/gen-fixtures \
    -out-dir="${RUN_DIR}" \
    -out-bootstrap="${BOOTSTRAP_FILE}" \
    -witnesses="${WITNESS_COUNT}"

# ── Build binary ────────────────────────────────────────────────
echo "== building ${BIN_PATH} =="
mkdir -p "$(dirname "${BIN_PATH}")"
go build -o "${BIN_PATH}" ./cmd/witness

# ── Spawn daemons ───────────────────────────────────────────────
mkdir -p "${LOG_DIR}"
: > "${PIDS_FILE}"
echo "== spawning ${WITNESS_COUNT} witness daemon(s) =="
for i in $(seq 1 "${WITNESS_COUNT}"); do
    port=$((PORT_BASE + i - 1))
    wkey="${RUN_DIR}/witnesses/witness-${i}.pem"
    wlog="${LOG_DIR}/witness-${i}.log"
    if [ ! -f "${wkey}" ]; then
        echo "FATAL: missing ${wkey} (gen-fixtures should have produced it)" >&2
        exit 1
    fi
    echo "  starting witness-${i} on :${port}  (log=${wlog})"
    ( "${BIN_PATH}" \
        -addr=":${port}" \
        -key-file="${wkey}" \
        -bootstrap="${BOOTSTRAP_FILE}" \
        > "${wlog}" 2>&1 ) &
    wpid=$!
    echo "${wpid}" >> "${PIDS_FILE}"
done

# Trap: when this script exits or is signalled, kill any tracked
# daemons. Without this, Ctrl-C would orphan background processes.
cleanup() {
    if [ -f "${PIDS_FILE}" ]; then
        while read -r pid; do
            [ -z "${pid}" ] && continue
            kill "${pid}" 2>/dev/null || true
        done < "${PIDS_FILE}"
        rm -f "${PIDS_FILE}"
    fi
}
trap cleanup EXIT INT TERM

# ── Wait for /healthz ───────────────────────────────────────────
# 50 × 200ms = 10s timeout per daemon. Matches the cadence used
# by ledger/scripts/run-local.sh for the same daemon shape.
for i in $(seq 1 "${WITNESS_COUNT}"); do
    port=$((PORT_BASE + i - 1))
    READY=0
    for attempt in $(seq 1 50); do
        body="$(curl -fsS "http://localhost:${port}/healthz" 2>/dev/null || echo "")"
        if [ "${body}" = "ok" ]; then
            echo "  witness-${i} ready (attempt ${attempt})"
            READY=1
            break
        fi
        sleep 0.2
    done
    if [ "${READY}" -ne 1 ]; then
        echo "FATAL: witness-${i} did not respond ok on /healthz." >&2
        echo "       inspect ${LOG_DIR}/witness-${i}.log" >&2
        exit 1
    fi
done

# ── Auto-export env (LEDGER_* the ledger reads) ─────────────────
"${REPO_ROOT}/scripts/local/write-env.sh" \
    "${WITNESS_COUNT}" "${PORT_BASE}" "${BOOTSTRAP_FILE}" "${RUN_DIR}"

# ── Final summary ───────────────────────────────────────────────
cat <<EOF

== standalone-witness fleet UP ==
  witnesses                       = ${WITNESS_COUNT}
  port range                      = :${PORT_BASE}..:$((PORT_BASE + WITNESS_COUNT - 1))
  cosign endpoint                 = POST /v1/cosign
  bootstrap doc                   = ${BOOTSTRAP_FILE}
  per-daemon logs                 = ${LOG_DIR}/witness-<i>.log
  PID file                        = ${PIDS_FILE}

== drive a separate ledger at this fleet (no manual exports) ==
  eval "\$(make -s print-env)"        # sets LEDGER_* in this shell
  # or:  source ${RUN_DIR}/witness.env

== tear down ==
  ./scripts/run-local.sh down

EOF

# Disable the trap before exiting normally — we WANT the daemons
# to keep running once the script returns. The user explicitly
# tears them down with `./scripts/run-local.sh down`.
trap - EXIT INT TERM

echo "(script returning; daemons continue to run in background)"
