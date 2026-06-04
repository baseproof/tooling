#!/bin/bash
# scripts/run-local.sh
#
# Local-dev orchestrator: runs the REAL Ledger binary against the
# ledger's own infra (Postgres + SeaweedFS, via scripts/infra) and
# an EXTERNAL witness fleet (owned by the tooling repo (services/witness)).
# Points the Ledger at SeaweedFS (S3) by DEFAULT.
#
# ─────────────────────────────────────────────────────────────────
# THREE LAYERS, THREE OWNERS — NO INTERMINGLING
# ─────────────────────────────────────────────────────────────────
#
#   scripts/infra (this repo)   Postgres + SeaweedFS. NO witnesses.
#                               Env via `eval "$(./scripts/infra env)"`
#                               → BASEPROOF_TEST_DSN + LEDGER_BYTE_STORE_S3_*.
#
#   tooling repo (services/witness)     The witness fleet. Owns fixture
#                               generation + the daemon runner:
#                                 cd ../tooling/services/witness
#                                 ./scripts/run-local.sh --witnesses N
#                               Prints LEDGER_WITNESS_ENDPOINTS /
#                               _QUORUM_K / _NETWORK_BOOTSTRAP_FILE.
#
#   scripts/run-local.sh        The ledger binary. Consumes BOTH of
#                               the above PURELY via env vars: infra's
#                               DSN + S3 (auto-imported), and the
#                               witness fleet's three vars (which YOU
#                               export from the witness repo's output).
#                               This repo describes ZERO witness config.
#
# BYTESTORE — SeaweedFS by default:
#
#   The Ledger writes entry bytes to SeaweedFS (the S3 wire) by
#   default — the same bytestore.S3 adapter production uses, and the
#   same backend the soak + determinism profiles exercise. Real GCS
#   is OPT-IN: export LEDGER_BYTE_STORE_GCS_BUCKET (+ ADC) and
#   run-local switches to the GCS backend.
#
# ARCHITECTURAL BOUNDARY:
#
#   The Ledger and the Witness are physically separate Go modules in
#   different repositories. The Ledger never imports witness-daemon
#   code, never builds or runs a witness container, and talks to the
#   fleet purely over HTTP as a cosign CLIENT. The contract between
#   the two repos is exactly three env vars.
#
# Usage:
#
#   # 1. Witness fleet (separate repo, separate terminal):
#   cd ../tooling/services/witness && ./scripts/run-local.sh --witnesses 3
#   export LEDGER_WITNESS_ENDPOINTS=... LEDGER_WITNESS_QUORUM_K=... \
#          LEDGER_NETWORK_BOOTSTRAP_FILE=...
#
#   # 2. Ledger (this repo):
#   ./scripts/run-local.sh up        # infra up + ledger (SeaweedFS)
#   ./scripts/run-local.sh           # same as `up`
#   ./scripts/run-local.sh down      # tear down infra (scripts/infra down)
#   ./scripts/run-local.sh clean     # wipe .run/ then up
#   ./scripts/run-local.sh integration   # run integration tests
#
# Opt into real GCS instead of SeaweedFS:
#   gcloud auth application-default login
#   export LEDGER_BYTE_STORE_GCS_BUCKET=<your-bucket>
#   ./scripts/run-local.sh up
#
# Witness topology is fixed at 2 (K=2 quorum) by scripts/infra. The
# legacy `--witnesses N` flag is accepted for back-compat but warns
# and is ignored — N-witness laptop topologies were the one feature
# unique to the old process-witness model; if you need them, drive
# scripts/infra directly.
#
# Integration mode:
#   - Brings up scripts/local/docker-compose.integration.yml
#     (2 ledger nodes, fake-gcs-server, dual Postgres DBs).
#   - Runs `go test -count=1 ./integration/`.
#
# Submit an entry from a second terminal:
#   go run ./cmd/submit-stamp -log-did "$LEDGER_LOG_DID"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INT_COMPOSE_FILE="${REPO_ROOT}/scripts/local/docker-compose.integration.yml"
RUN_DIR="${REPO_ROOT}/.run"

# ── Parse flags ────────────────────────────────────────────────────
SUBCMD="run"
CLEAN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --witnesses)
            echo "WARN: --witnesses is ignored — scripts/infra provides a fixed" >&2
            echo "      2-witness (K=2) topology. Drive scripts/infra directly" >&2
            echo "      for other counts." >&2
            shift 2 2>/dev/null || shift
            ;;
        up)
            # Verb-alignment alias: `run-local up` == bare `run-local`,
            # consistent with `./scripts/infra up`.
            SUBCMD="run"
            shift
            ;;
        down)
            SUBCMD="down"
            shift
            ;;
        clean)
            CLEAN=1
            shift
            ;;
        integration)
            SUBCMD="integration"
            shift
            ;;
        -h|--help)
            sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

# ── Tear-down: kill witnesses + down Docker ────────────────────────
if [ "${SUBCMD}" = "down" ]; then
    echo "== tearing down infra (scripts/infra down) =="
    "${REPO_ROOT}/scripts/infra" down
    if docker compose -f "${INT_COMPOSE_FILE}" ps -q 2>/dev/null | grep -q .; then
        echo "== integration topology also up — tearing down =="
        docker compose -f "${INT_COMPOSE_FILE}" down -v
    fi
    exit 0
fi

cd "${REPO_ROOT}"

# ── Integration: boot topology + run integration tests ─────────────
if [ "${SUBCMD}" = "integration" ]; then
    echo "== bringing up integration topology (fake-gcs, 2 ledger nodes) =="
    docker compose -f "${INT_COMPOSE_FILE}" up -d --build

    echo "== waiting for both ledger nodes to report healthy =="
    READY=0
    for i in $(seq 1 60); do
        a=$(curl -fsS http://localhost:8080/healthz 2>/dev/null || echo "")
        b=$(curl -fsS http://localhost:8081/healthz 2>/dev/null || echo "")
        if [ "${a}" = "ok" ] && [ "${b}" = "ok" ]; then
            echo "ready: node-a=:8080  node-b=:8081  fake-gcs=:4443 (attempt ${i})"
            READY=1
            break
        fi
        sleep 2
    done
    if [ "${READY}" -ne 1 ]; then
        echo "FATAL: ledger nodes did not report healthy in time" >&2
        echo "       check: docker compose -f ${INT_COMPOSE_FILE} logs" >&2
        exit 1
    fi

    echo
    echo "== running integration tests (./integration/) =="
    set +e
    go test -count=1 -v ./integration/
    TEST_RC=$?
    set -e

    echo
    if [ ${TEST_RC} -eq 0 ]; then
        echo "== integration tests PASSED =="
        echo "   topology still UP. Tear down with: ./scripts/run-local.sh down"
    else
        echo "== integration tests FAILED (exit=${TEST_RC}) =="
        echo "   topology left UP for log inspection."
    fi
    exit ${TEST_RC}
fi

# ── Default / `up`: infra up → import env → run the Ledger ─────────
if [ "${CLEAN}" = "1" ]; then
    echo "== wiping ${RUN_DIR} =="
    rm -rf "${RUN_DIR}"
fi

# Bring up the ledger's infra (Postgres + SeaweedFS) and import the
# env it emits (DSN + S3 bytestore vars). Witnesses are NOT part of
# this infra — see the witness-tier block below.
if ! docker inspect baseproof_test_postgres >/dev/null 2>&1; then
    echo "== bringing up infra (scripts/infra up) =="
    "${REPO_ROOT}/scripts/infra" up
fi
# shellcheck disable=SC2046  # word-splitting of export lines is intended
eval "$("${REPO_ROOT}/scripts/infra" env)"

# ── Witness tier — consumed via env vars, NOT run by this repo ─────
# The witness daemon lives in github.com/clearcompass-ai/standalone-
# witness, which owns its own fleet runner. The ledger consumes the
# tier PURELY through three env vars. If they're not already set,
# point the operator at the witness repo instead of intermingling
# its container config into this one.
if [ -z "${LEDGER_WITNESS_ENDPOINTS:-}" ] || \
   [ -z "${LEDGER_NETWORK_BOOTSTRAP_FILE:-}" ]; then
    cat <<'ERR' >&2

== run-local.sh: witness tier not configured ==

The ledger needs a running witness fleet, which is owned by the
tooling repo (services/witness) (this repo defines NO witness container).
Stand one up there, then import the env it exports:

  cd ../tooling/services/witness
  ./scripts/run-local.sh --witnesses 3      # fleet on :19001..:19003
  # it writes .run/witness.env (export LEDGER_* lines), so in THIS shell:
  eval "$(make -s print-env)"               # sets LEDGER_* for the ledger
  # or:  source ../tooling/services/witness/.run/witness.env

Then re-run ./scripts/run-local.sh up.

ERR
    exit 1
fi
# LEDGER_LOG_DID must match the log DID the witness fleet's bootstrap
# was generated for (the witness gen-fixtures -log-did). The
# default below matches that repo's default; override if you changed it.

# ── Local volumes (WAL + Tessera tile storage stay on the host) ────
mkdir -p "${RUN_DIR}/wal" "${RUN_DIR}/tessera" "${RUN_DIR}/antispam" "${RUN_DIR}/logs"

# ── Ledger env ────────────────────────────────────────────────────
# Database: infra emits BASEPROOF_TEST_DSN; the Ledger reads
# LEDGER_DATABASE_URL. Map one to the other (same PG either way).
export LEDGER_DATABASE_URL="${LEDGER_DATABASE_URL:-${BASEPROOF_TEST_DSN}}"
# Default matches the witness gen-fixtures' default -log-did,
# so the ledger's log DID lines up with the witness fleet's bootstrap.
# Override if you passed a custom -log-did to the witness fleet.
export LEDGER_LOG_DID="${LEDGER_LOG_DID:-did:baseproof:standalone-witness:local}"
export LEDGER_WAL_PATH="${LEDGER_WAL_PATH:-${RUN_DIR}/wal}"
export LEDGER_TESSERA_STORAGE_DIR="${LEDGER_TESSERA_STORAGE_DIR:-${RUN_DIR}/tessera}"
export LEDGER_TESSERA_ANTISPAM_PATH="${LEDGER_TESSERA_ANTISPAM_PATH:-${RUN_DIR}/antispam}"
export LEDGER_ADDR="${LEDGER_ADDR:-:8080}"

# ── Bytestore: SeaweedFS by default, real GCS opt-in ──────────────
# If the operator exported LEDGER_BYTE_STORE_GCS_BUCKET they want
# real GCS — verify ADC and switch the backend. Otherwise use the
# SeaweedFS (S3) wiring `scripts/infra env` already exported
# (LEDGER_BYTE_STORE_BACKEND=s3 + LEDGER_BYTE_STORE_S3_*).
if [ -n "${LEDGER_BYTE_STORE_GCS_BUCKET:-}" ]; then
    ADC_JSON="${HOME}/.config/gcloud/application_default_credentials.json"
    if [ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ ! -f "${ADC_JSON}" ]; then
        cat <<'ERR' >&2
== run-local.sh: GCS requested but no Google Cloud ADC found ==

LEDGER_BYTE_STORE_GCS_BUCKET is set, so run-local will use real GCS.
Authenticate first:

  gcloud auth application-default login
    (writes ~/.config/gcloud/application_default_credentials.json)
  OR
  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

Or UNSET LEDGER_BYTE_STORE_GCS_BUCKET to use the default SeaweedFS
backend (no cloud auth required).
ERR
        exit 1
    fi
    export LEDGER_BYTE_STORE_BACKEND="gcs"
    # GCS path: clear the S3 wiring infra emitted so it can't bleed in.
    unset LEDGER_BYTE_STORE_S3_ENDPOINT LEDGER_BYTE_STORE_S3_BUCKET \
          LEDGER_BYTE_STORE_S3_REGION LEDGER_BYTE_STORE_S3_ACCESS_KEY \
          LEDGER_BYTE_STORE_S3_SECRET_KEY LEDGER_BYTE_STORE_S3_PATH_STYLE
    unset LEDGER_BYTE_STORE_GCS_ENDPOINT LEDGER_BYTE_STORE_GCS_ANONYMOUS
    BYTESTORE_DESC="gcs (bucket=${LEDGER_BYTE_STORE_GCS_BUCKET})"
else
    # SeaweedFS (default) — LEDGER_BYTE_STORE_BACKEND=s3 +
    # LEDGER_BYTE_STORE_S3_* already exported by `scripts/infra env`.
    BYTESTORE_DESC="seaweedfs/s3 (endpoint=${LEDGER_BYTE_STORE_S3_ENDPOINT:-?} bucket=${LEDGER_BYTE_STORE_S3_BUCKET:-?})"
fi

export LEDGER_METRICS_ENABLE="${LEDGER_METRICS_ENABLE:-true}"
export LEDGER_METRICS_ENVIRONMENT="${LEDGER_METRICS_ENVIRONMENT:-laptop-dev}"
export LEDGER_OTLP_TRACES_ENDPOINT="${LEDGER_OTLP_TRACES_ENDPOINT:-stdout}"
export LEDGER_PPROF_ADDR="${LEDGER_PPROF_ADDR:-127.0.0.1:6060}"

echo "== env ready =="
echo "  LEDGER_DATABASE_URL=${LEDGER_DATABASE_URL}"
echo "  LEDGER_LOG_DID=${LEDGER_LOG_DID}"
echo "  LEDGER_ADDR=${LEDGER_ADDR}"
echo "  LEDGER_BYTE_STORE_BACKEND=${LEDGER_BYTE_STORE_BACKEND}  → ${BYTESTORE_DESC}"
echo "  LEDGER_WITNESS_ENDPOINTS=${LEDGER_WITNESS_ENDPOINTS:-} (quorum_k=${LEDGER_WITNESS_QUORUM_K:-})"
echo "  LEDGER_NETWORK_BOOTSTRAP_FILE=${LEDGER_NETWORK_BOOTSTRAP_FILE:-}"
echo "  witnesses: external fleet (tooling repo (services/witness)) — consumed via env vars above"
echo
echo "  Tear down: ./scripts/run-local.sh down   (witness fleet: cd ../tooling/services/witness && ./scripts/run-local.sh down)"
echo

# ── Run Ledger ────────────────────────────────────────────────────
echo "== starting ledger =="
exec go run ./cmd/ledger
