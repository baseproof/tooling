#!/bin/bash
# scripts/_validation_determinism.sh — internal profile body.
# Invoke via run-validation.sh, not directly.
#
# Runs TestScale_DeterministicReplay (tests/scale_determinism_test.go).
# At-scale P5 idempotent-replay validator: each worker builds wire
# FRESH per iteration, POSTs first + replay, verifies byte-identity
# inline. No pre-built batch (no staleness). Non-fatal submit (errors
# counted, not silenced).
#
# VALIDATES (scale + end-to-end):
#   1. SDK primitive determinism (baseproof RFC 6979 ECDSA).
#   2. Ledger dedup-and-replay path.
#   3. Pipeline integrity under concurrent realistic load.
#   4. Real bytestore (SeaweedFS S3) shipper + read path — the
#      shipper migrates every WAL entry into SeaweedFS during the
#      run, so the determinism contract is verified against the
#      SAME byte-store wire production uses (no in-memory gap).
#
# INFRA: this profile replicates production shape — Postgres +
# SeaweedFS (S3) — via `scripts/infra`. The default backend is
# `s3` (SeaweedFS); set BASEPROOF_SCALE_DETERMINISM_BYTESTORE=memory
# for the legacy quick in-memory variant.
#
# REQUIRED ENV:
#   BASEPROOF_TEST_DSN  Postgres connection string. Auto-provisioned
#                     via `scripts/infra up` when unset (which also
#                     brings up SeaweedFS for the s3 backend).
#
# OPTIONAL KNOBS (with defaults):
#   BASEPROOF_SCALE_DETERMINISM_N             10000  target pairs
#                                                  (= 2N submissions)
#   BASEPROOF_SCALE_DETERMINISM_CONCURRENCY   8      worker goroutines
#   BASEPROOF_SCALE_DETERMINISM_MAX_DURATION  15m    in-test safety net
#                                                  (workers stop early
#                                                  if exceeded)
#   BASEPROOF_SCALE_DETERMINISM_STOP_ON_DRIFT 1      fail-fast toggle
#                                                  (1=stop on first
#                                                  drift, 0=keep going)
#   BASEPROOF_SCALE_DETERMINISM_TIMEOUT       20m    go test process
#                                                  ceiling
#   BASEPROOF_SCALE_DETERMINISM_BYTESTORE     s3     bytestore backend
#                                                  (s3=SeaweedFS via
#                                                  scripts/infra;
#                                                  memory=in-memory)
#
# Bash because: set -o pipefail (POSIX has only set -e), and the
# resolved-defaults block below is clearer with bash's parameter
# expansion than POSIX equivalents.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# shellcheck source=lib/validation_common.sh
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

# ── `down` subcommand: tear down infra (verb-aligned with soak) ──────
case "${1:-}" in
    down)
        echo "== tearing down test infra =="
        exec "${REPO_ROOT}/scripts/infra" down
        ;;
esac

# Bytestore backend — default s3 (SeaweedFS) for the true end-to-end
# replication the determinism profile now targets. memory is the
# opt-out for a fast, dependency-free smoke.
BYTESTORE="${BASEPROOF_SCALE_DETERMINISM_BYTESTORE:-s3}"

# ── Infra provisioning ───────────────────────────────────────────────
# For the s3 backend, bring up the full scripts/infra topology
# (Postgres + SeaweedFS + bucket) and import its env (DSN +
# BASEPROOF_TEST_S3_*). For the memory backend, only Postgres is
# required — infra_ensure_postgres_up provisions it (or honours an
# externally supplied DSN).
if [ "${BYTESTORE}" = "s3" ]; then
    # Provision (or honor a passed-in) Postgres + SeaweedFS via the
    # shared chokepoint in validation_common.sh. Witnesses are never
    # provisioned — they are discovered from LEDGER_WITNESS_*.
    validation_ensure_seaweedfs_infra
else
    infra_ensure_postgres_up
fi

validation_preflight_dsn

# Resolve every knob to its final value, then re-export. The script
# becomes the single source of truth for "what the test process
# actually saw" — banner + go test invocation read from the same
# locals. Without re-export, an unset env var would cause the test
# process to apply ITS OWN default (defined in Go) which might drift
# from what this script's banner advertises. Re-exporting closes
# that gap.
N="${BASEPROOF_SCALE_DETERMINISM_N:-10000}"
CONCURRENCY="${BASEPROOF_SCALE_DETERMINISM_CONCURRENCY:-8}"
MAX_DURATION="${BASEPROOF_SCALE_DETERMINISM_MAX_DURATION:-15m}"
STOP_ON_DRIFT="${BASEPROOF_SCALE_DETERMINISM_STOP_ON_DRIFT:-1}"
TIMEOUT="${BASEPROOF_SCALE_DETERMINISM_TIMEOUT:-20m}"

export BASEPROOF_SCALE_DETERMINISM_N="${N}"
export BASEPROOF_SCALE_DETERMINISM_CONCURRENCY="${CONCURRENCY}"
export BASEPROOF_SCALE_DETERMINISM_MAX_DURATION="${MAX_DURATION}"
export BASEPROOF_SCALE_DETERMINISM_STOP_ON_DRIFT="${STOP_ON_DRIFT}"
export BASEPROOF_SCALE_DETERMINISM_BYTESTORE="${BYTESTORE}"

echo "== validation profile: determinism (continuous end-to-end replay) =="
echo "   target n:         ${N} pairs (= ${N} × 2 submissions)"
echo "   concurrency:      ${CONCURRENCY} workers (each runs its own loop)"
echo "   bytestore:        ${BYTESTORE} (s3=SeaweedFS via scripts/infra)"
echo "   max duration:     ${MAX_DURATION} (in-test safety net)"
echo "   stop on drift:    ${STOP_ON_DRIFT} (1=fail fast, 0=keep going)"
echo "   test timeout:     ${TIMEOUT} (go test process ceiling)"
validation_witness_banner
echo
echo "shape: each worker builds wire FRESH per iteration, POSTs first +"
echo "       replay, verifies byte-identity inline, then next. No pre-"
echo "       built batch (no staleness). Non-fatal submit (errors are"
echo "       counted, not silenced)."
echo
echo "what passes look like:"
echo "  scale-determinism PASS: ${N} pairs end-to-end, all byte-identical"
echo "  (canonical_hash + log_time_micros + signature)"
echo
echo "what failures point at:"
echo "  canonical_hash drift  → wire-construction mutation upstream of the SCT path"
echo "  log_time_micros drift → ledger persisted-replay regression"
echo "  signature drift       → SDK RFC 6979 regression OR random state in signed payload"
echo

validation_start_timer

go test -tags=scale \
    -count=1 \
    -timeout "${TIMEOUT}" \
    -v \
    -run '^TestScale_DeterministicReplay$' \
    ./tests/

WALL_SEC="$(validation_elapsed_secs)"

echo
echo "== summary =="
echo "  target n:          ${N}"
echo "  concurrency:       ${CONCURRENCY}"
echo "  bytestore:         ${BYTESTORE}"
echo "  wall_clock_secs:   ${WALL_SEC}"
echo "  contract verified: SDK RFC 6979 ECDSA + ledger dedup-and-replay"
if [ "${BYTESTORE}" = "s3" ]; then
    echo "                     + real SeaweedFS shipper/read path (no in-memory gap)"
    echo
    echo "Test infra still running. Tear down when finished:"
    echo "  ./scripts/run-validation.sh determinism down"
fi
