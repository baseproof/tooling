#!/bin/bash
# scripts/_validation_soak.sh — internal profile body.
# Invoke via run-validation.sh, not directly.
#
# Runs the build-tag-isolated ledger soak test (tests/soak_test.go).
# Default: 1M entries.
#
# ── BYTESTORE SELECTION ──────────────────────────────────────────────
#   BASEPROOF_SOAK_BYTESTORE_BACKEND
#     gcs        Real GCS (default; preserves prior behavior).
#                Requires BASEPROOF_TEST_GCS_BUCKET + Google ADC.
#     seaweedfs  Local SeaweedFS in Docker — fully self-contained.
#                Auto-provisions the container, pre-creates bucket,
#                exports S3 endpoint/creds. ZERO cloud dependencies.
#     s3         Bring-your-own S3-compatible (real AWS, MinIO, R2).
#                Requires BASEPROOF_TEST_S3_* env vars.
#
# ── POSTGRES ─────────────────────────────────────────────────────────
#   If BASEPROOF_TEST_DSN is set, that DSN is used as-is (no docker).
#   If unset, this script auto-provisions Postgres in Docker using
#   the same compose file as scripts/run-local.sh and exports the
#   canonical testharness DSN. Tear down with
#   `./scripts/run-validation.sh soak down`.
#
# ── REQUIRED ENV (per backend) ───────────────────────────────────────
#   GCS:
#     BASEPROOF_TEST_GCS_BUCKET        real GCS bucket name (REQUIRED)
#     GOOGLE_APPLICATION_CREDENTIALS path to a service-account key
#                                    (or workload identity / gcloud ADC)
#   SeaweedFS:
#     (nothing — fully self-contained)
#   BYO S3:
#     BASEPROOF_TEST_S3_BUCKET, BASEPROOF_TEST_S3_ENDPOINT,
#     BASEPROOF_TEST_S3_ACCESS_KEY, BASEPROOF_TEST_S3_SECRET_KEY
#
# ── OPTIONAL POSTGRES OVERRIDE ───────────────────────────────────────
#   BASEPROOF_TEST_DSN              postgres connection string
#                                 (or auto-docker)
#
# ── OPTIONAL KNOBS (with defaults) ───────────────────────────────────
#   BASEPROOF_SOAK_ENTRIES                1000000  total entries to submit
#   BASEPROOF_SOAK_CONCURRENCY            8        submitter goroutines
#   BASEPROOF_SOAK_VERIFY_SAMPLES         100      sample for /raw + SHA-256
#                                                round-trip. Accepts a
#                                                count ("100") OR a percent
#                                                of submitted ("5%", "0.5%").
#                                                CASCADES: when
#                                                TREE_PROOF_SAMPLES /
#                                                SMT_PROOF_SAMPLES below
#                                                are unset, both fall back
#                                                to this value. Set
#                                                VERIFY_SAMPLES once →
#                                                every sampled verifier
#                                                scales together.
#   BASEPROOF_SOAK_TREE_PROOF_SAMPLES     (cascade) inclusion-proof samples
#                                                vs /v1/tree/head root.
#                                                UNSET = inherit from
#                                                VERIFY_SAMPLES;
#                                                final fallback 100.
#   BASEPROOF_SOAK_SMT_PROOF_SAMPLES      (cascade) SMT membership-proof
#                                                samples vs /v1/smt/root.
#                                                UNSET = inherit from
#                                                VERIFY_SAMPLES;
#                                                final fallback 100.
#   BASEPROOF_SOAK_P99_BOUND_MS           100      admission p99 ceiling (ms)
#   BASEPROOF_SOAK_SHIPPER_MAX_IN_FLIGHT    16     parallel uploads
#   BASEPROOF_SOAK_SEQUENCER_MAX_IN_FLIGHT  0      sequencer stage-1 pool size
#                                                (parallel Tessera
#                                                AppendLeaf). 0 ⇒
#                                                sequencer.DefaultMaxInFlight.
#   BASEPROOF_SOAK_DRAIN_TIMEOUT          10m      in-test wait for WAL HWM
#   BASEPROOF_SOAK_TEST_TIMEOUT           30m      go test process ceiling
#   BASEPROOF_SOAK_KEEP_DATA              0/1      when set, the test does
#                                                NOT cleanTables on
#                                                teardown. PG + bytestore
#                                                survive the test exit
#                                                so operator can run
#                                                their own SQL / S3
#                                                queries afterwards.
#
# ── POST-TEST VERIFICATION (automated, in-test) ──────────────────────
# The soak test runs three end-to-end evidence assertions before
# returning, replacing manual psql / aws-cli commands operators
# used to run after every successful soak:
#
#   1. SELECT COUNT(*) FROM entry_index == submitted
#   2. SELECT MIN(sequence), MAX(sequence) FROM entry_index spans
#      [0, submitted-1] contiguously
#   3. Every (seq, canonical_hash) tuple from PG is fetchable from
#      the bytestore via Backend.ReadEntry — non-zero bytes for all
#      N entries, parallelised across 64 workers.
#
# Failure on any of the three is a hard t.Fatalf — no quiet "PASS"
# with hidden divergence between PG, bytestore, and submitted count.
#
# ── NO AUTO-TEARDOWN ─────────────────────────────────────────────────
# This script does NOT tear containers down on exit. Tear down
# explicitly when done:
#   ./scripts/run-validation.sh soak down
# (Or the historical alias: ./scripts/run-soak.sh down)
#
# ── USAGE EXAMPLES ───────────────────────────────────────────────────
#
# Cloud-free, fully local 100K smoke:
#   BASEPROOF_SOAK_BYTESTORE_BACKEND=seaweedfs \
#   BASEPROOF_SOAK_ENTRIES=100000 \
#     ./scripts/run-validation.sh soak
#
# Single-knob 10K cascade (VERIFY_SAMPLES drives all three samplers):
#   BASEPROOF_SOAK_BYTESTORE_BACKEND=seaweedfs \
#   BASEPROOF_SOAK_ENTRIES=10000 \
#   BASEPROOF_SOAK_VERIFY_SAMPLES=10% \
#     ./scripts/run-validation.sh soak
#
# Tear down all auto-provisioned containers:
#   ./scripts/run-validation.sh soak down
#
# Bash because: docker provisioning logic uses set -o pipefail (POSIX
# only has set -e), the seaweedfs polling loop relies on $(seq) +
# bash-style arithmetic, and the per-backend display block is much
# clearer with explicit local-style scoping.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "${REPO_ROOT}"

# shellcheck source=lib/validation_common.sh
. "${REPO_ROOT}/scripts/lib/validation_common.sh"

# ── `down` subcommand: short-circuit before any provisioning ─────────
# Tear-down delegates to scripts/infra — the single owner of the
# Postgres + SeaweedFS + witness containers the soak uses.
case "${1:-}" in
    down)
        echo "== tearing down test infra =="
        exec "${REPO_ROOT}/scripts/infra" down
        ;;
esac

# ── Bytestore backend selection ──────────────────────────────────────
BACKEND="${BASEPROOF_SOAK_BYTESTORE_BACKEND:-gcs}"
PROVISIONED_SEAWEEDFS=0

case "${BACKEND}" in
    gcs)
        # GCS preflight (no auto-provision; soak is real-cloud).
        if [ -z "${BASEPROOF_TEST_GCS_BUCKET:-}" ]; then
            echo "FATAL: BASEPROOF_TEST_GCS_BUCKET not set (backend=gcs)"
            echo
            echo "  export BASEPROOF_TEST_GCS_BUCKET=<your-bucket>"
            echo "  OR  export BASEPROOF_SOAK_BYTESTORE_BACKEND=seaweedfs"
            exit 1
        fi
        if [ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && [ ! -r "${GOOGLE_APPLICATION_CREDENTIALS}" ]; then
            echo "FATAL: GOOGLE_APPLICATION_CREDENTIALS points at unreadable file:"
            echo "       ${GOOGLE_APPLICATION_CREDENTIALS}"
            exit 1
        fi
        ;;

    seaweedfs)
        # Delegate SeaweedFS + Postgres provisioning to scripts/infra
        # (the unified orchestrator). `infra up` brings up Postgres +
        # 2 witnesses + SeaweedFS + the baseproof-bytes bucket, health-
        # gating each; `infra env` emits the matching BASEPROOF_TEST_S3_*
        # + BASEPROOF_TEST_DSN vars. The soak no longer hand-maintains a
        # parallel SeaweedFS readiness loop or env-var set — that
        # eliminated the bucket-name / endpoint drift between this
        # script and the canonical infra topology.
        # Provision (or honor a passed-in) Postgres + SeaweedFS via the
        # shared chokepoint in validation_common.sh. infra env emits the
        # BASEPROOF_TEST_S3_* family + BASEPROOF_TEST_DSN, which the soak test
        # reads directly. Witnesses are NOT provisioned here — they are
        # discovered from LEDGER_WITNESS_* (see validation_witness_banner).
        validation_ensure_seaweedfs_infra
        PROVISIONED_SEAWEEDFS=1
        echo "   BASEPROOF_TEST_S3_ENDPOINT=${BASEPROOF_TEST_S3_ENDPOINT:-}"
        echo "   BASEPROOF_TEST_S3_BUCKET=${BASEPROOF_TEST_S3_BUCKET:-}"
        echo "   BASEPROOF_TEST_DSN=${BASEPROOF_TEST_DSN:-}"
        echo "   (tear down with: ./scripts/run-validation.sh soak down)"
        ;;

    s3)
        # User-supplied S3 (e.g. real AWS, R2, MinIO they manage).
        # We don't auto-provision; we just validate the env vars.
        if [ -z "${BASEPROOF_TEST_S3_BUCKET:-}" ]; then
            echo "FATAL: BASEPROOF_TEST_S3_BUCKET not set (backend=s3)"
            exit 1
        fi
        if [ -z "${BASEPROOF_TEST_S3_ENDPOINT:-}" ]; then
            echo "WARN: BASEPROOF_TEST_S3_ENDPOINT not set; defaulting to AWS S3 region endpoint"
        fi
        ;;

    *)
        echo "FATAL: BASEPROOF_SOAK_BYTESTORE_BACKEND=${BACKEND} unsupported"
        echo "       Supported: gcs (default) | seaweedfs (local docker) | s3 (BYO)"
        exit 1
        ;;
esac

# ── Postgres: delegated to scripts/infra (or env-supplied DSN) ───────
# For backend=seaweedfs the `infra up` above already provisioned PG
# and `infra env` exported BASEPROOF_TEST_DSN, so this is a no-op there.
# For backend=gcs / s3 (real cloud or BYO bytestore) we still need a
# local PG — infra_ensure_postgres_up brings it up if no DSN was set.
PROVISIONED_PG=0
if [ -z "${BASEPROOF_TEST_DSN:-}" ]; then
    infra_ensure_postgres_up
    PROVISIONED_PG=1
fi

# Belt-and-suspenders DSN check now that auto-provisioning has had
# its chance. If we're still without a DSN, it's the validation_*
# library's job to tell the operator how to set one.
validation_preflight_dsn

# Defensive: when BACKEND=gcs, the soak goes to REAL GCS — explicitly
# clear any container-mode signal a fake-gcs test harness might have
# left in the environment. No-op for the seaweedfs / s3 paths.
unset BASEPROOF_TEST_GCS_ENDPOINT

# ── Resolve every knob to its final value, then re-export ────────────
#
# Re-exporting closes the "banner-vs-test-process drift" gap: the
# script becomes the single source of truth for "what the test
# process actually saw". Without re-export, an unset env var would
# cause the test process to apply ITS OWN default (defined in Go)
# which might silently drift from what this script's banner
# advertises.
#
# Note on cascading samplers: the test process implements the cascade
# in envSampleCountCascade (tests/soak_test.go). The script intentionally
# does NOT pre-resolve TREE_PROOF / SMT_PROOF here — surfacing the
# cascade resolution in the test process keeps the shape consistent
# with the percent-of-N math (e.g., "10%" needs the actual N at
# resolution time). The banner shows the unresolved state ("(cascade)"
# label) when the per-verifier overrides are unset.
ENTRIES="${BASEPROOF_SOAK_ENTRIES:-1000000}"
CONCURRENCY="${BASEPROOF_SOAK_CONCURRENCY:-8}"
VERIFY_SAMPLES="${BASEPROOF_SOAK_VERIFY_SAMPLES:-100}"
TREE_PROOF_SAMPLES="${BASEPROOF_SOAK_TREE_PROOF_SAMPLES:-(cascade from VERIFY_SAMPLES)}"
SMT_PROOF_SAMPLES="${BASEPROOF_SOAK_SMT_PROOF_SAMPLES:-(cascade from VERIFY_SAMPLES)}"
P99_BOUND_MS="${BASEPROOF_SOAK_P99_BOUND_MS:-100}"
SHIPPER_MAX_IN_FLIGHT="${BASEPROOF_SOAK_SHIPPER_MAX_IN_FLIGHT:-16}"
SEQUENCER_MAX_IN_FLIGHT="${BASEPROOF_SOAK_SEQUENCER_MAX_IN_FLIGHT:-0}"
DRAIN_TIMEOUT="${BASEPROOF_SOAK_DRAIN_TIMEOUT:-10m}"
TEST_TIMEOUT="${BASEPROOF_SOAK_TEST_TIMEOUT:-30m}"
KEEP_DATA="${BASEPROOF_SOAK_KEEP_DATA:-}"

# Re-export the resolved values so the test process sees exactly what
# the banner advertises. TREE_PROOF / SMT_PROOF are only re-exported
# when the operator EXPLICITLY set them — leaving them unset preserves
# the in-test cascade default (envSampleCountCascade falls back to
# VERIFY_SAMPLES). The :+ form expands to nothing when the var is
# unset, so this is a no-op in that case.
export BASEPROOF_SOAK_ENTRIES="${ENTRIES}"
export BASEPROOF_SOAK_CONCURRENCY="${CONCURRENCY}"
export BASEPROOF_SOAK_VERIFY_SAMPLES="${VERIFY_SAMPLES}"
${BASEPROOF_SOAK_TREE_PROOF_SAMPLES:+export BASEPROOF_SOAK_TREE_PROOF_SAMPLES="${BASEPROOF_SOAK_TREE_PROOF_SAMPLES}"}
${BASEPROOF_SOAK_SMT_PROOF_SAMPLES:+export BASEPROOF_SOAK_SMT_PROOF_SAMPLES="${BASEPROOF_SOAK_SMT_PROOF_SAMPLES}"}
export BASEPROOF_SOAK_P99_BOUND_MS="${P99_BOUND_MS}"
export BASEPROOF_SOAK_SHIPPER_MAX_IN_FLIGHT="${SHIPPER_MAX_IN_FLIGHT}"
export BASEPROOF_SOAK_SEQUENCER_MAX_IN_FLIGHT="${SEQUENCER_MAX_IN_FLIGHT}"
export BASEPROOF_SOAK_DRAIN_TIMEOUT="${DRAIN_TIMEOUT}"
${KEEP_DATA:+export BASEPROOF_SOAK_KEEP_DATA="${KEEP_DATA}"}

if [ "${PROVISIONED_PG}" -eq 1 ]; then
    DSN_SOURCE="docker (auto-provisioned)"
else
    DSN_SOURCE="env BASEPROOF_TEST_DSN"
fi

# ── Bytestore display state ──────────────────────────────────────────
#
# Single source of truth for per-backend display. Every banner /
# summary / cleanup line below reads these variables, so adding a
# backend means adding one branch here — not editing three downstream
# blocks. Also guarantees no `set -u` failures from per-backend env
# vars that aren't set in other branches.
case "${BACKEND}" in
    gcs)
        BS_KIND="gcs (real cloud)"
        BS_BUCKET="${BASEPROOF_TEST_GCS_BUCKET}"
        BS_TARGET="gs://${BS_BUCKET}"
        BS_AUTH_MODE="${GOOGLE_APPLICATION_CREDENTIALS:-workload identity / gcloud ADC}"
        BS_LIST_HINT="gsutil ls 'gs://${BS_BUCKET}/soak/**' || echo '(none)'"
        ;;
    seaweedfs)
        BS_KIND="seaweedfs (scripts/infra, Allow-All Mode)"
        BS_BUCKET="${BASEPROOF_TEST_S3_BUCKET}"
        BS_TARGET="${BASEPROOF_TEST_S3_ENDPOINT}/${BS_BUCKET}"
        BS_AUTH_MODE="Allow-All — gateway accepts SigV4 unverified"
        BS_LIST_HINT="docker run --rm --network infra_default -e AWS_ACCESS_KEY_ID=anything -e AWS_SECRET_ACCESS_KEY=anything -e AWS_DEFAULT_REGION=us-east-1 amazon/aws-cli:latest --endpoint-url http://baseproof_infra_seaweedfs:8333 s3 ls 's3://${BS_BUCKET}/' --recursive --summarize | tail -5"
        ;;
    s3)
        BS_KIND="s3 (BYO endpoint)"
        BS_BUCKET="${BASEPROOF_TEST_S3_BUCKET}"
        BS_TARGET="${BASEPROOF_TEST_S3_ENDPOINT:-aws}/${BS_BUCKET}"
        BS_AUTH_MODE="SigV4 via BASEPROOF_TEST_S3_ACCESS_KEY/SECRET_KEY"
        BS_LIST_HINT="aws --endpoint-url '${BASEPROOF_TEST_S3_ENDPOINT:-https://s3.amazonaws.com}' s3 ls 's3://${BS_BUCKET}/' --recursive --summarize | tail -5"
        ;;
esac

if [ -n "${KEEP_DATA}" ]; then
    KEEP_DATA_DISPLAY="yes — entry_index + bytestore objects preserved post-test"
else
    KEEP_DATA_DISPLAY="no  — cleanTables runs on teardown (set BASEPROOF_SOAK_KEEP_DATA=1 to keep)"
fi

echo "== validation profile: soak =="
echo "   dsn source:        ${DSN_SOURCE}"
echo "   bytestore source:  ${BS_KIND}"
echo "   bytestore target:  ${BS_TARGET}"
echo "   auth mode:         ${BS_AUTH_MODE}"
echo "   entries:           ${ENTRIES}"
echo "   concurrency:       ${CONCURRENCY}        (submitter goroutines)"
echo "   sequencer pool:    ${SEQUENCER_MAX_IN_FLIGHT}        (parallel Tessera AppendLeaf; 0 ⇒ default 4)"
echo "   shipper workers:   ${SHIPPER_MAX_IN_FLIGHT}        (parallel uploads)"
echo "   verify:            ${VERIFY_SAMPLES}        (HTTP /raw → 302 follow + SHA-256 round-trip; count or N%)"
echo "   tree-proof:        ${TREE_PROOF_SAMPLES}        (random inclusion proofs vs /v1/tree/head root)"
echo "   smt-proof:         ${SMT_PROOF_SAMPLES}        (random membership proofs vs /v1/smt/root)"
echo "   p99 bound ms:      ${P99_BOUND_MS}"
echo "   drain timeout:     ${DRAIN_TIMEOUT}        (in-test wait for HWM)"
echo "   test timeout:      ${TEST_TIMEOUT}        (go test process ceiling)"
echo "   keep data:         ${KEEP_DATA_DISPLAY}"
validation_witness_banner
echo "   evidence checks:   automated — PG count, contiguity, full bytestore fetch"
echo

validation_start_timer

# Test process timeout. Should comfortably exceed expected
# submission-time + drain-time. Defaults to 30m for the legacy 1M
# soak; bump via BASEPROOF_SOAK_TEST_TIMEOUT for higher-volume runs.
go test -tags=soak \
    -count=1 \
    -timeout "${TEST_TIMEOUT}" \
    -v \
    -run 'TestSoak' \
    ./tests/

WALL_SEC="$(validation_elapsed_secs)"

echo
echo "== summary =="
cat <<EOF
{
  "entries":             ${ENTRIES},
  "concurrency":         ${CONCURRENCY},
  "verify_samples":      "${VERIFY_SAMPLES}",
  "tree_proof_samples":  "${TREE_PROOF_SAMPLES}",
  "smt_proof_samples":   "${SMT_PROOF_SAMPLES}",
  "p99_bound_ms":        ${P99_BOUND_MS},
  "wall_clock_seconds":  ${WALL_SEC},
  "backend":             "${BS_KIND}",
  "bucket":              "${BS_BUCKET}",
  "evidence_verified":   "PG count + contiguity + full bytestore fetch + SHA-256 round-trip + N inclusion proofs vs root + N membership proofs vs SMT root (in-test)",
  "test_status":         "ok"
}
EOF

echo
echo "Containers are still running. Inspect post-test state with:"
echo "  # Postgres row count + sequence-space contiguity:"
echo "  docker exec baseproof_test_postgres psql -U baseproof -d baseproof_test \\"
echo "    -c 'SELECT COUNT(*), MIN(sequence_number), MAX(sequence_number) FROM entry_index;'"
echo
echo "  # Bytestore object count (per-run prefix is logged in the test output as soak/<unix-nano>):"
echo "  ${BS_LIST_HINT}"
echo
echo "  # Sample anonymous fetch — copy a real PublicURL from the test log"
echo "  # ('verifyEvidence: ✓ … sample URL …' line; only present when keep-data is set):"
echo "  curl -sI '<paste-PublicURL-from-test-log>'"
echo
echo "Tear down when finished:"
echo "  ./scripts/run-validation.sh soak down"
