# scripts/lib/validation_common.sh
#
# Sourced by run-validation.sh and the per-profile _validation_*.sh
# scripts. POSIX-only — no bashisms — so it works under either
# /bin/sh or /bin/bash without surprise. Don't add `local`, `[[ ]]`,
# arrays, `set -o pipefail`, or process-substitution `<()` to this
# file.
#
# Functions exported:
#
#   validation_print_usage     — prints the canonical multi-profile
#                                usage block to stderr. Single source
#                                of truth for the operator-facing
#                                env-var inventory.
#
#   validation_preflight_dsn   — asserts BASEPROOF_TEST_DSN is set;
#                                prints actionable error + exits 1
#                                if not. Both profiles need Postgres,
#                                so the check lives here, not per-
#                                profile.
#
#   validation_start_timer     — captures the wall-clock start time
#                                in VALIDATION_START_NS (global,
#                                because POSIX functions can't return
#                                multi-byte values without an extra
#                                fork).
#
#   validation_elapsed_secs    — echoes integer seconds since
#                                validation_start_timer. Caller embeds
#                                in its own summary so each profile
#                                keeps full control of summary
#                                formatting.

# Print the canonical usage block. Routed to stderr because operator
# error (no profile, unknown profile) belongs there. Heredoc with
# 'EOF' (quoted) prevents variable expansion inside.
validation_print_usage() {
    cat >&2 <<'EOF'
Usage: ./scripts/run-validation.sh <profile> [profile-args]

Profiles:
  determinism   SCT byte-identity contract validation (scale + e2e).
                Production-shape: Postgres + SeaweedFS (S3) provisioned
                via scripts/infra. Default 10K pairs. The shipper
                migrates every entry into SeaweedFS during the run, so
                the determinism contract is verified against the real
                byte-store wire (set BYTESTORE=memory for the legacy
                in-memory smoke). Tests TestScale_DeterministicReplay
                (-tags=scale).

  soak          Throughput + bytestore durability + Merkle integrity.
                Heavy. Requires S3-compatible bytestore + Postgres.
                Default 1M entries. Wall time depends on N.
                Tests TestSoak_LedgerBytestore (-tags=soak).

Both profiles provision their infra (Postgres + SeaweedFS) via
scripts/infra when BASEPROOF_TEST_DSN is unset, and tear it down with
the `down` subcommand. Bring your own Postgres by exporting
BASEPROOF_TEST_DSN; bring your own S3 by exporting BASEPROOF_TEST_S3_*.

Required env (all profiles):
  BASEPROOF_TEST_DSN          Postgres connection string. Auto-provisioned
                            via `scripts/infra up` when unset; pass it in
                            (with BASEPROOF_TEST_S3_*) to use your own.

Witness tier (DISCOVERED via env — these profiles never orchestrate it):
  LEDGER_WITNESS_ENDPOINTS      CSV of witness cosign base URLs. SET ⇒ the
                                run cosigns checkpoints against that fleet
                                (production-shape K-of-N quorum). UNSET ⇒
                                NON-WITNESS, with a warning (not fatal).
  LEDGER_WITNESS_QUORUM_K       K threshold (default 1; must be ≤ endpoints).
  LEDGER_NETWORK_BOOTSTRAP_FILE bootstrap JSON → NetworkID. REQUIRED when
                                LEDGER_WITNESS_ENDPOINTS is set.
  Stand a fleet up yourself (e.g. ../tooling/services/witness/scripts/run-local.sh)
  and export these — the profiles connect to it; they do not spawn it.

Profile-specific env (knobs documented in each profile body):
  determinism:  BASEPROOF_SCALE_DETERMINISM_{N,CONCURRENCY,
                  MAX_DURATION,STOP_ON_DRIFT,TIMEOUT,BYTESTORE}
  soak:         BASEPROOF_SOAK_{ENTRIES,CONCURRENCY,
                  VERIFY_SAMPLES,TREE_PROOF_SAMPLES,SMT_PROOF_SAMPLES,
                  P99_BOUND_MS,SHIPPER_MAX_IN_FLIGHT,
                  SEQUENCER_MAX_IN_FLIGHT,DRAIN_TIMEOUT,
                  TEST_TIMEOUT,BYTESTORE_BACKEND,KEEP_DATA}
                Plus BASEPROOF_TEST_S3_*  (s3 / seaweedfs backends)
                  or BASEPROOF_TEST_GCS_BUCKET (gcs backend).

  Soak's VERIFY_SAMPLES cascades to TREE_PROOF_SAMPLES + SMT_PROOF_SAMPLES
  when those are unset. Set VERIFY_SAMPLES once and every sampled
  verifier scales together; override individuals only when needed.

Examples:
  ./scripts/run-validation.sh determinism            # 10K pairs on SeaweedFS
  BASEPROOF_SCALE_DETERMINISM_N=1000 \
    ./scripts/run-validation.sh determinism          # 1K smoke on SeaweedFS
  BASEPROOF_SCALE_DETERMINISM_BYTESTORE=memory \
    ./scripts/run-validation.sh determinism          # in-memory smoke

  BASEPROOF_SOAK_ENTRIES=10000 BASEPROOF_SOAK_VERIFY_SAMPLES=10% \
    ./scripts/run-validation.sh soak

  ./scripts/run-validation.sh determinism down       # tear down infra
  ./scripts/run-validation.sh soak down              # tear down infra

Backward-compatible entry points:
  ./scripts/run-soak.sh                → run-validation.sh soak
  ./scripts/run-scale-determinism.sh   → run-validation.sh determinism
EOF
}

# Asserts BASEPROOF_TEST_DSN is set; exits 1 with an actionable message
# otherwise. Profiles that auto-provision Postgres (soak, currently)
# call this AFTER their own provisioning attempt, so the only path
# this fires through is "no DSN AND no docker."
validation_preflight_dsn() {
    if [ -z "${BASEPROOF_TEST_DSN:-}" ]; then
        cat >&2 <<'EOF'
FATAL: BASEPROOF_TEST_DSN not set

  export BASEPROOF_TEST_DSN='postgres://baseproof:baseproof@localhost:5432/baseproof_test?sslmode=disable'

  Or run scripts/run-local.sh up to auto-provision Postgres.
EOF
        exit 1
    fi
}

# Stamps the wall-clock start time. Single global VALIDATION_START_NS
# is the simplest portable carrier — POSIX functions can't return
# multi-byte values via stdout without an extra subshell fork, and
# we don't want timing helpers to fork.
validation_start_timer() {
    VALIDATION_START_NS=$(date +%s%N)
}

# Echoes integer seconds elapsed since validation_start_timer. Caller
# captures via $(validation_elapsed_secs).
#
# Note: macOS BSD `date` doesn't support %N — falls back to
# nanosecond-zero, so ELAPSED_S resolves to 0 on macOS. To keep the
# library single-platform, we accept that quirk; the per-profile
# scripts can override timing if sub-second resolution ever matters.
validation_elapsed_secs() {
    end_ns=$(date +%s%N)
    echo $(( (end_ns - VALIDATION_START_NS) / 1000000000 ))
}

# infra_ensure_postgres_up brings up the unified `scripts/infra`
# topology IFF the canonical Postgres container isn't already
# running. This is the single chokepoint every legacy test-runner
# script (run-cursor-tests, run-gcs-tests, run-p4, run-integration,
# _validation_soak, etc.) calls instead of running its own
# `docker compose ... up postgres`.
#
# Rationalization (the verb-aligned post-N6 model):
#   - `scripts/infra` owns the ledger's OWN multi-test infra
#     (Postgres + SeaweedFS + S3 bucket). It does NOT run a witness
#     tier — witnesses are owned by the tooling repo (services/witness) and
#     DISCOVERED via the LEDGER_WITNESS_* env, never orchestrated here.
#   - Every other script becomes a thin "I assume infra is up"
#     consumer.
#   - On macOS where Docker Desktop isn't running, the operator
#     sees ONE failure mode (start Docker Desktop) instead of
#     N-script-specific surfaces.
#
# Exports BASEPROOF_TEST_DSN if it was unset, so callers can keep
# their existing `validation_preflight_dsn` check intact.
#
# No-op if BASEPROOF_TEST_DSN is already pointed at an external PG
# (e.g., CI running its own service container) — we do not touch
# Docker in that case.
infra_ensure_postgres_up() {
    if [ -n "${BASEPROOF_TEST_DSN:-}" ]; then
        return 0  # operator/CI supplied their own PG; do nothing
    fi
    if ! command -v docker >/dev/null 2>&1; then
        cat >&2 <<'EOF'
FATAL: BASEPROOF_TEST_DSN unset AND docker CLI not on PATH

  Either:
    export BASEPROOF_TEST_DSN='postgres://...'      # bring your own PG
  Or install Docker + run:
    ./scripts/infra up                            # provisions infra
EOF
        return 1
    fi
    # Check .State.Running, not mere existence — `docker inspect` succeeds
    # for a STOPPED container, which would skip `infra up` and leave the
    # test hitting a dead port.
    running_pg="$(docker inspect -f '{{.State.Running}}' baseproof_test_postgres 2>/dev/null || echo false)"
    if [ "${running_pg}" != "true" ]; then
        REPO_ROOT_INFRA="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
        : "${REPO_ROOT_INFRA:?cannot resolve repo root}"
        echo "== BASEPROOF_TEST_DSN unset and baseproof_test_postgres not running — provisioning via scripts/infra =="
        "${REPO_ROOT_INFRA}/scripts/infra" up
    fi
    # Export the canonical DSN that `scripts/infra env` would emit.
    export BASEPROOF_TEST_DSN="postgres://baseproof:baseproof@localhost:5544/baseproof_test?sslmode=disable"
}

# validation_ensure_seaweedfs_infra brings up the ledger's OWN test
# infra (Postgres + SeaweedFS + S3 bucket) via scripts/infra and imports
# its env (BASEPROOF_TEST_DSN + BASEPROOF_TEST_S3_*). The single chokepoint
# the soak + determinism profiles share for the LOCAL-Docker bytestore.
#
# The `seaweedfs` backend is local-Docker BY DEFINITION — a truly
# external bytestore uses the `s3` backend instead — so this ensures the
# canonical container is actually RUNNING and never trusts BASEPROOF_TEST_*
# that may be stale in the operator's shell. A torn-down / crashed
# container with leftover exports must be re-provisioned, not silently
# skipped (skipping surfaces as "connection refused" at test time). It
# NEVER provisions witnesses.
validation_ensure_seaweedfs_infra() {
    if ! command -v docker >/dev/null 2>&1; then
        cat >&2 <<'EOF'
FATAL: the seaweedfs backend needs Docker so scripts/infra can provision
       Postgres + SeaweedFS. Start Docker, or use a bring-your-own
       bytestore: BASEPROOF_SOAK_BYTESTORE_BACKEND=s3 with BASEPROOF_TEST_S3_*
       (+ BASEPROOF_TEST_DSN for an external Postgres).
EOF
        return 1
    fi
    REPO_ROOT_INFRA="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
    : "${REPO_ROOT_INFRA:?cannot resolve repo root}"
    # `docker inspect` alone is insufficient — it succeeds for a STOPPED
    # container — so read .State.Running. This re-provisions a
    # stopped/crashed/absent container even when BASEPROOF_TEST_* is still
    # exported in the shell from a previous (now torn-down) run.
    running="$(docker inspect -f '{{.State.Running}}' baseproof_infra_seaweedfs 2>/dev/null || echo false)"
    if [ "${running}" != "true" ]; then
        echo "== provisioning Postgres + SeaweedFS via scripts/infra =="
        "${REPO_ROOT_INFRA}/scripts/infra" up
    fi
    # Always import the canonical env from the RUNNING infra so
    # BASEPROOF_TEST_DSN / BASEPROOF_TEST_S3_* reflect the live containers,
    # overwriting any stale values in the shell.
    # shellcheck disable=SC2046  # word-splitting of export lines is intended
    eval "$("${REPO_ROOT_INFRA}/scripts/infra" env)"
}

# validation_witness_banner prints whether the witness tier was
# DISCOVERED from the env, and warns when it was not. The validation
# profiles never spawn witnesses — they consume an externally-run fleet
# via the SAME env contract the production ledger reads:
#
#   LEDGER_WITNESS_ENDPOINTS      CSV of witness cosign base URLs
#   LEDGER_WITNESS_QUORUM_K       K threshold (default 1)
#   LEDGER_NETWORK_BOOTSTRAP_FILE bootstrap JSON → NetworkID binding
#
# These are read by the Go test (cosignerFromEnv); this banner only
# surfaces the resolved state so the operator sees, up front, whether
# the run exercises quorum or falls back to NON-WITNESS.
validation_witness_banner() {
    if [ -n "${LEDGER_WITNESS_ENDPOINTS:-}" ]; then
        echo "   witnesses:        DISCOVERED — ${LEDGER_WITNESS_ENDPOINTS} (K=${LEDGER_WITNESS_QUORUM_K:-1})"
        echo "   network bootstrap: ${LEDGER_NETWORK_BOOTSTRAP_FILE:-<unset — REQUIRED with endpoints>}"
    else
        echo "   witnesses:        NONE — running NON-WITNESS (no quorum)"
        echo "   (export LEDGER_WITNESS_ENDPOINTS + LEDGER_NETWORK_BOOTSTRAP_FILE [+ LEDGER_WITNESS_QUORUM_K]"
        echo "    pointing at an already-running fleet to exercise the K-of-N cosign path)"
    fi
}
