#!/usr/bin/env bash
#
# no-silent-fallback-anchor.sh — v1.34 SDK contract enforcer for the
# anchor publish surface.
#
# The v1.34 baseproof SDK removed silent fallback to a plaintext
# DefaultClient from every constructor that takes an *http.Client.
# The intent: a misconfigured operator must NOT be able to publish
# anchors / fetch peer tree heads over plaintext without a loud
# signal. The ledger's anchor/ package is the federation's most
# security-sensitive outbound (anchor publishing across 15 networks
# × 3-10 exchanges, parent-target federation, peer head fetch).
#
# This script enforces the contract STATICALLY at CI time: any
# `sdklog.DefaultClient(*, nil)` inside anchor/**/*.go — outside an
# explicit comment-block allowlist — is rejected.
#
# The allowed pattern is panic-at-construction with a v1.34 reference
# in the panic message (see anchor/publisher.go:NewPublisher and
# anchor/publisher.go:SubmitToHTTPEndpoint for the canonical shape).
#
# Exit codes:
#   0  - no violations
#   1  - one or more violations detected
#
# Usage:
#   bash scripts/no-silent-fallback-anchor.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANCHOR_DIR="${REPO_ROOT}/anchor"

if [[ ! -d "${ANCHOR_DIR}" ]]; then
    echo "no-silent-fallback-anchor.sh: missing ${ANCHOR_DIR}"
    exit 1
fi

# Find any sdklog.DefaultClient invocation in anchor/ production code
# (not _test.go) whose TLS argument is literal nil — that is the
# silent-fallback shape.
#
# The grep pattern matches the canonical violation:
#   sdklog.DefaultClient(<anything>, nil)
# and reports the file:line so a developer can jump straight to it.
#
# The awk filter strips comment-only lines: a line where the FIRST
# non-whitespace token is `//` is a doc comment and not subject to
# the contract (the comment may legitimately reference the pattern
# to document it).
violations="$(
    grep -nE 'sdklog\.DefaultClient\([^)]*,\s*nil\s*\)' \
        "${ANCHOR_DIR}"/*.go 2>/dev/null \
        | grep -v '_test\.go:' \
        | awk -F: '{
            # Reassemble the line content (everything after file:lineno:).
            line = ""
            for (i = 3; i <= NF; i++) line = line (i > 3 ? ":" : "") $i
            # Strip leading whitespace.
            sub(/^[[:space:]]+/, "", line)
            # Drop pure comment lines.
            if (substr(line, 1, 2) == "//") next
            print $0
        }' \
        || true
)"

if [[ -n "${violations}" ]]; then
    echo "no-silent-fallback-anchor.sh: v1.34 SDK contract violation(s) in anchor/:"
    echo "${violations}"
    echo
    echo "The anchor publish surface is the federation's most security-sensitive"
    echo "outbound. A silent fallback to a plaintext DefaultClient lets a"
    echo "misconfigured operator publish anchors / fetch peer tree heads over"
    echo "plaintext WITHOUT any signal — exactly the failure mode the v1.34 SDK"
    echo "release rejected across every constructor that takes an *http.Client."
    echo
    echo "Fix: replace the silent fallback with a panic-at-construction that"
    echo "cites the v1.34 contract. See anchor/publisher.go::NewPublisher for"
    echo "the canonical pattern."
    echo
    exit 1
fi

echo "no-silent-fallback-anchor.sh: PASS (no silent fallback to a plaintext default in anchor/)"
