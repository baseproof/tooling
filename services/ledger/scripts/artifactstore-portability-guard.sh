#!/usr/bin/env bash
#
# artifactstore portability guard (ledger#193).
#
# The artifact-store module MUST import ONLY baseproof/storage + standard-library
# / cloud backends — never any other clearcompass-ai/ledger/... package. That is
# the property that lets it relocate ledger -> tooling -> SDK toolkit by a
# directory move. This guard fails the build on any ledger-internal dependency.
#
# Run from the ledger module root (CI).
set -euo pipefail

hits="$(go list -deps ./artifactstore/... \
  | grep '^github.com/baseproof/tooling/services/ledger/' \
  | grep -v '^github.com/baseproof/tooling/services/ledger/artifactstore' || true)"

if [ -n "${hits}" ]; then
  echo "FAIL: artifactstore has ledger-internal dependencies (breaks portability):"
  echo "${hits}" | sed 's/^/  - /'
  exit 1
fi
echo "OK: artifactstore depends only on the SDK + backends (portable)."
