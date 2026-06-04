#!/usr/bin/env bash
# client-contract.sh — enforces the v1.27.x outbound-client contract:
# every binary builds its outbound *http.Client ONCE at boot via
# libs/outbound.HoistFromEnv (or libs/clienttls.BuildFromEnv), then
# threads it into every SDK / libs/* constructor that takes one.
#
# The recurring failure mode is binary main.go doing:
#
#     httpClient := &http.Client{Timeout: 10 * time.Second}
#
# — inline, untyped, posture-blind, at one of N call sites instead of ONE.
# That construction sidesteps every mTLS posture decision the operator
# made; it's the exact "silent plaintext" anti-pattern v1.25.0+v1.27.0
# removed from the SDK. This script catches the symptom in service
# binaries.
#
# Companion to scripts/dependency-law.sh — runs in CI (.github/workflows/
# ci.yml) and locally. Exits non-zero on any violation.
#
# Scope:
#   - services/*/cmd/*/main.go — the binary entry points. Every other
#     surface receives its client by argument, not by construction.
#   - Production code only (not _test.go) — tests legitimately build
#     fixture clients with httptest.NewServer().Client() etc.
#
# An ALLOWLIST_RE escape hatch is provided for the rare legitimate
# in-main construction (e.g. a sidecar's local-only probe). Add a
# comment line "// client-contract: allow <reason>" immediately above
# the &http.Client{ line to whitelist it; the script greps the
# preceding line for that marker.

set -euo pipefail

# shellcheck source=scripts/lib/governed.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/governed.sh"

fail=0
note()    { printf '  %s\n' "$*"; }
violate() { printf '  ::error::%s\n' "$*"; fail=1; }

echo "== client contract: no raw &http.Client{...} in service binary main.go =="

# Find every GOVERNED service-binary main.go (exclude tests). Colocated
# INDEPENDENT tenants (.law-exempt, e.g. services/ledger) are pruned — they
# don't link libs/outbound and aren't bound by this contract.
mains=$(find $(governed_services) -path '*/cmd/*/main.go' -not -name '*_test.go' 2>/dev/null | sort)
if [ -z "$mains" ]; then
  note "no service binaries to check"
else
  for f in $mains; do
    # Grep for &http.Client{ — the construction shape. The allowlist
    # marker is checked one line above each hit.
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      lineno=$(echo "$line" | cut -d: -f1)
      prev=$((lineno - 1))
      if [ "$prev" -ge 1 ]; then
        marker=$(sed -n "${prev}p" "$f" || true)
        if echo "$marker" | grep -q 'client-contract: allow'; then
          note "ALLOW $f:$lineno (marker present)"
          continue
        fi
      fi
      violate "raw &http.Client{ in $f:$lineno — hoist via libs/outbound.HoistFromEnv (see $f line 1)"
    done < <(grep -n '&http\.Client{' "$f" 2>/dev/null || true)
  done
  if [ "$fail" -eq 0 ]; then
    note "ok  every service binary hoists via libs/outbound or libs/clienttls"
  fi
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "client contract: PASS"
else
  echo "client contract: FAIL"
  exit 1
fi
