#!/usr/bin/env bash
# governed.sh — shared helper for the monorepo layering/contract scripts
# (dependency-law.sh, client-contract.sh). Sourced, not executed.
#
# A subtree opts OUT of the laws by carrying a `.law-exempt` marker at its root:
# a colocated but INDEPENDENT tenant with its own go.mod + go.work + CI + image
# (e.g. services/ledger). The laws govern the agnostic half (libs + the
# first-party services); exempt tenants are validated by their own pipeline.
# A future colocated domain network just drops its own .law-exempt — no edit
# to these scripts is needed.

# law_exempt <dir> — succeeds if <dir> or any ancestor up to the repo root
# carries a .law-exempt marker.
law_exempt() {
  local d="$1"
  while [ -n "$d" ] && [ "$d" != "." ] && [ "$d" != "/" ]; do
    [ -e "$d/.law-exempt" ] && return 0
    d=$(dirname "$d")
  done
  return 1
}

# governed_services — prints the services/* roots the laws govern (exempt
# tenants pruned), one per line. Used by the blanket grep scans (LAW 3, LAW 4b,
# the client contract) that would otherwise sweep an exempt tenant's source.
governed_services() {
  local s
  find services -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | while read -r s; do
    law_exempt "$s" || printf '%s\n' "$s"
  done
}
