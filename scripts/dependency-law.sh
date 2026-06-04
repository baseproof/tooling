#!/usr/bin/env bash
# dependency-law.sh — enforces the tooling-monorepo layering with the Go
# toolchain, not review discipline. Run from the repo root. Exits non-zero on
# any violation. Used by CI (.github/workflows/ci.yml) and locally.
#
#   baseproof (SDK)  <-  libs/*  <-  services/*          ✓
#   libs/*    -> services/*                              ✗
#   libs/* | services/*  -> any network/domain module    ✗
#   services/*  -> a remote Sign surface                  ✗   (keystore is linked, not dialed)
#
# Each check builds modules in isolation (GOWORK=off) so the workspace can't
# mask a forbidden edge.
set -euo pipefail

export GOWORK=off
export GOPRIVATE="${GOPRIVATE:-github.com/clearcompass-ai/*,github.com/baseproof/*}"

REPO="github.com/baseproof/tooling" # the monorepo module-path root
# Domain/network modules the agnostic half (libs + first-party services) may
# never link. The ledger appears at BOTH its retired standalone path
# (clearcompass-ai/ledger) and its new in-repo path
# (baseproof/tooling/services/ledger): it now lives at
# services/ledger but stays a domain tenant the tools must not import.
DOMAIN_RE='clearcompass-ai/(judicial-network|ledger|[a-z0-9-]*-network)|baseproof/tooling/services/ledger'

fail=0
note()    { printf '  %s\n' "$*"; }
violate() { printf '  ::error::%s\n' "$*"; fail=1; }

# shellcheck source=scripts/lib/governed.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/governed.sh"

# Every GOVERNED module under libs/ and services/ (each carries its own go.mod).
# Colocated INDEPENDENT tenants (a .law-exempt marker at their root, e.g.
# services/ledger) are pruned — they bring their own toolchain and CI, and the
# tenant's own self-referential deps would otherwise trip LAW 1.
MODDIRS=$(find libs services -name go.mod -not -path '*/vendor/*' -exec dirname {} \; 2>/dev/null \
  | while read -r d; do law_exempt "$d" || printf '%s\n' "$d"; done | sort)

echo "== LAW 1: no lib or service links a network/domain module =="
for d in $MODDIRS; do
  hits=$( cd "$d" && go list -deps ./... 2>/dev/null | grep -E "$DOMAIN_RE" || true )
  if [ -n "$hits" ]; then violate "$d links domain/network: $(echo "$hits" | tr '\n' ' ')"; else note "ok  $d"; fi
done

echo "== LAW 2: libs do not depend on services =="
for d in $MODDIRS; do
  case "$d" in libs*) ;; *) continue ;; esac
  hits=$( cd "$d" && go list -deps ./... 2>/dev/null | grep "$REPO/services/" || true )
  if [ -n "$hits" ]; then violate "$d depends on a service: $(echo "$hits" | tr '\n' ' ')"; else note "ok  $d"; fi
done

echo "== LAW 3: keystore stays linked, not dialed (no remote Sign surface in services) =="
if grep -rEn '\b(Sign|SignEntry)\b[^)]*\b(grpc|proto|rpc)\b' $(governed_services) 2>/dev/null; then
  violate "a service exposes a remote Sign surface"
else
  note "ok"
fi

# LAW 4 is the Separation-of-Duties guarantee: the durable gossip.Store (the
# custodial record of fraud evidence) lives ONLY in services/auditor/internal,
# where Go's internal/ rule makes it un-importable by any lib, any other service,
# or any external repo (an enforcer like judicial-network). Custody is therefore
# physically disjoint from enforcement — proven by the compiler, not a memo.
echo "== LAW 4: custody isolation — the gossip.Store impl is auditor-internal only =="
# (a) no lib carries a store impl (libs are custody-free).
if grep -rln 'func NewPostgresStore\|type PostgresStore' libs/ 2>/dev/null | grep -q .; then
  violate "libs/ contains a gossip.Store impl — custody belongs to the auditor"
else
  note "ok  libs custody-free"
fi
# (b) every store impl lives under services/auditor/internal/ (un-importable).
store_dirs=$(grep -rln 'func NewPostgresStore' $(governed_services) 2>/dev/null | xargs -n1 dirname 2>/dev/null | sort -u || true)
if [ -z "$store_dirs" ]; then
  note "ok  (no store impl yet)"
else
  for sd in $store_dirs; do
    case "$sd" in
      services/auditor/internal/*) note "ok  store impl in $sd (auditor-internal)" ;;
      *) violate "store impl in $sd is not under services/auditor/internal (custody leak)" ;;
    esac
  done
fi
# (c) libs link no store impl (the verify toolkit never touches custody).
for d in $MODDIRS; do
  case "$d" in libs*) ;; *) continue ;; esac
  hits=$( cd "$d" && go list -deps ./... 2>/dev/null | grep -E 'auditor/internal/store|PostgresStore' || true )
  if [ -n "$hits" ]; then violate "$d links the custodial store"; fi
done

echo
if [ "$fail" -eq 0 ]; then echo "dependency law: PASS"; else echo "dependency law: FAIL"; exit 1; fi
