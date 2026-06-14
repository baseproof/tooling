#!/usr/bin/env bash
# declare-genesis-witness-endpoints.sh — PRE-12 genesis bootstrap: seed the
# on-log witness-endpoint set at network birth.
#
# After the genesis ceremony, each genesis witness self-declares its dial
# endpoint on-log (signed with its own genesis key) so the ledger's by-kind
# resolver has the witness dial-list at FIRST boot — the producer side that
# lets LEDGER_WITNESS_ENDPOINTS stay deleted. This is the genesis-endorse
# shape: each witness self-signs its own declaration; this script collects and
# submits them.
#
# Each genesis witness's PubKeyID is already in the constitution's
# GenesisWitnessSet, so admission (PRE-12 step 4h) authorizes the declaration.
#
# Usage:
#   LEDGER_URL=https://ledger LOG_DID=did:baseproof:network:self \
#   WITNESS_ENDPOINTS="w1.hex=https://w1 w2.hex=https://w2 w3.hex=https://w3" \
#   [LEDGER_TOKEN=tok] ./declare-genesis-witness-endpoints.sh
#
# WITNESS_ENDPOINTS is a whitespace-separated list of "<key-file>=<public-url>"
# pairs — each <key-file> a raw-hex secp256k1 scalar (the genesis-ceremony key
# dialect). The on-log resolution itself is by-kind, so no schema position is
# required.
set -euo pipefail

: "${LEDGER_URL:?set LEDGER_URL to the network's ledger base URL}"
: "${LOG_DID:?set LOG_DID to the network's log DID}"
: "${WITNESS_ENDPOINTS:?set WITNESS_ENDPOINTS as \"key=url ...\" pairs}"

BIN="${DECLARE_WITNESS_ENDPOINT:-declare-witness-endpoint}"

n=0
for pair in $WITNESS_ENDPOINTS; do
  key="${pair%%=*}"
  url="${pair#*=}"
  if [ "$key" = "$url" ] || [ -z "$key" ] || [ -z "$url" ]; then
    echo "skip malformed pair (want key=url): $pair" >&2
    continue
  fi
  echo "declaring witness endpoint: key=$key url=$url"
  "$BIN" -url "$LEDGER_URL" -log-did "$LOG_DID" -key "$key" -public-url "$url" ${LEDGER_TOKEN:+-token "$LEDGER_TOKEN"}
  n=$((n + 1))
done
echo "declare-genesis-witness-endpoints: declared $n genesis witness endpoint(s) on-log."
