# witness — standalone witness daemon

A minimal standalone witness HTTP daemon for the Baseproof transparency-log
network. Loads a single secp256k1 PEM key + the network bootstrap document and
serves `POST /v1/cosign` on the configured port. The shipped binary is named
`standalone-witness`.

This is one of the two microservices in the
[`tooling`](../../README.md) monorepo (module
`github.com/baseproof/tooling/services/witness`). It imports **only**
the `baseproof` SDK — never `tooling/libs`, never a network repo.

Designed for multi-instance deployments where a writer ledger needs N external
witnesses to drive a real K-of-N quorum without spinning up N full ledger
processes.

## What it is not

This is NOT a full ledger, and it is NOT a stateful history authority. It does
NOT participate in gossip, hold a database, write tiles, run a builder loop, or
accept admissions. It exclusively serves cosignature requests.

It is a **blind notary**: it lends its cryptographic weight (1-of-N) attesting
that a tree head was presented to it at a moment in time. It deliberately does
**not** try to enforce the log's history — rollback/fork **detection** is owned
by downstream auditors (the [auditor service](../auditor/README.md) and domain
enforcers) via the gossip feed + `EquivocationFinding`. A size-only guard here
couldn't prevent a fork anyway (a malicious ledger can rewrite history and
present a larger `tree_size`), and preventing forks would require persisting
`RootHash` + verifying an RFC 6962 consistency proof on every request — which
this daemon can't do (no log access). So the daemon is intentionally
**stateless**.

## Architecture

The cosign handler (`internal/serve`) wraps the Baseproof SDK's
`cosign.NewWitnessHandler` with one addition: an **in-memory, ephemeral**
concurrent-misfire guard that won't co-sign a `tree_size` smaller than the
largest this *process* has signed since boot. It resets to zero on restart by
design and is never persisted — it catches accidental concurrent/duplicate
misfires, not cross-restart rollbacks (those are the auditors' job; see above).

Network binding: the witness's `NetworkID` is derived from the network bootstrap
document (`network.BootstrapDocument.IDs()`). Requests carrying a different
`network_id` are rejected with 403 by the SDK handler.

## Quick local run (no ledger checkout required)

Run from this module directory (`services/witness/`). The default local-dev path
is Docker — one container per witness:

```sh
make dev-up                                       # 1 witness on :19001
make dev-up WITNESS_COUNT=5                        # K=5 fleet on :19001..:19005
make dev-up WITNESS_COUNT=5 WITNESS_PORT_BASE=29001 # custom base port
make dev-status                                    # docker compose ps
make dev-logs                                      # tail all witness containers
make dev-down                                      # stop + remove containers
```

`make dev-up` runs a preflight (needs Docker + Compose v2), generates the PEM
keys + `BootstrapDocument` host-side, renders `.run/docker-compose.yml`, builds
the image, and waits for every container's `/healthz` to go green.

### No-Docker escape hatch

When Docker isn't available (or you want the fastest inner loop),
`scripts/run-local.sh` spawns the daemons as bare background processes instead:

```sh
make run-local WITNESS_COUNT=5                      # K=5 on :19001..:19005
make run-local WITNESS_COUNT=5 WITNESS_PORT_BASE=29001
make run-local-down                                # stop the fleet
```

Both flows generate the required PEM keys + `BootstrapDocument` JSON in-module
via `cmd/gen-fixtures` and write them under `./.run/`. Each boot also writes
`.run/witness.env` with the `export LEDGER_*` lines a ledger reads — load them
into your shell with `eval "$(make -s print-env)"` (no hand-typed exports). You
do **not** need a ledger checkout. Full operator guide:
[`scripts/local/README.dev.md`](scripts/local/README.dev.md).

## Build

```sh
# from services/witness/
go build -o ./bin/standalone-witness ./cmd/witness
```

Or via `go install`:

```sh
go install github.com/baseproof/tooling/services/witness/cmd/witness@latest
```

## Run

```sh
./bin/standalone-witness \
    -addr :8081 \
    -key-file .run/witnesses/witness-1.pem \
    -bootstrap .run/network-bootstrap.json
```

Flags:

| Flag | Required | Description |
| --- | --- | --- |
| `-addr` | no | HTTP listen address. Default `:8081`. |
| `-key-file` | yes | Path to the witness secp256k1 private key in PEM form (`BASEPROOF SECP256K1 PRIVATE KEY`). |
| `-bootstrap` | yes | Path to the network `BootstrapDocument` JSON (drives the `NetworkID`). |
| `-cosign-purposes` | no | Comma-separated cosign purposes this witness will sign: `tree-head` (default), `rotation`, `escrow-override`. See [Least-privilege scoping](#least-privilege-scoping). |
| `-tls-cert` / `-tls-key` | no | Serve HTTPS. Must be set together. Omit both only behind a TLS-terminating proxy. |
| `-max-rps` / `-burst` | no | Token-bucket DoS limit on `/v1/cosign` (requests/sec + burst). `0` (default) disables; rate-limit at the gateway instead if you prefer. |
| `-version` | no | Print the build version (stamped via `-ldflags -X main.version`) and exit. |

The keypair + bootstrap document are generated by this module's
`cmd/gen-fixtures` (run by `make run-local` and `make dev-up`), or — if you
already have a ledger checkout — by the Baseproof Ledger's `cmd/genesis-ceremony` (dev mode)
tool. Both produce the same on-disk shape:
`<dir>/witnesses/witness-<i>.pem` + `<dir>/network-bootstrap.json`.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| POST | `/v1/cosign` | Cosignature endpoint. Body is a `cosign.WireRequest` with `Purpose = "BP-COSIGN-TREE-V1"`. Mounted by `cosign.NewWitnessHandler`. |
| GET | `/metrics` | Prometheus scrape (`witness_cosign_requests_total`, `witness_cosign_request_seconds`, `witness_build_info`, + process/Go runtime). Same listener — ACL it at the proxy if it must not be public. |
| GET | `/healthz` | Liveness probe. Returns `ok` with 200 once the cosign handler is wired and listening. |

### Canonical tree-head payload

As of baseproof v1.9.x the cosign tree-head payload is the 104-byte canonical form
`root_hash ‖ smt_root ‖ receipt_root ‖ tree_size`. `receipt_root` is the Merkle
root over the batch's Web3 verification receipts and is **required** on the wire
(the 32-byte zero hash is the valid empty-batch sentinel). The SDK handler
rejects an all-zero `root_hash`/`smt_root` and signs the canonical message; the
witness adds only the local monotonicity guard on `tree_size`.

### Least-privilege scoping

A witness key is a high-value attestation key. The SDK handler will, by default
(`AllowedPurposes` nil), sign **every** registered cosign purpose — turning
`/v1/cosign` into a signing oracle for witness-set `rotation` and
`escrow-override` votes, not just tree-head attestation. DST separation stops a
tree-head signature from being *replayed* as a rotation signature, but it does
not stop the witness from being *asked* to sign a genuine rotation/override
payload.

So this daemon defaults `-cosign-purposes=tree-head` (only `PurposeTreeHead`
admitted; anything else gets 403). This is the **correct** default, not just the
tightest: a witness's `/v1/cosign` is a **commit-clock** endpoint that collects
exactly one thing — tree-head cosignatures per cadence. Witness-set rotation is
a **transparency-clock** (gossip) operation, assembled out-of-band and ingested
as a pre-validated finding, never collected over `/v1/cosign`.

Widen it only for a witness that genuinely contributes its own rotation
cosignature over HTTP:

```sh
./bin/standalone-witness -cosign-purposes=tree-head,rotation …
```

## Graceful shutdown

`SIGINT` / `SIGTERM` triggers `http.Server.Shutdown` with a 5s deadline.
In-flight cosign requests complete; new connections are rejected.

## Test

```sh
# Fast feedback (unit tests only):
go test -short ./...

# Full suite (includes the daemon e2e test that builds + execs the binary):
go test ./...
```

## Module boundary

This module imports only `github.com/baseproof/baseproof` (plus
`prometheus/client_golang` and `golang.org/x/time/rate`, confined to
`internal/obs`). It never imports `tooling/libs`,
`github.com/clearcompass-ai/ledger`, or any other project repository — the
witness daemon is intentionally isolated from ledger application state, and its
cosign handler lives under `internal/` so the compiler forbids outside imports.
