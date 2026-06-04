# Local dev — running the standalone-witness daemon

Three ways to run a K=N witness fleet on your laptop:

| Flow | Entry point | Needs | When |
|---|---|---|---|
| **Docker** (default) | `make dev-up` | Docker + Docker Compose v2 | The standard local-dev path. |
| **Go-native** (no-Docker escape hatch) | `make run-local` | Go (≥ the version in `go.mod`) | Docker unavailable, or fastest inner loop. |
| **Against a separate ledger checkout** | `LEDGER_WITNESS_ENDPOINTS=…` | Both repos, plus ledger's own prereqs | Driving a real writer at this fleet. |

All three produce the same on-disk fixtures under `./.run/`:

```
.run/
├── network-bootstrap.json          # BootstrapDocument JSON
├── witness.env                     # export LEDGER_* lines (eval/source)
├── witnesses/
│   ├── witness-1.pem               # secp256k1 private key, raw-scalar PEM
│   ├── witness-2.pem
│   └── ...
├── logs/witness-<i>.log            # Go-native flow only
├── witness-pids                    # Go-native flow only
└── docker-compose.yml              # Docker flow only (generated)
```

The fixtures are generated **in-module** by `cmd/gen-fixtures`.
You do **not** need a ledger checkout to run the daemon.

---

## Docker flow — `make dev-up` (default)

Every daemon runs in its own container, built from the module-root
`Dockerfile`. This is the standard local-dev path.

```bash
make dev-up                                 # 1 witness on :19001
make dev-up WITNESS_COUNT=5                 # K=5 on :19001..:19005
make dev-up WITNESS_COUNT=5 WITNESS_PORT_BASE=29001
```

What it does:

1. `make dev-preflight` — verifies Docker + Compose v2 are usable and the daemon is reachable
2. `make gen-fixtures` against the host (so PEM keys + bootstrap
   land in `./.run/`, then bind-mounted read-only into each container)
3. `scripts/local/render-compose.sh` emits `.run/docker-compose.yml`
   listing exactly `$WITNESS_COUNT` services
4. `docker compose -f .run/docker-compose.yml up -d --build`
5. Waits for every container's `/healthz` to report healthy

Inspect:

```bash
make dev-status              # docker compose ps
make dev-logs                # tail logs across all witnesses (Ctrl-C to stop)
```

Tear down:

```bash
make dev-down                # docker compose down -v (containers + networks)
```

`make dev-down` does **not** delete `./.run/` — keys + bootstrap
survive. Add `make clean-run` (or `rm -rf .run`) if you want a
fresh keyset.

---

## Go-native flow — `make run-local` (no-Docker escape hatch)

When Docker isn't available — or you want the fastest inner loop —
this spawns one bare background process per witness instead of a
container. Same fixtures, same ports, no Docker daemon required.

```bash
make run-local                                        # 1 witness on :19001
make run-local WITNESS_COUNT=5                        # K=5 on :19001..:19005
make run-local WITNESS_COUNT=5 WITNESS_PORT_BASE=29001
```

What it does:

1. `go run ./cmd/gen-fixtures -witnesses=$WITNESS_COUNT -out-dir=.run`
2. `go build -o ./bin/standalone-witness .`
3. Spawns `$WITNESS_COUNT` daemon copies in the background, logs to `.run/logs/witness-<i>.log`, PIDs tracked in `.run/witness-pids`
4. Polls `/healthz` on each port until ready (50 × 200 ms = 10 s)
5. Writes `.run/witness.env` (`export LEDGER_*` lines) — load the fleet into a ledger shell with `eval "$(make -s print-env)"`, no hand-typed exports

Tear down:

```bash
make run-local-down
```

This reads `.run/witness-pids` and `kill`s each PID. Tear-down is
idempotent — re-running on an empty PID file is a no-op.

---

## Driving a separate ledger at this fleet

This module knows nothing about ledger orchestration; that's the
ledger repo's `scripts/run-local.sh`. Every boot here writes
`.run/witness.env` with the `export LEDGER_*` lines the ledger reads.
Load them into your shell without hand-typing:

```bash
# In THIS repo, after `make run-local` / `make dev-up`:
eval "$(make -s print-env)"           # sets LEDGER_WITNESS_ENDPOINTS,
                                      # LEDGER_WITNESS_QUORUM_K,
                                      # LEDGER_NETWORK_BOOTSTRAP_FILE
# or: source .run/witness.env

# then drive the ledger from the SAME shell:
cd /path/to/ledger && ./scripts/run-local.sh   # writer only, NOT its own witnesses
```

`.run/witness.env` carries an absolute bootstrap path, so it works
from any directory, and is regenerated on every boot — re-run the
`eval` after a fleet restart.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `make run-local`: `FATAL: 'go' not on PATH` | Go toolchain not installed | Install Go (see `go.mod` for the minimum version). |
| `make run-local`: `FATAL: port :19001 is in use` | Another process holds the port | Stop that process, or pass `WITNESS_PORT_BASE=29001`. |
| `/healthz` never returns `ok` | Witness daemon failed to boot | `tail .run/logs/witness-<i>.log`. Common cause: a malformed bootstrap doc. |
| `gen-fixtures: validate bootstrap document` error | An ExchangeDID / NetworkName field is empty or the GenesisWitnessSet collapsed to zero entries | Re-run with explicit `-witnesses=N >= 1` and non-empty `-log-did`, `-network-name`. |
| `make dev-up`: `command not found: docker compose` | Docker Compose v2 missing | Install Docker Compose v2. v1 (`docker-compose`) is not supported. |
| `make dev-up` succeeds but containers exit immediately | `.run/network-bootstrap.json` missing or stale | `rm -rf .run` and re-run `make dev-up`. The Makefile chains `gen-fixtures` before `render-compose`. |
| Witness rejects every cosign with 403 | Request `network_id` doesn't match the bootstrap doc's derived `NetworkID` | The client must use the SAME `network-bootstrap.json` the daemon was started with. Recover by re-pointing the client (or regenerating fixtures so both sides match). |
| Cosign returns 409 Conflict | A `tree_size` smaller than `lastSignedSize` was requested | Expected behaviour — the monotonicity guard rejects rollbacks. See `internal/serve/serve.go`. |

---

## Cosign payload (baseproof v1.9.x canonical form)

The single endpoint `POST /v1/cosign` accepts the canonical 104-byte
tree-head payload: `root_hash ‖ smt_root ‖ receipt_root ‖ tree_size`.
`receipt_root` (the Merkle root over the batch's Web3 verification
receipts) is **required** on the wire; the 32-byte zero hash is the
valid empty-batch sentinel. Any cosign client posting to this witness
must include `receipt_root`. The SDK handler rejects an all-zero
`root_hash`/`smt_root` and signs the canonical message; the witness
adds only the local monotonicity guard on `tree_size`.

## K=N notes

The daemon enforces one rule that's only visible at K ≥ 2:
the **monotonicity guard** in `internal/serve/serve.go` tracks
`lastSignedSize` **per process**. State resets on daemon
restart — the authoritative non-rollback guarantee comes from
the writer ledger's hash chain + Tessera log layer; the
witness's local guard is belt-and-braces.

Practical consequence: if you `make run-local-down && make
run-local` between two cosign requests at the same `tree_size`,
the second request is accepted (a fresh process has no memory of
the first). This is deliberate and matches the daemon's
documented design.

For a true persistent-monotonicity deployment, run the daemon
behind a sidecar that journals `lastSignedSize` to disk and
restores it on boot. Out of scope for this module.
