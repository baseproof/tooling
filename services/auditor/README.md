# auditor — evidence custodian

The auditor is the **external evidence custodian** in the network's
Separation-of-Duties split. It is *not* an enforcer and holds no domain
authority: it independently observes the transparency plane and keeps the durable
record of misbehavior, so that enforcers (domain networks like
`judicial-network`) never custody evidence about the ledgers they police.

Module: `github.com/baseproof/tooling/services/auditor`. It composes
its pipeline from the shared `tooling/libs` engines + the `baseproof` SDK,
and keeps its own custody code under `internal/` (un-importable by anyone else).

## What it does

On boot with a durable store configured (`AUDITOR_GOSSIP_DSN` set), it assembles
one pipeline in `internal/app` from `libs` engines:

1. **Pull** — `libs/auditing/peers` polls each configured peer's
   `/v1/gossip/since` feed (dumb transport; a peer is only a byte source, never
   trust).
2. **Re-verify** — `libs/auditing/gossipverify` runs the SDK finding-router
   two-tier check (envelope authenticity → finding proof) against locally-held
   witness sets + DID registry. **Fail-closed** — an unverified event never
   reaches an enforcer or the store.
3. **Reconcile + persist** — `libs/monitoring.Reconciler` routes each verified
   finding (advance the trusted head / slash equivocation / apply a witness
   rotation) and **persists every verified event** to the durable store
   (`internal/store`, Postgres `peer_gossip`).
4. **Detect + slash** — proven same-size/different-root forks drive
   `internal/equivocation.Slasher` (re-verifies before counting; drops a
   ledger's trust to zero past the threshold).
5. **Serve** — `internal/gossipfeed` serves the auditor's **own** `/v1/gossip`
   feed (over the SDK feed handler), which enforcers re-verify.
6. **Prune** — an optional retention job (`libs/monitoring.PruneJob`) when
   `AUDITOR_GOSSIP_RETENTION_DAYS > 0`.

An empty `AUDITOR_GOSSIP_DSN` runs the binary in **health-only mode** — no store,
no pipeline, no feed.

## Why custody lives here (dependency-law LAW 4)

The durable `gossip.Store` implementation is `internal/store`. Go's `internal/`
rule makes it un-importable by any lib, any other service, or any enforcer
network — so custody is *physically disjoint* from enforcement, enforced by
`scripts/dependency-law.sh`, not by convention.

## Configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `AUDITOR_LISTEN_ADDR` | `:8088` | HTTP listen address |
| `AUDITOR_GOSSIP_DSN` | *(empty)* | Postgres DSN. **Empty ⇒ health-only mode.** |
| `AUDITOR_NETWORK_BOOTSTRAP_FILE` | *(falls back to `LEDGER_NETWORK_BOOTSTRAP_FILE`)* | shared trust root → derives `NetworkID` + witness sets |
| `AUDITOR_WITNESS_QUORUM_K` | `0` | cross-check of the bootstrap's `genesis_quorum_k` (the single source of K). `0` (unset) adopts it; an equal value is honoured; a differing value is startup-fatal |
| `AUDITOR_PEERS` | *(empty)* | source feeds, `logDID=baseURL,logDID=baseURL` |
| `AUDITOR_POLL_INTERVAL` | `30s` | catch-up cadence per peer |
| `AUDITOR_GOSSIP_RETENTION_DAYS` | `0` (keep all) | prune horizon |
| `AUDITOR_PRUNE_INTERVAL` | `24h` | prune cadence |
| `AUDITOR_READ_TIMEOUT` / `_WRITE_TIMEOUT` / `_IDLE_TIMEOUT` / `_SHUTDOWN_TIMEOUT` | `5s`/`10s`/`60s`/`15s` | HTTP server timeouts |

## Endpoints (plain HTTP — a public observer surface, no mTLS)

| Method | Path | Description |
|---|---|---|
| GET | `/v1/gossip/…` | the served evidence feed (mounted **only** when a store is configured) |
| GET | `/healthz` | liveness |
| GET | `/readyz` | readiness — flips to `503` on shutdown so orchestrators drain |
| GET | `/version` | build info JSON |

## Store schema

A single table, applied idempotently by the store's `Migrate` at boot:

```
peer_gossip(event_id PK, originator, kind, lamport, payload BYTEA, inserted_at)
  UNIQUE (originator, lamport)   -- one chain per originator
  INDEX  (inserted_at)           -- retention pruning
```

`payload` is **BYTEA, not JSONB** — the signed body bytes are
signature-covered, and JSONB would reorder keys and break verification.
Integrity is checked at read time by the SDK (every row is a
`gossip.SignedEvent`), so the store is "dumb durable bytes" yet unforgeable.

## Build & run

```sh
# from services/auditor/
GOWORK=off go build -o ./bin/auditor ./cmd/auditor

AUDITOR_GOSSIP_DSN='postgres://auditor:…@db:5432/auditor_gossip?sslmode=require' \
AUDITOR_NETWORK_BOOTSTRAP_FILE=/run/auditor/bootstrap.json \
AUDITOR_PEERS='did:web:state:tn:davidson=https://ledger.example/' \
  ./bin/auditor
# K comes from the bootstrap's genesis_quorum_k; AUDITOR_WITNESS_QUORUM_K is an
# optional cross-check (a differing value is startup-fatal).
```

Deployment is **per network** — the same image, configured by env + a mounted
bootstrap, runs one instance per network it audits. See
[`deploy/README.md`](deploy/README.md).
