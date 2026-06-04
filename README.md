# tooling

The **domain-agnostic** half of the Baseproof transparency-log network: shared Go
libraries every domain network links, plus the microservices every network runs.
Domain networks (e.g. `judicial-network`) live in their own repos and consume
`tooling/libs` + the [`baseproof`](https://github.com/baseproof/baseproof)
SDK, injecting their domain through interfaces.

> The protocol (envelopes, signatures, Merkle/SMT, cosignatures, gossip,
> verification) lives in the `baseproof` SDK. This repo never reimplements
> protocol — it packages reusable **engines** (`libs/`) and **services**
> (`services/`) on top of it.
>
> Architecture, the layer model, and the compiler-enforced dependency law:
> **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Modules

Three independent Go modules, stitched by `go.work` for local dev; CI builds each
in isolation with `GOWORK=off`.

| Module | Import path | What |
|---|---|---|
| **libs** | `…/tooling/libs` | the agnostic engines — the only module networks import: `aggregator`, `ledgerscan`, `auditing`, `monitoring`, `prereq`, `crosslog`, `keystore`, `identity`, `httpmw`, `cache`, `clitools` |
| **services/auditor** | `…/tooling/services/auditor` | evidence custodian — pulls + re-verifies + persists gossip, detects equivocation, serves a feed |
| **services/witness** | `…/tooling/services/witness` | stateless witness daemon — cosigns tree heads (`POST /v1/cosign`) |

## Quickstart

### Use the libs in a network

```go
import "github.com/baseproof/tooling/libs/keystore"
```

A new network is *"import `tooling` + inject domain + deploy the shared
services."* See [ARCHITECTURE.md → How a new network reuses tooling](ARCHITECTURE.md#how-a-new-network-reuses-tooling).

### Run a witness fleet locally

```sh
cd services/witness
make run-local WITNESS_COUNT=5     # K=5 on :19001..:19005 (no Docker)
make dev-up    WITNESS_COUNT=5     # same fleet, in Docker
```

Daemon reference: [services/witness/README.md](services/witness/README.md).
Full local-dev operator guide:
[services/witness/scripts/local/README.dev.md](services/witness/scripts/local/README.dev.md).

### Run the auditor

Env-driven; one instance per network it audits. See
[services/auditor/README.md](services/auditor/README.md).

## The dependency law

Enforced by `scripts/dependency-law.sh` in CI (`go list -deps`, `GOWORK=off`):

- no lib or service may link a domain/network module (`judicial-network`, `ledger`, `*-network`);
- libs may not depend on services;
- no service exposes a remote `Sign` surface — the keystore is **linked, not dialed**;
- the durable `gossip.Store` (custody) lives **only** under `services/auditor/internal/` — Separation of Duties.

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

## Build & test

```sh
# per module, the way CI does it:
for m in libs services/auditor services/witness; do
  (cd "$m" && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go test ./...) || exit 1
done
bash scripts/dependency-law.sh
```

## Layout

```
libs/                 the agnostic engines (one module)   — see libs/README.md
services/auditor/     evidence custodian                  — see services/auditor/README.md
services/witness/     witness daemon                      — see services/witness/README.md
scripts/              dependency-law.sh (the layering gate)
go.work               local-dev workspace (CI uses GOWORK=off)
.github/workflows/    ci.yml · go-test.yml
```
