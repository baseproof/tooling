# tooling platform e2e

A Go-driven end-to-end harness (modeled on the judicial-network e2e — `cmd` +
`stack` + `runner` + `dockerx`, no bash) that drives the **unified `baseproof`
CLI** (`libs/cli`) against a **real ledger fleet**. It validates the live paths a
unit test cannot: authoring a bundle over HTTPS, submitting through the real
admission→sequencer→builder→cosign pipeline, proving an actually-submitted entry
(including the builder's `receipt_proof` leg), verifying that proof **offline**,
and `info --verify` against a real cosigned horizon + a real auditor.

This is an **internal, untagged module** — it is not part of the `v0.0.X` /
`libs/v0.0.X` dual release. It depends on `libs` via a local `replace`, so it
builds and runs in-repo with no published tag.

## Two ways to run

### `e2e selftest` — no docker, runs anywhere
Drives the **read/verify side** (network add → proof live-gather → verify offline →
info --verify) over **real HTTPS with real cryptography** against an in-process
fixture (a pre-committed entry + cosigned horizon + the full introspection
surface). Proves the unified-CLI read path end to end:

```
go run ./cmd/e2e selftest
```

### `e2e up` + `e2e run` — the real docker fleet
Brings up **postgres + seaweedfs (S3) + witness + ledger (HTTPS) + auditor** and
drives the **full** pipeline, including the write side:

```
go run ./cmd/e2e up            # pull the published fleet; or --build to build from the local Dockerfiles
go run ./cmd/e2e run           # submit → await cosigned horizon → load → proof → verify → info
go run ./cmd/e2e down
```

The ledger serves **open HTTPS** with a self-signed run CA (minted by the harness;
SANs cover `localhost` + the container name). Reads are open; writes are gated by
in-body crypto. The libs runner pins the CA via `network add --ca-cert`. The
genesis bootstrap + witness key are minted by the ledger's own
`services/ledger/cmd/init-network` (reused, not reinvented).

## Layout
- `dockerx/` — the only layer that shells to `docker` (pure, testable argv builders).
- `stack/` — fleet bring-up (`Build`/`Wipe`) + self-signed cert minting (`certs.go`).
- `fixture/` — in-process real-crypto TLS ledger + auditor (backs `selftest`).
- `runner/` — the staged libs-CLI driver (`ReadStages` / `WriteStages` / `Run`),
  unit-tested against the fixture (`runner_test.go`).
- `cmd/e2e/` — `selftest` | `up` | `run` | `down`.

## Environment
- `BASEPROOF_E2E_DIR` — state dir (default `./.run/e2e`).
- `E2E_LOG_DID`, `E2E_QUORUM_K` — network parameters for `up`.
- `E2E_BUILD=1` (or `up --build`) — build the fleet images from the local
  Dockerfiles instead of pulling the published `ghcr.io/baseproof/tooling/*`.
