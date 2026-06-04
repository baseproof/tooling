# tooling — architecture

`tooling` is the **domain-agnostic half** of the Baseproof transparency-log
network: the shared libraries every domain network links, and the microservices
every network runs. Domain networks (`judicial-network`, and future ones) live
in their own repos and consume `tooling/libs` + the `baseproof` SDK,
**injecting their domain through interfaces**.

The protocol itself — envelopes, signatures, Merkle/SMT, cosignatures, gossip,
the verification primitives — lives in the **`baseproof` SDK**
(`github.com/baseproof/baseproof`). `tooling` never reimplements
protocol; it packages reusable *engines* and *services* on top of it.

## Layers (strict, one-way dependency)

```
baseproof (SDK)            protocol vocabulary + verification primitives (universal)
      ▲
tooling/libs       agnostic ENGINES every network links (one published module)
      ▲                          ▲
tooling/services    domain network repos     each network: import baseproof + tooling/libs,
(auditor, witness)        (judicial-network, …)    inject domain via interfaces, deploy the services
```

## Modules

Three independent Go modules, each with its own `go.mod`:

| Module | Path | Role |
|---|---|---|
| **libs** | `github.com/baseproof/tooling/libs` | the agnostic engines — the **only** module a domain network imports |
| **services/auditor** | `github.com/baseproof/tooling/services/auditor` | the evidence-custodian microservice |
| **services/witness** | `github.com/baseproof/tooling/services/witness` | the stateless witness daemon |

`go.work` at the repo root stitches the three together for local cross-module
edits. **CI builds each module in isolation with `GOWORK=off`** (`ci.yml`), so a
missing `require` fails loudly instead of being papered over by the workspace.

## Layout

```
libs/                 agnostic libraries — ONE module, lean deps, the only thing networks import
services/auditor/     evidence custodian: cmd/auditor · internal/{app,gossipfeed,equivocation,store} · deploy/
services/witness/     witness daemon: cmd/{witness,gen-fixtures} · internal/{serve,obs,witkey} · scripts/local/
services/ledger/      COLOCATED but INDEPENDENT domain tenant — its own go.mod + go.work + third_party/tessera
                      submodule + CI (ledger-*.yml) + image; exempt from the laws via .law-exempt (see below)
go.work               local dev only; CI builds each module with GOWORK=off (the ledger keeps its own go.work)
scripts/              dependency-law.sh + client-contract.sh (layering gates) · lib/governed.sh (tenant exemption)
.github/workflows/    ci.yml (per-module build/vet/test + the dependency law) · go-test.yml (witness) · ledger-*.yml
```

## The dependency law (compiler-enforced — `scripts/dependency-law.sh`)

The layering is enforced by the Go toolchain in CI (`go list -deps` per module,
`GOWORK=off`), not by review discipline. Four laws:

```
LAW 1   libs/* | services/*  →  judicial-network | ledger | *-network    ✗  (no domain, ever)
LAW 2   libs/*              →  services/*                                 ✗  (a lib that imports a service is a fork)
LAW 3   services/*          →  a remote Sign surface (grpc/rpc/proto)     ✗  (the keystore is LINKED, not dialed)
LAW 4   the gossip.Store impl lives ONLY under services/auditor/internal/ ✗  elsewhere  (custody isolation — SoD)
```

**LAW 4 is the Separation-of-Duties guarantee** (see below). The durable
`gossip.Store` — the custodial record of fraud evidence — lives under
`services/auditor/internal/store`, where Go's `internal/` rule makes it
un-importable by any lib, any other service, or any enforcer network. Custody is
therefore *physically disjoint* from enforcement, proven by the compiler rather
than a memo.

**The colocated ledger is exempt — but still un-importable.** The ledger (a
domain network's sequencer) now lives in-tree at `services/ledger` for
colocation only; it is an *independent tenant*, not part of the agnostic half.
A `.law-exempt` marker at its root prunes it from the four scans
(`scripts/lib/governed.sh`), so its self-referential deps and its own
`NewPostgresStore` don't trip LAW 1 / LAW 4. The exemption is **asymmetric**:
the ledger is no longer a *subject* of the laws, but it remains a forbidden
*object* — LAW 1's `DOMAIN_RE` names it at both its retired path
(`clearcompass-ai/ledger`) and its new one
(`baseproof/tooling/services/ledger`), so no lib or first-party
service may import it. Physical colocation, logical separation.

Two invariants worth restating:

- **Engines, not policy.** Each library is a domain-agnostic engine; networks
  inject domain via interfaces, extractor registries, and rules-as-data. A lib
  owns its own config/extension types so it never has to import a consumer.
- **Clean closure ≠ agnostic.** `go list -deps` proves *contamination*, not
  *purpose*. Domain leaves (e.g. judicial `schemas`, `cases`) have clean
  closures yet stay in their network repo. Promotion to `libs/` is a human call
  backed by the closure check, not the closure check alone.

## `libs/` — the agnostic engines (one module)

The module is kept to a **lean dependency surface** (it is the only thing
networks import). Each package is an engine; the **domain seam** column is how a
network injects its domain without the lib ever importing a consumer.

| package | what it is | domain seam / neutralization |
|---|---|---|
| `aggregator` | ledger→projection ingestion engine: poll a log, SDK-decode each entry to an agnostic `DecodedEntry`, drive an injected `Projector`; per-log watermark; the projection is a rebuildable cache | `Projector` (classify + index); `LedgerScanner`/`WatermarkStore` injected (default to `clitools`); owns `DecodedEntry`/`ScannerConfig` |
| `ledgerscan` | generic restart-safe sequential log scanner (CT-monitor style); traverses in position order and persists a cursor | `Indexer` (what to index) + `Cursor` (resume) injected; stays at raw SDK `*envelope.Entry` |
| `auditing/gossipverify` | zero-trust **re-verification** of inbound gossip: two-tier (envelope authenticity → finding-proof) against locally-held trust roots; `WitnessSetRegistry` (verify-before-swap, monotonic rotation); HTTP tile mirrors | trust roots injected: `OriginatorVerifier` + `NetworkID`, witness sets, DID `SignerVerifier`, trusted heads/tiles |
| `auditing/peers` | dumb inbound transport: per-peer poll loop pulling `/v1/gossip/since`, handing raw **unverified** events to a sink — grants a peer no trust | `SignedEventSink` injected (the verify-then-act consumer) |
| `monitoring` | the autonomous audit engine: a ticker `Scheduler` running a family of `Check*` audits + the inbound-gossip `Reconciler`/`TrustedHeadStore`/equivocation responder + a retention `PruneJob` | per-call config structs + SDK data-access interfaces; minimal local interfaces for verifier/rotator/slasher/pruner |
| `prereq` | event-prerequisite policy engine: a closed-set event vocabulary + per-event **Hard/Advisory** rules, evaluated by a `Walker` over a caller-built `CaseContext` | rules-as-data via `NewInMemoryPolicy`/`Register`; the `Policy` interface |
| `crosslog` | offline cross-log federation: `HopDispatcher` (per-hop key-at-position signature verify) + `BuildWitnessSets` | owns `WitnessSetSpec`; `HopDispatcher` fields (`Registry`/`Rotations`/`InitialKey`/`GovernsOnLog`) |
| `keystore` (+`vault`,`pkcs11`,`signer`) | in-process **secp256k1** key custody — backends: memory · Vault Transit · PKCS#11 HSM; `signer` adapts a `KeyStore` to the SDK SCW `keys/v1.Signer` | the `KeyStore` interface; **linked in-process, never dialed** (LAW 3) |
| `identity` | the Web2→Web3 IdP seam (production target: Privy): verify IdP JWTs → `Claims`, ask the user's embedded wallet to `SignDigest` typed data; interface + in-memory stub | the `IdentityProvider` interface; the **network** builds the EIP-712 typed data + 32-byte digest |
| `httpmw` (+`observability`,`reliability`) | the HTTP layer: mTLS (DID-from-cert URI SAN) + JWT auth; OTel RED metrics, request-ID, zerolog access logs, `/readyz`; circuit breaker, rate limit, max-body, request timeout, tuned client | config structs the libs own; auth establishes `callerDID` in the request context |
| `cache` | generic goroutine-safe TTL cache for read-time policy enforcement (lazy eviction) | Go generics (`Cache[V]`); stdlib-only |
| `clitools` | shared client/config layer for tool processes: `Config` (+`TOOLS_*` env), a Postgres `DB` (lib/pq) with watermark helpers, read-only `LedgerClient`/`VerifyClient`, and a write-only `ExchangeClient` (build-sign-submit; **tools hold no signing keys**) | leaf lib; owns its DTOs/config |

`go list -deps ./...` proves the whole module is network-free (incl.
`-tags pkcs11`). New packages land here **by promotion** — the day a second
module imports one — not speculatively. Inter-lib coupling is minimal: only
`aggregator` and `monitoring` import a sibling (`clitools`).

See [`libs/README.md`](libs/README.md) for the per-package rules.

## `services/`

### auditor — evidence custodian

The auditor pulls peer ledgers' `/v1/gossip` feeds (`libs/auditing/peers`),
**re-verifies** every event via the SDK finding router
(`libs/auditing/gossipverify`), reconciles + **persists** verified findings via
`libs/monitoring` to a durable Postgres store (`internal/store`, the
`peer_gossip` table), **slashes** proven equivocators
(`internal/equivocation` + the monitoring responder), and serves its **own**
`/v1/gossip` feed (`internal/gossipfeed`, over the SDK feed handler) for
enforcers to re-verify. Fully env-driven (`AUDITOR_*`); plain HTTP on `:8088`
(`/v1/gossip`, `/healthz`, `/readyz`, `/version`). An empty `AUDITOR_GOSSIP_DSN`
runs it in health-only mode (no store ⇒ no pipeline ⇒ no feed). See
[`services/auditor/README.md`](services/auditor/README.md).

### witness — stateless notary

A "blind notary" that serves `POST /v1/cosign`, lending 1-of-N cryptographic
weight that a tree head was presented to it at a moment in time. No DB, no
gossip, no builder loop, no admissions. The shipped binary is
`standalone-witness`. It imports **only** the `baseproof` SDK — never `libs`,
never a network repo. See [`services/witness/README.md`](services/witness/README.md)
and [`services/witness/scripts/local/README.dev.md`](services/witness/scripts/local/README.dev.md).

## Separation of Duties: custodian ↔ enforcer

The network splits two clocks across distinct processes:

- **Commit clock (enforcement).** A domain network (e.g. `judicial-network`)
  admits and enforces entries on its own log — authority, attestation,
  prerequisites. It runs a **verify-only** gossip ingest: it *pulls* evidence
  and re-verifies it, but **hosts no custody**.
- **Transparency clock (custody + detection).** The **auditor** is the external
  evidence custodian: it pulls peers' `/v1/gossip`, re-verifies every event,
  **persists** fraud evidence to its own durable store, runs equivocation/fork
  detection (slashing), and serves its own `/v1/gossip` feed — which enforcers
  then independently re-verify.

*"The enforcer hosts no custody."* LAW 4 makes that physical: the `gossip.Store`
impl is `services/auditor/internal/store`, un-importable by any enforcer. The
witness is a third, even simpler role — a stateless notary that only cosigns
tree heads. Everything entering an inbound pipeline is treated as untrusted
bytes until it passes local re-verification; trust never comes from a peer.

## How a new network reuses `tooling`

```go
import (
    "github.com/baseproof/baseproof/..."                   // protocol + verification
    "github.com/baseproof/tooling/libs/keystore"   // sign in-process (memory/Vault/HSM)
    "github.com/baseproof/tooling/libs/httpmw"     // auth / reliability / observability
    "github.com/baseproof/tooling/libs/prereq"     // event-prerequisite rules-as-data
    "github.com/baseproof/tooling/libs/monitoring" // autonomous audit loops
    // … inject the network's schema extractors, authz policy, prereq rules,
    //    aggregator Projector, and IdentityProvider
)
// then deploy the SAME auditor + witness binaries, configured with the
// network's bootstrap document.
```

A new network is **"import `tooling` + inject domain + deploy the shared
services"** — never "fork a sibling network."
