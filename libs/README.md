# `libs` — agnostic shared libraries (one module)

This module is the **domain-agnostic substrate** every ClearCompass network
links against (judicial-network, and future networks). It is the *only* module
in this repo that downstream networks import, so it is kept to a **lean
dependency surface**.

## Rules (compiler-enforced in CI)

- **No domain, ever.** A package here may import `baseproof` (the SDK), the
  standard library, and other `libs/*` packages — **never** a network repo
  (`judicial-network`, `ledger`, `*-network`) and **never** a `services/*`
  package. `ci.yml` + `scripts/dependency-law.sh` fail the build on violation
  (`go list -deps`, `GOWORK=off`).
- **Engines, not policy.** Each library is a domain-agnostic *engine*; the
  network injects its domain via interfaces / extractor registries / rules
  passed as data. A library owns the config and extension types it needs so it
  never has to import a consumer's package.
- **No `internal/`.** Libraries are meant to be imported; keep packages
  directly under `libs/<name>/`. (Service-private code lives in
  `services/<svc>/internal/`, where the compiler forbids outside imports.)
- **No silent plaintext.** Every `libs/*` constructor that takes an
  `*http.Client` field requires it — nil returns `ErrInvalidConfig`
  wrapping the field name. Consumers thread the binary's hoisted outbound
  client (one per binary, built at boot); `libs/*` itself never
  constructs a fallback `&http.Client{}`. Enforced by
  `scripts/client-contract.sh` for service binary main.go and by
  `libs/sdkguard` at runtime for staging / CI.

## Contents

| package | what | domain seam / neutralization |
|---|---|---|
| `aggregator` | ledger→projection ingestion engine: poll → SDK-decode to an agnostic `DecodedEntry` → drive an injected `Projector`; per-log watermark; rebuildable cache | `Projector` (classify+index); `LedgerScanner`/`WatermarkStore` injected; owns `DecodedEntry`/`ScannerConfig` |
| `ledgerscan` | generic restart-safe sequential log scanner (CT-monitor style) | **inverted**: `Indexer`/`Cursor` injected; field-parsing + index store stay in the network |
| `auditing/gossipverify` | zero-trust re-verification of inbound gossip (two-tier: envelope → finding proof); `WitnessSetRegistry` (verify-before-swap rotation); tile mirrors | trust roots injected (originator verifier, witness sets, DID signer-verifier, heads/tiles) |
| `auditing/peers` | dumb inbound transport — per-peer poll of `/v1/gossip/since`, hands raw **unverified** events to a sink (grants no trust) | `SignedEventSink` injected (the verify-then-act consumer) |
| `gossipingest` | reusable inbound pipeline: pull → verify → reconcile → persist; one `Build(Config)` call wires verifier + reconciler + heads + puller in the correct order with every required field validated at construction | `HTTPClient`, `DIDRegistry`, `Store`, `WitnessSets` injected; optional `Equivocation` responder + `Tiles` cross-log source |
| `monitoring` | autonomous audit engine: ticker `Scheduler` + the `Check*` audit family + inbound-gossip `Reconciler`/`TrustedHeadStore`/equivocation responder + retention `PruneJob` | per-call config structs + SDK data-access interfaces; minimal local interfaces for verifier/rotator/slasher/pruner |
| `prereq` | event-prerequisite engine — closed-set vocabulary + per-event Hard/Advisory rules, evaluated by a `Walker` over a caller-built `CaseContext` | rules injected as data via `NewInMemoryPolicy`/`Register`; the `Policy` interface |
| `crosslog` | offline cross-log verify (`HopDispatcher`) + witness-set builder (`BuildWitnessSets`) | owns **`WitnessSetSpec`**; `HopDispatcher` fields (`Registry`/`Rotations`/`InitialKey`/`GovernsOnLog`) |
| `keystore` (+`vault`,`pkcs11`,`signer`) | in-process **secp256k1** signer — memory · Vault Transit · PKCS#11 HSM; `signer` adapts to the SDK SCW `keys/v1.Signer` | the `KeyStore` interface; **linked, never dialed**; Vault takes the hoisted `HTTPClient` (no plaintext fallback) |
| `identity` | Web2→Web3 IdP seam (production target Privy): verify IdP JWTs → `Claims`; wallet `SignDigest` of typed data | the `IdentityProvider` interface; the network builds the EIP-712 typed data + digest |
| `httpmw` (+`reliability`,`observability`) | mTLS (DID-from-cert SAN) / JWT auth; breaker/retry-free timeout/rate-limit/max-body; OTel RED metrics, request-ID, zerolog, `/readyz` | config structs the libs own; establishes `callerDID` in the request context; JWT verifier + readyz probes require the hoisted client |
| `cache` | generic goroutine-safe TTL policy cache (lazy eviction) | Go generics (`Cache[V]`); stdlib only |
| `clienttls` | canonical outbound `*http.Client` builder: `Flags{}+Bind(fs)` for CLI tools, `BuildFromEnv(prefix, logger)` for services, explicit `Posture` (MTLS / Plaintext) returned + logged | env scheme owned (`<prefix>CLIENT_CERT_FILE` etc.); half-config (cert XOR key) fail-closed |
| `clitools` | shared client/config helpers: `Config` (+`TOOLS_*` env), Postgres `DB` (lib/pq) + watermarks, read-only `LedgerClient`/`VerifyClient`, write-only `ExchangeClient` (build-sign-submit), artifact-store `NewContentStore` | leaf lib; owns its DTOs/config; tools hold no signing keys; every constructor takes the hoisted client or branches on `*MTLSConfigured()` |
| `outbound` | the binary's hoisted outbound client (`Client{*http.Client, clienttls.Posture}`) + canonical `HoistFromEnv` — declared, grep-able type so `scripts/client-contract.sh` can catch raw `&http.Client{}` in service binary main.go | wraps `libs/clienttls`; pure typing + lint anchor |
| `sdkguard` | env-gated runtime assertion (`BASEPROOF_FAIL_ON_PLAINTEXT_FALLBACK=true`) — `AssertMTLS(client, label)` panics on plaintext / nil / custom-Transport / no-client-cert clients at the caller's file:line | strict mode off by default; CI / staging flip it on to catch missing-wiring tests pass through |

`go list -deps ./...` proves the whole module is network-free (incl. `-tags
pkcs11`). New packages land here **by promotion** — the day a second module
imports one — not speculatively. Inter-lib coupling is minimal: `aggregator`
and `monitoring` import `clitools`; `gossipingest` imports
`auditing/gossipverify`+`auditing/peers`+`monitoring`; `outbound` wraps
`clienttls`.

## Contract for downstream binaries

Every binary built on `libs/` MUST:

1. **Build exactly one outbound `*http.Client` at boot** via
   `libs/outbound.HoistFromEnv(prefix, logger)` (or
   `libs/clienttls.BuildFromEnv` if you don't want the typed wrapper).
   The hoist returns an explicit `Posture` — log it.
2. **Thread that client into every `libs/*` and SDK constructor** that
   takes a `*http.Client` field. Never pass `nil`. Never construct a
   second `&http.Client{}` elsewhere in the binary.
3. **Fail closed on half-config**: cert XOR key is a startup-fatal
   error, surfaced unchanged by every helper that touches mTLS material.
4. **Log the chosen `Posture`** (`MTLS` / `Plaintext`) at startup so
   operators see what mode the binary actually entered.

`libs/*` itself never silently constructs a fallback `*http.Client` —
every config struct requires `Client`; every constructor returns
`ErrInvalidConfig` (or panics, for register-once probes like
`observability.CheckHTTPGet`) on `nil`. Consumers that intentionally
want a plaintext client construct it explicitly at the boot site —
`libs/` does not paper over the decision.

CI enforces this with two independent checks:

- `scripts/dependency-law.sh` — the layering rule (no domain in
  `libs/*`; no services in `libs/*`).
- `scripts/client-contract.sh` — no `&http.Client{...}` in
  `services/*/cmd/*/main.go`. An allowlist marker
  (`// client-contract: allow <reason>` immediately above the line)
  unblocks the rare legitimate case.

Optional runtime check for staging / CI:

- `libs/sdkguard.AssertMTLS(client, label)` at every SDK construction
  site that requires mTLS in production. No-op by default; the env
  var `BASEPROOF_FAIL_ON_PLAINTEXT_FALLBACK=true` (or `1`/`yes`) makes
  it panic on a plaintext client, naming the caller file:line. Pairs
  with the constructor `ErrInvalidConfig` check: one catches missing
  wiring at boot, the other catches wrong wiring in test harnesses.
