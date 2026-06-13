# Changelog

All notable changes to clearcompass-ai/ledger are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning tracks the underlying baseproof SDK release.

## [Unreleased] — v1.37.0 SDK adoption: polymorphic admission + EIP-1271 + PQ

### Make the ledger dumb — the load-bearing change

Pre-v1.37.0 the ledger's admission gate hardcoded `if algoID != SigAlgoECDSA { reject }` at `admission/multisig_verifier.go:118`. That guard rejected every algorithm the baseproof SDK already had a verifier for. The "BY DESIGN" rationale in the file docstring was retrofitted to code that never actually called `ecrecover` or any chain — it did offline ECDSA math and returned `ZeroWeb3VerificationReceipt`. v1.37.0 deletes the policy decision at this layer and delegates ALL algorithm + DID-method dispatch to the SDK's `*did.VerifierRegistry`.

After this release, the admission pipeline admits every signature the SDK can verify: **ECDSA secp256k1, Ed25519, EIP-191, EIP-712, EIP-1271, ML-DSA-65, ML-DSA-87, SLH-DSA-128s** — across **did:key, did:web, did:pkh** identifiers. The ledger is "dumb" at the cryptographic seam: whatever the SDK accepts, admission accepts.

### Three tiers in one release

**Tier 1 — Polymorphic admission** (the make-ledger-dumb load-bearer)

- `go.mod`: `baseproof v1.36.0` → `v1.37.0`
- `api.IdentityDeps` gains a `Verifier attestation.SignatureVerifier` field. Production wires it with `*did.VerifierRegistry`; tests may keep the legacy `DIDResolver` field for backward compat
- `admission.VerifyEntryAllSignaturesWithVerifier` is the new polymorphic admission entry point. The pre-existing `VerifyEntryAllSignatures` (wrapping a `DIDResolver` in `sigVerifierAdapter`) remains for tests and pre-v1.37 deployments
- `cmd/ledger/boot/wire/wire.go::buildIdentityDeps` composes the full chain: `MethodRouter(did:key + did:web) → CachingResolver(5min TTL) → DefaultVerifierRegistry(LedgerDID, cached, pkhOpts)`. `did:web` HTTPS fetches use `d.OutboundHTTPClient` (always non-nil per v1.34.0 contract honesty)
- `admission/multisig_verifier.go` file docstring refreshed: the fictional "MUST be verifiable on-chain" claim is replaced with an honest description of the polymorphic seam

**Tier 2 — EIP-1271 smart-contract-wallet verification** (feature-flagged, OFF by default)

- New env-var contract for K-of-N quorum:
  - `LEDGER_EIP1271_ENABLED` (master switch; default `false`)
  - `LEDGER_EIP1271_EXECUTORS` (comma-separated `id=endpoint` pairs; ≥2 required)
  - `LEDGER_EIP1271_QUORUM_K` (default 2; SDK enforces K≥2)
  - `LEDGER_EIP1271_CHAIN_ID` (CAIP-2; e.g., 1 for Ethereum mainnet)
  - `LEDGER_EIP1271_BLOCK_NUMBER` + `LEDGER_EIP1271_BLOCK_HASH` (StaticBlockProvider pin; see runbook for refresh cadence)
- `cmd/ledger/ethereum_rpc.go` gains `LoadEIP1271Config` + `BuildPKHVerifierOptions`. The Ethereum RPC client previously discarded as `_ = ethRPC` at `main.go:170` is now plumbed through `deps.EthereumRPC` into the verifier registry when enabled
- v1.37.0 first-ship uses `StaticBlockProvider` (the SDK does not yet ship a dynamic head-pinning provider). Suitable for staged rollout; production-grade dynamic pinning lands in a follow-up release. **Cost posture**: at the disabled default the ledger makes zero Ethereum RPC calls. At realistic court-system volumes (100-200 TPS avg, ~5% EIP-1271 share, K=2), monthly Ethereum spend is ~$50-300 with the SDK's `EIP1271BatchCache` active

**Tier 3 — Post-quantum (ML-DSA / SLH-DSA) admission**

- No ledger-side code is required. The SDK's v1.37.0 release wired ML-DSA-65, ML-DSA-87, and SLH-DSA-128s through `did:key` and `did:web` verifiers. Because the ledger now delegates to the SDK registry (Tier 1), PQ admission is automatic. New tests `admission/multisig_verifier_polymorphic_test.go` lock the end-to-end path for did:key + ECDSA + Ed25519 + ML-DSA-65, plus a tampered-signature rejection case

### Added

- `admission.VerifyEntryAllSignaturesWithVerifier` — the polymorphic admission entry point
- `api.IdentityDeps.Verifier` — preferred over `DIDResolver` when both are set
- `cmd/ledger/ethereum_rpc.go` — `EIP1271Config`, `LoadEIP1271Config`, `BuildPKHVerifierOptions`
- `deps.AppDeps.EthereumRPC` + `deps.AppDeps.PKHVerifierOptions`
- `cmd/ledger/boot/wire/wire.go::buildIdentityDeps` — polymorphic chain composer
- 4 new admission tests covering did:key + ECDSA, Ed25519, ML-DSA-65, and a tampered-signature rejection
- `docs/v1.37.0-adoption-runbook.md` — operator rollout, cost expectations, EIP-1271 enable procedure

### Changed

- `cmd/ledger/main.go:170` — `_ = ethRPC` removed; ethRPC now threaded through `deps.EthereumRPC`
- `cmd/ledger/main.go` — calls `LoadEIP1271Config` + `BuildPKHVerifierOptions` at startup
- `admission/multisig_verifier.go` header docstring — replaced "ECDSA-only by design" rationale with the honest polymorphic-seam description

### Backward compatibility

- All existing admission tests pass unmodified — the legacy `DIDResolver` path (single-sig and multi-sig adapter) is preserved
- Operators who do nothing get v1.37.0 with EIP-1271 disabled, identical wire-format behaviour to v1.36.0 for ECDSA entries, plus automatic admission of Ed25519 / ML-DSA / SLH-DSA entries when signers present them. **No on-log entries from v1.36.0 become invalid**
- The "ECDSA-only" cost-of-entry that previously blocked court-system did:web actors (federal/state courts, bar-association-rooted lawyers) is gone

## [Unreleased] — v1.34.0 SDK adoption: no silent HTTP-client fallbacks

### Breaking — load-bearing

v1.34.0 of the baseproof SDK removes three silent `*http.Client` fallbacks (`cosign.NewWitnessClient`, `gossip.NewClient`, `gossip.NewFeedClient` — see baseproof CHANGELOG 1.34.0). A nil client now returns a typed error at construction. The ledger matches that posture in its own four constructors, plus the boot wiring that supplies them.

**Why this matters.** A silent default hides the absence of mTLS material from any operator who simply forgot to wire it — exactly the failure mode the v1.27.x cleanup sweep was designed to prevent. Closing the four remaining sites in the ledger (and the two latent sites in `lifecycle/archive_reader.go`) finishes that principle in the ledger's own home.

### Changed (BREAKING) — `gossipnet`, `witnessclient`, `lifecycle`

| Constructor | Before (v1.33.1) | After (v1.34.0) |
|---|---|---|
| `gossipnet.NewAntiEntropy` | `cfg.HTTPClient == nil` → `sdklog.DefaultClient(20s, nil)` | `cfg.HTTPClient == nil` → error |
| `gossipnet.NewEquivocationMonitor` | same fallback | error |
| `gossipnet.Build` (`buildSink`) | conditional `WithHTTPClient` (relied on SDK fallback) | hard requirement when `PeerEndpoints` non-empty |
| `witnessclient.NewHeadSync` | `cfg.HTTPClient == nil` → `sdklog.DefaultClient(PerWitnessTimeout, nil)` | error |
| `lifecycle.NewArchiveReader` | `httpClient == nil` → `sdklog.DefaultClient(30s, nil)` | panic |
| `lifecycle.LoadShardIndex` (http source) | `httpClient == nil` → `sdklog.DefaultClient(30s, nil)` | error |

### Changed — `cmd/ledger/boot/wire`

- `buildPeerHTTPClient` now ALWAYS returns a non-nil `*http.Client`. When no mTLS material is configured (no `PeerClientCertFile`/`PeerClientKeyFile`), it returns a plaintext client carrying the SDK's `RetryAfterRoundTripper` — appropriate for dev/test and for deployments terminating mTLS at an upstream proxy.
- `Wire` assigns `d.OutboundHTTPClient` unconditionally; the boot log now distinguishes "peer mTLS client configured" from "peer HTTP client configured (plaintext; no PeerClientCertFile)" so the operator sees the posture in startup output.

These two changes together mean every downstream consumer of `d.OutboundHTTPClient` (gossip sink, anti-entropy, equivocation monitor, head-sync, archive reader) receives a live `*http.Client` even on plaintext-dev boots — the v1.34 SDK contract is satisfied without requiring every dev deployment to add cert paths.

### Resolved — latent boot-error from the v1.27 → v1.34 jump

The pre-v1.34 `gossipnet/wiring.go:381-383`:

```go
if cfg.HTTPClient != nil {
    opts = append(opts, sdkgossip.WithHTTPClient(cfg.HTTPClient))
}
```

is now:

```go
if cfg.HTTPClient == nil {
    return nil, nil, fmt.Errorf(
        "gossipnet: HTTPClient required when PeerEndpoints is non-empty (...)")
}
client, err := sdkgossip.NewClient(ep, sdkgossip.WithHTTPClient(cfg.HTTPClient))
```

Combined with `buildPeerHTTPClient` always returning non-nil, every code path — mTLS, plaintext-dev, no-peers — boots cleanly under v1.34.

### Tests

- 6 new sentinel tests pin the fail-closed contracts: `TestAntiEntropy_RejectsNilHTTPClient`, `TestNewHeadSync_RejectsNilHTTPClient`, plus the v1.34 reframe of `TestBuildPeerHTTPClient_Unconfigured_ReturnsPlaintextClient` and `TestNewHeadSync_RejectsNilHTTPClient` (replacing the obsolete `_UsesDefault`/`_ReturnsNil` tests).
- Every pre-existing test that constructed one of the affected types now passes a real `*http.Client` (shared `testHTTPClient()` helper in the gossipnet package; `testHeadSyncHTTPClient()` for the witnessclient package). Assertions preserved byte-for-byte; only the construction call shape changed.
- Full suite under `-race`: every ledger package green, no regressions.

### Files

- Source: `cmd/ledger/boot/wire/wire.go`, `gossipnet/{antientropy,equivocation_monitor,wiring}.go`, `witnessclient/head_sync.go`, `lifecycle/archive_reader.go`.
- Tests: matching `_test.go` companions plus `gossipnet/{cross_ledger,escrow_override,equivocation_monitor,history_rewrite,smt_replay,v011_contract}_test.go`.
- `go.mod`: `github.com/baseproof/baseproof v1.33.1` → `v1.34.0`; `go.sum` regenerated.

## [Released] — v1.33.1 SDK adoption

### Security — load-bearing

v1.33.1 fixed a confused-authority foot-gun in v1.33.0's `AuditorRegistration.AuthorizedFor(kind)` method by splitting it into two intent-explicit methods. Beyond the compile-break fix, this release closes two correctness gaps PR #178 left open:

- **Gap 3 (KindAuditorCompromise) recordCompromise hook was unreachable.** PR #178 added the compromise-tracking branch *after* the `isFindingKind` early-exit in `gossipnet/auditor_scope_gate.go`. Since `KindAuditorCompromise` is not in the claim-class set, every compromise event short-circuited to passthrough and `recordCompromise()` was never invoked — meaning the compromise-cutoff map stayed empty and the fast-reject path was dead code. This release hoists the `KindAuditorCompromise` branch to the top of `Append` so the cutoff is recorded on every broadcast.
- **Gap 2 (amendment-merge) silent gate-vs-API disagreement.** The gate enforced the amendment-merged scope via `network.ResolveAuditorAt(records, amendments, did, asOf)`, but `auditorRegistryFetcher.LoadCurrentAuditors` served the raw registration scope. The moment any `AuditorScopeAmendmentV1` entry was admitted on-log, the `/v1/network/auditors` endpoint would report a different scope than the gate enforced. This release promotes the fetcher to `internal/auditorregistry` and rewires it to call the amendment-aware resolver per-DID, locking gate↔API consistency.

### Changed

- `go.mod` / `go.sum` bumped from `baseproof v1.33.0` to `baseproof v1.33.1`.
- `gossipnet/auditor_scope_gate.go` — `reg.AuthorizedFor(ev.Kind)` → `reg.AuthorizedForClaim(ev.Kind)` (v1.33.1 removed `AuthorizedFor`). The early-exit at the top of `Append` filters to claim-class only, so `AuthorizedForClaim` is the only call needed; proof-class kinds (`KindCrossLogInclusion`, `KindWitnessRotation`) are intentionally NOT gated here — their authority lives in the embedded cryptographic proof. Header doc + struct doc + `isFindingKind` doc refreshed to reference the v1.33.1 split.
- `gossipnet/auditor_scope_gate.go` — `KindAuditorCompromise` branch hoisted above the `isFindingKind` early-exit so `recordCompromise()` actually runs on broadcasts. The previously redundant `if ev.Kind != KindAuditorCompromise` guard on the compromise-check is removed (it was structurally dead after the hoist).
- `cmd/ledger/boot/wire/wire.go` — inline `auditorRegistryFetcher` replaced with `auditorregistry.New(registry, amendments, treeSizer)` from the new internal package. `wireV1_32Resolver` wires both sources from the resolver's `AuditorRegistryRecords` and `AuditorScopeAmendmentRecords`.

### Added

- `internal/auditorregistry/fetcher.go` — amendment-aware `Fetcher` implementing `api.AuditorRegistryFetcher`. Per-DID dispatch through `network.ResolveAuditorAt` so the projection's `Scope` field carries the merged value. Required `registry` and `treeSizer` constructor args; `amendments` is optional (nil treated as empty, equivalent to bootstrap-window posture).
- 8 new tests in `gossipnet/auditor_scope_gate_test.go`:
  - **Amendment-merge (Gap 2)**: `TestAuditorScopeGate_AmendmentExpandsScope`, `TestAuditorScopeGate_AmendmentReducesScope`, `TestAuditorScopeGate_FreshRegistrationSupersedesAmendment`, `TestAuditorScopeGate_RejectsWhenAmendmentSourceErrors`.
  - **Compromise (Gap 3)**: `TestAuditorScopeGate_CompromiseBroadcastAccepted`, `TestAuditorScopeGate_RejectsFindingFromCompromisedAuditor`, `TestAuditorScopeGate_CompromiseLowestSeqWins`, `TestAuditorScopeGate_PriorFindingNotRetroactivelyRejected`.
- 7 new tests in `internal/auditorregistry/fetcher_test.go` including `TestFetcher_AmendmentsMergeIntoScope` — the regression test that would have caught the PR #178 silent disagreement.
- `docs/v1.33.1-adoption-runbook.md` — operator runbook covering the new env var rollout, the new reject-reason counters, and operator playbook for compromise broadcasts.

### Bug fixes uncovered by the new tests

- `gossipnet/auditor_scope_gate.go` Gap 3 recordCompromise was unreachable. Found by `TestAuditorScopeGate_CompromiseBroadcastAccepted` failing on first run. Fixed by hoisting the branch above the claim-class early-exit.
- `cmd/ledger/boot/wire/wire.go` `auditorRegistryFetcher` ignored the amendment stream. Found by `TestFetcher_AmendmentsMergeIntoScope`. Fixed by replacing with the amendment-aware `internal/auditorregistry.Fetcher`.

### Operator migration notes

This release is a refinement of v1.33.0 with no new on-log entry kinds and no new env vars. The cutover order is:

1. Deploy the v1.33.1 binary. Existing `LEDGER_AUDITOR_SCOPE_AMENDMENT_SCHEMA` operator config (from v1.33.0) remains in effect unchanged.
2. Verify `auditor_scope_reject_total{reason="auditor_compromised"}` is reachable in the metrics surface (it was always exported; PR #178 just couldn't fire it on a compromise event because the recordCompromise hook was unreachable).
3. The `GET /v1/network/auditors` projection will now reflect amendments on every poll. Consumers MUST NOT cache the projection longer than the SDK's `ResolveAuditorAt` evaluation period — the existing `Cache-Control: public, max-age=60` is the recommended floor.

See `docs/v1.33.1-adoption-runbook.md` for the full operator-facing rollout protocol.

## [Unreleased] — v1.32.0 SDK adoption

### Security — load-bearing

The release closes five operator-config backdoors. Each one had the same shape: a load-bearing identity or URL the ledger trusted from operator config (env var, deployment manifest) — an attacker who could edit that config could silently redirect cosignature traffic, accept fabricated audit claims, or replace upstream-anchoring URLs without producing any on-log evidence. v1.32.0 moves the authoritative source for each of these to on-log entries that are network-signed, cosigned-tree-head-anchored, and walked deterministically by every consumer.

- **L1 — silent witness URL substitution closed.** `witnessclient/head_sync.go` now consults an on-log `WitnessEndpointDeclarationV1` walker (`*discover.DefaultAuthoritativeResolver`) at construction and uses those URLs in preference to `LEDGER_WITNESS_ENDPOINTS`. The env var remains as a bootstrap-window canary fallback; operators drop it once `endpoint_source{source="config_canary_fallback"}` is zero across the deployment.
- **L2 — auditor-scope authorization gate added.** `gossipnet/auditor_scope_gate.go` decorates the gossip `Store.Append` surface and rejects any finding-class event (`KindEquivocationFinding`, `KindSMTReplayFinding`, `KindHistoryRewriteFinding`) whose originator either is not registered as an auditor at the current `asOf` or whose `Scope` mask does not cover the event Kind. Pre-v1.32.0 the gossip Handler chain accepted any properly-signed event from any DID.
- **L3 — convenience endpoints for the on-log walker projections.** `GET /v1/network/labels`, `GET /v1/network/auditors`, `GET /v1/network/witness-endpoints` serve the materialized current projection. Pure CQRS: a fetcher seam (`WitnessLabelFetcher`, `AuditorRegistryFetcher`, `WitnessEndpointsFetcher`) is closed over the same on-log walker the ledger itself consumes for L1/L2. `Cache-Control: public, max-age=60`. Nil fetcher → 404 (deployment-not-wired); typed sentinel error → 404; other error → 500.
- **L4 — per-Kind structural validation at admission.** `admission/network_payload_validator.go` runs the SDK's per-payload `Validate()` on `WitnessEndpointDeclarationV1`, `WitnessIdentityLabelV1`, `AuditorRegistrationV1` payloads. Malformed entries get a 422 with the SDK's structural error message verbatim. Wired into `api/submission.go` as step 4g between schema validation and rotation validation.
- **L5 — silent parent URL substitution closed.** `anchor/resolved_submit.go` resolves the parent log's admission URL through an on-log `FederationGraph` walker per publish, falling through to `LEDGER_PARENT_ADMISSION_URL` only when the resolver returns empty or errors. Per-publish (not cached) so a transiently-poisoned FederationGraph cannot keep the ledger publishing to the wrong URL after the entry is corrected.

### Added

- `observability/v1_32_counters.go` — two OTel `Int64Counter` instruments:
  - `endpoint_source{source, surface}` — per-snapshot (L1) and per-publish (L5) source selection.
  - `auditor_scope_reject_total{reason, kind}` — per-reject classification (L2).
- 8 new test files locking the L1–L5 contracts (~1700 LOC):
  - `witnessclient/head_sync_resolver_test.go`
  - `gossipnet/auditor_scope_gate_test.go` + `gossipnet/auditor_scope_gate_kinds_test.go`
  - `admission/network_payload_validator_test.go`
  - `anchor/resolved_submit_test.go`
  - `api/labels_test.go` + `api/auditors_test.go` + `api/witness_endpoints_test.go`
- `docs/v1.32.0-adoption-runbook.md` — rollout order, env-var deprecation timeline, fail-closed traps, observability alerts, rollback procedure.

### Changed

- `go.mod` / `go.sum` bumped from `baseproof v1.31.0` to `baseproof v1.32.0`.
- `witnessclient.WitnessEndpointResolver` is now a NARROW one-method interface declared at the consumer rather than an alias for the SDK's `witness.EndpointResolver` (which embeds `LedgerEndpoint` — a method the ledger does not call). Mirrors the structural-typing pattern used by `admission.SignaturePolicyAmendmentSource`, `gossipnet.AuditorRegistrySource`, and `anchor.PeerAdmissionURLResolver`.
- `gossipnet.Build` now wraps `cfg.Store` with `AuditorScopeGate` when `cfg.AuditorRegistrySource` is set. When the source is `nil`, Build logs `gossipnet: auditor-scope gate DISABLED ...` and the pre-v1.32.0 open-ingest behaviour is preserved for the transition window.
- `api/submission.go` step 4g runs L4 between rotation validation and entry-size check.
- `api/server.go` registers the three new L3 handlers.

### Fixed

- `admission/pow_gate_test.go` — two tests (`StampForDifferentLogFailsHashCheck`, `TamperedNonceReturnsErrModeBStampInvalid`) were flaky-by-design at `difficulty=1` (~50% false-pass probability against random hashes). Raised to `difficulty=16` (~1/65,536 false-pass). The baseproof v1.32.0 canonical-layout change in `buildHashInputBuffer` surfaced this as a deterministic failure rather than the previous flake; the test difficulty bump is the right fix regardless of SDK version.

### Operator migration notes

The v1.32.0 binary is backward-compatible with deployments running pre-v1.32.0 on-log entries — the canary fallbacks keep the ledger operable until the network's admission authority has published the new entry kinds. The cutover order documented in the runbook is:

1. Deploy v1.32.0 binary with old env vars still set. Verify `endpoint_source{source="on_log_resolver"}` is incrementing.
2. Drop `LEDGER_WITNESS_ENDPOINTS` and `LEDGER_PARENT_ADMISSION_URL` from manifests after the on-log walker has been verified at boot.
3. Audit `auditor_scope_reject_total` for `reason="not_registered"` from known-auditor DIDs — those indicate config drift between the operator's auditor list and the on-log registry.

The schema-ID env vars (`LEDGER_WITNESS_ENDPOINT_SCHEMA`, `LEDGER_WITNESS_LABEL_SCHEMA`, `LEDGER_AUDITOR_REGISTRATION_SCHEMA`) are permanent — they identify which schema-ID a given network uses to admit each on-log entry kind. They are NOT canary paths. _**[Superseded by PRE-11 Phase B (#114): this "permanent" claim is retracted. These were the AuthoritativeResolver's record locators, not admission inputs; they are removed, and resolution is now by-kind from `idx_entry_kind`.]**_

### Coordination

- `tooling` should adopt the materialized walker views in a follow-up PR (~480 LOC). The CLI gains a `view auditors`/`view witness-endpoints`/`view labels` command set.
- `judicial-network` Phase 3 should drop `cfg.Witness.Sets`, swap `StaticEndpoints` for `*DefaultAuthoritativeResolver` (~300 LOC). Until JN adopts, its peer-ledger queries resolve URLs from JN's own config rather than from the ledger's on-log declarations.

### Acceptance criteria for "v1.32.0 fully adopted" per network

1. `endpoint_source{source="config_canary_fallback"}` zero across both surfaces.
2. `LEDGER_WITNESS_ENDPOINTS` and `LEDGER_PARENT_ADMISSION_URL` removed from manifests.
3. At least one `AuditorRegistrationV1` per active auditor admitted on-log.
4. At least one `WitnessEndpointDeclarationV1` per witness in the set admitted on-log.
5. `auditor_scope_reject_total{reason="no_registry"}` zero.
6. `auditor_scope_reject_total{reason="scope_mismatch"}` zero.
7. CI green on the running ledger binary.

When all seven hold for 7 consecutive days, the backdoors v1.32.0 was designed to close are operationally closed for that network. See `docs/v1.32.0-adoption-runbook.md` for the full rollout protocol.
