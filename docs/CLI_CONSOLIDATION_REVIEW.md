# CLI consolidation — evidence review & plan amendments

**Status:** review of `docs/CLI_CONSOLIDATION.md` against code at HEAD
**Evidence base:** `tooling@b02997a` (libs/v0.1.9), `baseproof@c688a2f` (v0.0.4-rc3);
re-verified same-day against `cli@732d146` (v0.1.1) and `judicial-network@91c3852`
after both repos moved mid-review. Every claim below was verified by reading code,
imports, tags, and tests — not comments or docs. Where the plan and the code
disagree, the code wins and the discrepancy is called out.

## 1. Verification of the plan's claims

| Plan claim | Verdict at HEAD | Evidence |
|---|---|---|
| 20 `package main` binaries across 3 repos | **23** dirs (SDK 2, cli 1, tooling 20) — plus **9 more in judicial-network** the plan never inventoried | `grep -rl "^package main"` sweep; JN: `cmd/{judicial-cli,network-api,e2e,add-destination,add-destination-fields,verify-destination}`, `tools/{aggregator,court-tools,provider-tools}/cmd/*` |
| `submit-stamp`/`backfill` are stale duplicates of `baseproof submit`/`load` | Confirmed; both still exist, import only SDK + ledger `internal/{clienttls,retryhttp}` | `services/ledger/cmd/submit-stamp/main.go:43-66`, `cmd/backfill/main.go:45-72` |
| `audit`/`admission-authority`/`signature-policy` couple to the ledger only via the two generic helpers | Confirmed | each `main.go` import block (agent-verified, SDK + clienttls + retryhttp only) |
| `init-network` is SDK-only | Confirmed (SDK + secp256k1 + stdlib) | `cmd/init-network/main.go:43-60` |
| "promote `clienttls` + `retryhttp` to libs (~162 + ~150 lines)" | **Half-wrong.** `libs/clienttls` already exists but is a *different* API (379 lines; env+flags; returns `*http.Client` + `Posture`) vs the ledger's flag-only `*tls.Config` variant (163 lines). `retryhttp` has **no** libs equivalent at all. The port is an adaptation, not a promotion. | `libs/clienttls/clienttls.go` vs `services/ledger/internal/clienttls/clienttls.go`; `internal/retryhttp/retryhttp.go` (151 lines, no counterpart under `libs/`) |
| "or switch the tools to `libs/clitools`" | **Only for reads.** `clitools.VerifyClient` calls `/v1/verify/*` and `ExchangeClient` calls `/v1/build-sign-submit` — routes the ledger does **not** register; they are exchange-side (JN network-api) surfaces. Only `LedgerClient` talks to the ledger. Also see §3 (clitools is court-coupled). | ledger route table `services/ledger/api/server.go:404-651` (53 routes, none of these); `libs/clitools/{verify_client.go:59-77,exchange_client.go:61}` |
| Ledger admin API / operations API / maintenance flag (Plane 3) | **None exists.** No route matching admin/maintenance/operation. But `Server.writable` (`atomic.Bool`) already degrades writes to 503 while reads serve — the natural seam for soft maintenance. | `services/ledger/api/server.go:171` and route table at `:404-651` |
| Shim was byte-identical, drifted via PR #69 | Drifted 06-10 02:52→12:14, then **manually re-synced** (cli PR #2 "Relay from tooling/baseproof-cli", released as `v0.1.1`); byte-identical again. See §2. | `cli@12b4fe1`; `diff baseproof-cli/commands.go <(git show origin/main:commands.go)` = identical |
| `cli` repo unscanned by the dependency law | Confirmed: the law scans `libs` + `services/{auditor,witness}` only; `baseproof-cli/` and `e2e/` are also outside it | `scripts/dependency-law.sh:37` (`find libs services -name go.mod`), `scripts/lib/governed.sh` |
| Reference cleanup is a broad sweep risk | **Smaller than feared.** CI references none of the binaries. Touch points: `services/ledger/scripts/local/Dockerfile:60-114` (builds submit-stamp, init-network, backfill, admission-authority, rebuild-projection), `scripts/run-e2e.sh:91` (runs init-network), `run-local.sh:78` (submit-stamp, commented out). | reference sweep, all workflows checked |
| e2e drives the `libs/cli` seams | Confirmed for `network add --from-ledger`, `submit`, `proof`, `verify` (offline), `info --verify`, `load`. **Not** covered: `witnesses`, `config`, and the whole gated-write surface (no enforcer in the fleet). | `e2e/runner/runner.go:107-202` |

## 2. Finding — `baseproof/cli` is the canonical front end; the relay held this
## time, by hand

**Correction history.** An earlier draft of this review reported the extracted
`cli` repo stuck at `libs v0.1.7`, missing the gated-write surface, with a
behavioral consequence (a `write_endpoint` bundle silently degrading to a direct —
refused — ledger write). That was accurate at clone time and is **no longer
current**: cli PR #2 ("Relay from tooling/baseproof-cli: gated-network writes +
cosignature models", `12b4fe1`, merged 06-10 12:14) bumped the pin to
`libs v0.1.9`, restored `commands.go` to byte-identical with the shim, and shipped
as release **`v0.1.1`**; judicial-network PR #163 (`65872da`) converged on
`libs v0.1.9` + SDK `rc3` the same day. The version matrix is flat at this instant:
cli, JN, and tooling HEAD all consume libs v0.1.9.

What the episode establishes (and what remains actionable):

- **`baseproof/cli` is the CLI.** It owns the packaging layer the shim never will —
  version stamping, man pages, completions, GoReleaser, Sigstore keyless signing,
  SLSA provenance, Homebrew tap. The shim is not a front end to maintain; it is a
  delete-when-convenient line item (migration step 1; verified zero CI/e2e
  references). This review spends no further analysis on it. The development-loop
  need it served (a binary built against libs HEAD) is met by a checkout of the
  `cli` repo with a local `replace`, or `go run` against the workspace.
- **The relay is still a manual process** that worked because someone noticed
  within ~13 hours; the commit message *is* the process. There is no parity test,
  no tag-freshness gate, and no automation that would catch the next missed relay
  at compile time. cli PR #2 added no tests (its diff: `commands.go`, `go.mod`,
  `go.sum`, `.goreleaser.yaml` only), so nothing pins the Cobra surface to the
  libs seams.
- **The strict-decode gap now has a released instance.** `cli v0.1.0` binaries
  (installed before the relay) parse a `write_endpoint` bundle with plain
  `json.Unmarshal` — no `DisallowUnknownFields` (`libs/cli/clientbundle.go:92-94`)
  — silently dropping the field and writing direct, which a gated ledger refuses.
  Nothing in the bundle tells an old binary "you are too old for this network";
  only upgrading fixes it. `netmanifest.Decode` already shows the strict pattern
  (`judicial-network/netmanifest/manifest.go:496-507`).

### Amendment 2A — make recurrence impossible at compile time

1. **Surface-as-spec:** move flag/command declarations into `libs/cli` as data (a
   `CommandSpec` table the stdlib dispatch **and** the Cobra front end both
   render). "The logic is the library" becomes "the surface is the library"; a
   parity test in the `cli` repo locks binary ↔ libs.
2. **Tag-freshness gate:** a `cli`-repo CI job that fails when the `libs` pin is
   older than the newest `libs/v*` tag — the same canonical-derivation pattern as
   tooling's SDK-version-pin job (`ci.yml:73-112`). Optionally, a tooling job that
   builds the `cli` repo against libs HEAD via `replace` before tagging.
3. **Strict bundle decode** (see §4A.5) so released binaries fail loudly on
   newer bundles instead of silently changing write behavior.
4. Delete `tooling/baseproof-cli` whenever convenient — no analysis needed.

Until item 1 lands, every new `libs/cli` flag is a latent repeat of the PR #69
drift, with detection dependent on a human noticing.

## 3. Finding — domain-agnosticism: imports are clean, vocabulary is not

LAW 1 holds at the import level: **zero** `clearcompass-ai/*` imports anywhere in
`libs/`, the shim, or the `cli` repo; the SDK's only domain references are godoc
examples and test fixtures. But the law checks `go list -deps`, so *vocabulary*
coupling sails through:

| Where | Coupling | Class |
|---|---|---|
| `libs/clitools/config.go:26-30,97-102,129,134` | `CourtDID`, `OfficersLogDID`, `CasesLogDID`, `PartiesLogDID`, `CourtToolsAddr`, `CourtSSOIssuer`, `TOOLS_COURT_DID`/`TOOLS_COURT_ADDR` env, `court_tools` DB name | exported identifiers + env contract |
| `libs/clitools/types.go` | `Case`, `Evidence`, `Judge`, `Party`, `CaseContext`, `Courtrooms`, `JudgeDID` — comment admits "Domain types — used by courts/, providers/, aggregator/" | exported types |
| `libs/monitoring/custody_chain_compliance.go:49`, `dual_attestation.go:36` | monitor IDs `judicial.custody_chain_compliance`, `judicial.dual_attestation` | wire-visible IDs |
| `libs/monitoring/dashboard.go:49-100` | `CourtHealth`, `TotalCourts`, `CriticalCourts`, per-court aggregation | exported types |
| `libs/cli/submit.go:46,98,160-167,304-330` | `submitViaJN`, `postThroughJN`; user-facing flag help and error text naming "the JN" ("JN submit HTTP %d", "the JN accepted the write…") | identifiers + **user-visible strings** in the universal client |
| `libs/cli/clientbundle.go:55-64` | `WriteEndpoint` doc: "the JN enforcer's base URL" (while *asserting* "The CLI stays domain-agnostic") | comment |
| `baseproof-cli/commands.go:19-23` | "write goes THROUGH the JN enforcer" in `submit --help` | user-visible string |
| `libs/{cache,outbound,clienttls,auditing/*}` | "JN" in comments only (e.g. `clienttls.go:132`: "the JN's judicial-cli SHOULD use this" — it doesn't; see below) | comments |

**The concept is already agnostic; the naming is not.** The gated-write mechanism is
generic: POST wire bytes to a write gate that mints the gate-5 `WriteAuthorization`
(SDK `authz`, agnostic), poll the ledger. JN's own manifest vocabulary is the
agnostic one — `Admission.Gating = "write-authorization"`, `WriteVia = "gate"`
(`netmanifest/manifest.go:97-102`). The fix is lexical + structural:

### Amendment 3A — rename JN → gate in the agnostic layer
`submitViaGate`/`postThroughGate`; help/error text says "write gate / gated
network"; `WriteEndpoint` documented as "the network's write gate." Zero behavior
change, removes the domain name from every user-visible string in the universal
client.

### Amendment 3B — split `libs/clitools` before building Bucket B on it
The plan routes ported tools through clitools; today that links court-typed code
into governance tooling. Split: agnostic client core (`LedgerClient`,
`VerifyClient`, `ExchangeClient`, content store, horizon verify) stays in `libs`;
`Case`/`Evidence`/`Judge`/`Party` + `Court*` config moves to judicial-network
(its `tools/{court-tools,provider-tools,aggregator}` are the only consumers).
Same for `libs/monitoring`'s `judicial.*` monitor IDs and `CourtHealth` dashboard:
either parameterize the ID namespace or relocate the checks to the tenant.

### Amendment 3C — extend the law from imports to vocabulary
Add a LAW 5 lint to `dependency-law.sh`: forbid domain lexemes
(`judicial|court|case_|judge|JN`) in exported identifiers and user-facing strings
under `libs/` (allowlist for protocol-mandated names). The law is the only thing
that *keeps* agnosticism true over 15 years; today it cannot see this class.

### Amendment 3D — the domain CLI should be an overlay, not a re-implementation
`judicial-cli` imports **zero** tooling libs and re-implements build→sign→POST
`/v1/entries`→poll `entries-hash` (`cmd/judicial-cli/{submit.go,manifest.go:199-212}`)
— the exact logic of `libs/cli` `RunSubmit`/`pollSequence` and `libs/loadgen.SubmitOne`.
Its agnostic subcommands (`submit`, `keygen`, `get`, `head`, `inclusion`, `wait`)
duplicate the unified client; only `publish-manifest` and `onboard` are domain
logic. JN's *services* already consume `libs/clitools` — the CLI should follow.
Target: domain CLIs = thin overlays adding domain verbs over `libs/cli` seams.
(This is the same "thin front end" rule the plan applies to the `cli` repo,
extended to tenants — it belongs in the plan as an explicit principle.)

## 4. Finding — the "network bundle" is produced but consumed by nothing

Six artifacts answer to "bundle"; the two that matter to the CLI never meet:

| Artifact | Format tag / type | Producer | Consumer |
|---|---|---|---|
| SDK proof-side injection | `protocol.NetworkBundle` (`baseproof/protocol/protocol.go:125-158`) | `libs/networkbundle.Build` + JN's duplicate copy | `libs/cli` proof/info gather |
| Ledger proof bundle | `baseproof-bundle/v1`, `GET /v1/bundle/{seq}` (`api/server.go:651`) | ledger | SDK/mirror clients |
| Portable proof | `baseproof-bundle/v2-self-anchored` (`log/bundle/v2.go:48`) | `baseproof proof` | `baseproof verify` |
| **Client bundle** | `baseproof-client-bundle/v1` (`libs/cli/clientbundle.go:21`) | `network add --from-ledger` authoring, `saveNetwork` | the CLI only |
| **Consumption manifest** | `baseproof-network-manifest/v1`, `GET /v1/network/bundle` (`judicial-network/netmanifest/manifest.go:42`) | JN `manifesthttp` + `judicial-cli publish-manifest` | **nobody** — zero client code in any repo |
| Domain policy bundle | `jurisdiction.Bundle` (JN) | JN deployments | JN gate + manifest projection |

Evidence of the gap:

- **No consumer.** `grep "network/bundle"` across all four repos hits only JN's
  server, tests, and docs. The SDK's discovery layer (`log/discover`) knows
  `/v1/network/{peers,mirrors,witnesses,…}` but not `/v1/network/bundle` — despite
  `netmanifest`'s claim that the path "slots into the /v1/network/* discovery
  family the SDK's log/discover clients consume."
- **The CLI can't import it.** `network add --from <url>` decodes a
  `baseproof-client-bundle/v1` only (`libs/cli/network.go:172-184`); feeding it a
  manifest fails on the format tag.
- **The served manifest isn't self-certifying yet.** `NetworkRef` has the
  Zero-Trust pin fields (`network_id`, `bootstrap_hash`, `bootstrap_endpoint`,
  `quorum_k`) but both producers fill only `Name`
  (`cmd/judicial-cli/manifest.go:121-122`; `cmd/network-api/main_helpers.go:358`).
  A consumer could not verify "this manifest describes the network it claims" today.
- **The manifest's core is already domain-free.** `NetworkRef`/`Endpoint`/
  `Transport`/`Admission`/`Submit`/`StatusProbes`/`Datatype` reference no JN types;
  only `Operation.Signing` (`policy.CosignatureRule`), `Roles` (`schemas.Role`) do
  (`Requires` already uses tooling's `libs/prereq`).
- **The duplicate builder.** `libs/networkbundle` and JN's `networkbundle` are
  functionally identical; JN imports only its own copy (`e2e/runner/proof.go`)
  despite depending on tooling libs.

### Amendment 4A — define "fully implement the network bundle" as five work items

1. **Promote the manifest's agnostic core** (NetworkRef, Endpoints, Transport,
   Admission, Submit, StatusProbes, Datatypes, and Operations with
   `Signing`/`Roles` abstracted or omitted) into `libs` (e.g. `libs/netmanifest`),
   keeping JN's package as the domain extension that embeds its policy types.
   `Decode` keeps `DisallowUnknownFields`.
2. **Fill `NetworkRef` at publish/serve time** (network_id, bootstrap_hash,
   bootstrap_endpoint, quorum_k) so the document is verifiable: consumer fetches
   the bootstrap, recomputes SHA-256(JCS) = network_id — the same ZT check
   `authorBundleFromLedger` already performs (`libs/cli/network.go:204-213`).
3. **Implement the consumer in the CLI**: `baseproof network add --from <url|file>`
   detects `baseproof-network-manifest/v1` and derives the ClientBundle —
   `Endpoint` from the ledger endpoint entry, `WriteEndpoint` from
   `Admission.WriteVia` when `Gating == "write-authorization"`, transport from
   `Endpoint.Transport.CAPin`, trust root from `NetworkRef`. Decide and document
   the `LogDID` mapping (manifest `Exchange` ↔ destination DID) and the **quorum
   provenance rule** (an on-log, hash-verified manifest is a governance statement
   of K; an HTTPS-only manifest is TOFU — `--quorum` override stays).
4. **Decide who serves it for ungated networks.** Today only JN's gate serves
   `/v1/network/bundle`. Either the ledger serves a minimal manifest (it already
   serves identity/bootstrap/peers and knows its admission posture) and the path
   joins the platform discovery contract (then teach SDK `log/discover` about it),
   or the path is explicitly a gate-level contract and the SDK claim is dropped.
5. **Strict-decode the client bundle** (`DisallowUnknownFields` or
   known-field/version check in `LoadClientBundle`) so older binaries fail loudly
   on newer bundles instead of silently degrading (§2). This is one line plus a
   compat decision, and it is what turns format evolution from a silent hazard
   into an error message.

Also: pick one user-facing term per artifact (the CLI's `verify --bundle` help
currently calls the client bundle a "network bundle", `cli/commands.go:97`) and
de-duplicate `networkbundle` by switching JN to `libs/networkbundle`. Note: JN's
bump to libs v0.1.9 (JN PR #163) did **not** de-duplicate — versions are now
aligned, so the switch is a one-line import change awaiting someone to make it.

## 5. Finding — test coverage: strong core, gaps exactly where the risk is

Verified per-test (all in `libs/cli`): bundle load/validate + catalog + federation
(`clientbundle_test.go`), config-store precedence + **ZT authoring fail-closed on
identity lie** (`config_test.go:76`), federation info walks (`info_test.go`), live
HTTP proof gather + horizon verify (`live_http_test.go`), real-crypto proof
round-trip + tamper detection (`realproof_test.go`), fail-closed offline verify
(`verify_test.go`), `RunLoad` end-to-end with JSONL oracle
(`clientbundle_test.go:180`), gated-write multi-sig wire shape vs a fake enforcer
(`via_jn_test.go:29`), witnesses time-travel (`witnesses_test.go`).

Gaps (each maps to a §2–§4 risk):

- `importBundle` (`--from <file|url>`) — untested.
- Unknown-field leniency of `LoadClientBundle` — untested (the exact §2 failure mode).
- Cosignature **model #2** (`--cosign`, `Header.CosignatureOf`) — only flag parsing
  is tested (`TestParseLogPos`); no submit-path test.
- The `cli` repo and the shim have **zero tests** — nothing pins the Cobra surface
  (the §2 parity problem).
- Platform e2e has no gated-write stage (no enforcer in the fleet) and no
  `witnesses`/`config` stages; manifest import has nothing to test yet.

### Amendment 5A — test additions, ordered by leverage
(1) strictness test for `LoadClientBundle` + the strict-decode fix; (2) surface
parity test in the `cli` repo (or the spec-table refactor that obsoletes it);
(3) model-#2 submit test beside `TestSubmitViaJN`; (4) `importBundle` file+URL;
(5) e2e gated-write stage using a stub gate (the `via_jn_test` fixture pattern,
promoted into the e2e fleet); (6) manifest→ClientBundle import round-trip once 4A.3
lands.

## 6. Corrections to carry back into CLI_CONSOLIDATION.md

1. **Inventory**: 23 binaries at HEAD across SDK/cli/tooling (the ctx-* scripts and
   the extracted `cli` shifted the count), plus the 9 JN binaries — the plan should
   classify tenant CLIs too (JN's three AST/codegen tools are Bucket D; its three
   service daemons are Bucket A; `judicial-cli` is the §3D overlay case).
2. **Step 2 unblock**: replace "promote clienttls + retryhttp" with "adapt Bucket B
   tools to `libs/clienttls.Flags.Client()`; promote `retryhttp` (or fold its
   transient-retry transport into `libs/clienttls`/`outbound`); use `clitools`
   only for ledger reads."
3. **Step 3 anchor**: soft maintenance should be specified as an authenticated
   toggle over the existing `Server.writable` degrade path (503 writes, live
   reads), not a new mechanism.
4. **Reference sweep**: replace the open-ended "sweep Makefiles/compose/CI" risk
   with the verified three touch points (local Dockerfile, run-e2e.sh:91,
   run-local.sh:78 comment).
5. **Add the missing workstreams**: the network-bundle items (§4A) and the
   domain-vocabulary law (§3C) are prerequisites for "domain-agnostic CLI that
   fully implements the network bundle", and neither appears in the plan.

## 6b. Addendum — found & fixed during this review: the witness-history
## genesis hole

Live repro (the mo5 network): `baseproof witnesses` → `HTTP 404 from
/v1/network/witnesses/current` while `info --verify` showed `witnesses 2-of-0`
yet verified the horizon 2/2. Root cause, traced end-to-end: the
`/v1/network/witnesses/*` endpoints serve only `witness_sets` rows
(`api/witnesses.go`), the **only** writer of that table is the rotation path
(`witnessclient/rotation_handler.go` — `INSERT INTO witness_sets`), and boot
falls back to the genesis set **in memory only**
(`cmd/ledger/boot/wire/gossip.go::wireWitnessQuorum`) — so a never-rotated
network 404s forever, and worse, the FIRST rotation's `UPDATE … WHERE
retired_seq IS NULL` retires nothing on an empty table, leaving the genesis
era permanently uncovered. Migration 0014 designed the genesis-baseline row
("0 for the genesis baseline … loaded from config at boot") but nothing wrote
it; the handler doc prescribed *operator seeding* — an off-log step.

Fixed in this branch, per the log-driven doctrine (nothing operator-seeded;
the row is a pure derivation of the trust root):

- `services/ledger/witnessclient/genesis_seed.go` — `SeedGenesisBaseline`,
  idempotent boot-time reconcile: empty table → genesis row ACTIVE at
  effective_seq 0; rotated-before-baseline table → genesis row RETIRED at the
  earliest rotation (hole backfill); already recorded → no-op. Wired
  fail-closed at the end of `wireWitnessQuorum`; writer-only (`ledger-reader`
  does not run this wiring). Three DB-gated tests.
- `libs/cli` — `witnesses` falls back on 404 to the genesis set derived from
  the **hash-verified bootstrap** (works against unpatched ledgers and PG-off
  readers; refuses to guess over a *real* history hole when `/current`
  serves); `info` renders `K-of-N (genesis, derived from bootstrap)` instead
  of the misleading `K-of-0`. Typed `httpStatusError` from `getJSON`. Tests.

The deeper design — genesis recorded ON-LOG via an endorsed ceremony, and the
ceremony generalized to every platform event — is specified in
`docs/WITNESSED_CONFIGURATION.md`.

## 7. Definition of done — "fully hashed out"

The cleanup is hashed out when every box below is checkable by CI or by a
one-command audit, not by reading docs:

- [ ] One Cobra front end (`baseproof/cli`); `tooling/baseproof-cli` deleted;
      e2e still green (it imports `libs/cli` directly and never referenced the shim).
- [ ] Flag surface generated from `libs/cli` specs; parity enforced by test.
- [ ] `cli` repo CI fails on stale `libs` pin (tag-freshness gate), mirroring the
      SDK-version-pin job pattern.
- [ ] `LoadClientBundle` rejects unknown fields; bundle format changes produce
      errors, not silent behavior changes.
- [ ] No domain lexemes in `libs/` exported identifiers or CLI-visible strings
      (LAW 5 green); `clitools` split landed; `judicial.*` monitor IDs relocated
      or parameterized.
- [ ] `GET /v1/network/bundle` has a consumer: `baseproof network add --from`
      imports a manifest whose `NetworkRef` is populated and hash-verified; the
      serving decision (ledger vs gate) is recorded in the plan.
- [ ] JN imports `libs/networkbundle` (duplicate deleted) and `judicial-cli`'s
      agnostic subcommands delegate to `libs/cli`/`clitools`.
- [ ] `submit-stamp` + `backfill` deleted; local Dockerfile + scripts repointed to
      the `baseproof` binary.
- [ ] Bucket B ports land as `RunLedgerX` seams + e2e stages (including a gated
      write against a stub gate); Plane-3/4 unchanged until the admin/operations
      API exists.
- [ ] Version matrix (SDK ↔ libs ↔ cli ↔ JN pins) published and CI-checked
      cross-repo.
