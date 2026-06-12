# CLI consolidation — moving sensible CLIs into `baseproof/cli`

**Status:** proposal (for review — no code changes yet)
**Scope:** `baseproof/cli`, `baseproof/tooling`, `baseproof/baseproof`

## Why this exists

Today "the CLI" is not one thing. There are **20 `package main` binaries** spread
across the three repos, plus a byte-for-byte duplicate of the unified client kept
"for compatibility" at `tooling/baseproof-cli`. We want:

1. every *sensible* CLI to live in the unified `baseproof/cli` binary;
2. user/operator-facing **ledger** operations namespaced under `baseproof ledger …`
   so all of them sit in one place, with a **gcloud-style noun → verb** surface
   (`describe` / `list` / `create` / `update` / …) that stays predictable for 15 years;
3. everything else exposed as a **service API endpoint** or an **operation**, not a
   standalone binary — and the heavy/blocking ones gated behind **maintenance mode**.

This document inventories every binary, states the one rule that decides where each
can live, and lays out the target end state + a migration sequence. It changes no
code.

## The rule that decides everything

It is **not** "does it feel like a CLI." It is **what the tool imports**, because the
dependency law (`scripts/dependency-law.sh`, LAW 1) is compiler-enforced:

> no `libs/*` and no first-party `services/*` may link
> `baseproof/tooling/services/ledger` (the colocated domain tenant).

The unified client's logic lives in `libs/cli` (each command is a `RunX(ctx, args)`
seam that `tooling/e2e` drives — "the logic is the library"). So a command can join
the unified CLI **only if its logic imports the SDK + HTTP and nothing from the
ledger module.** The ledger additionally carries a `third_party/tessera` git
submodule, so importing it into the universal client is a non-starter on size and
layering grounds regardless.

| If a tool's logic needs… | It can become… |
|---|---|
| **SDK + HTTP only** | a `libs/cli` `RunX` seam → a `baseproof` subcommand |
| **ledger storage internals** (`store`, `bytestore`, `tessera`, `recovery`, `builder`, `lifecycle`) | a ledger **API endpoint**, or an offline ops binary — never a client command |

This pattern is **already proven**: `libs/loadgen` is the SDK-only engine, and
`baseproof submit` / `baseproof load` (in `libs/cli`) drive it. The ledger's
`submit-stamp` and `backfill` are now stale duplicates of that exact path.

## Inventory & verdict

### Bucket A — daemons → stay as services (not CLIs)

| Binary | Path |
|---|---|
| `ledger` | `tooling/services/ledger/cmd/ledger` |
| `ledger-reader` | `tooling/services/ledger/cmd/ledger-reader` |
| `auditor` | `tooling/services/auditor/cmd/auditor` |
| `standalone-witness` | `tooling/services/witness/cmd/witness` |
| `artifact-store` | `tooling/services/ledger/artifactstore/cmd/artifact-store` |

Long-running HTTP servers. Out of scope for "move to CLI."

### Bucket B — SDK-only client tools → move into `baseproof/cli`

| Binary | Couples to (beyond SDK) | Verdict |
|---|---|---|
| `submit-stamp` | ledger `internal/{clienttls,retryhttp}` | **already** = `baseproof submit`; delete |
| `backfill` | ledger `internal/{clienttls,retryhttp}` | **already** = `baseproof load` (via `libs/loadgen`); delete |
| `audit` (ledger) | ledger `internal/{clienttls,retryhttp}` | → `baseproof ledger audit` (live K-of-N checkpoint + SMT sampling) |
| `admission-authority` | ledger `internal/{clienttls,retryhttp}` | → `baseproof ledger admission-authority` |
| `signature-policy` | ledger `internal/{clienttls,retryhttp}` | → `baseproof ledger signature-policy` |
| `genesis-ceremony` (superseded init-network) | SDK only | → `baseproof network init` (optional; dev mode wraps `genesis-ceremony dev`) |

The **only** thing tying these to the ledger module is two *generic* HTTP helpers —
`internal/clienttls` (~162 lines, TLS config) and `internal/retryhttp` (~150 lines,
retry transport). Neither is ledger-specific. The unblock is to either (a) use
`libs/clitools`, which already exposes `LedgerClient` (reads) / `VerifyClient`
(verification) / `ExchangeClient` (writes), or (b) promote the two helpers into
`libs` (e.g. alongside `libs/httpmw`'s tuned client). After that swap these tools
import **only the SDK** and qualify as `libs/cli` seams.

> `submit-stamp` and `backfill` are not ports — they are **deletions**. `libs/cli`
> `RunSubmit` already does Mode A token + Mode B PoW via `loadgen.SubmitOne`, and
> `RunLoad` already drives `loadgen.Run` with `--amend-ratio` / `--delegate-ratio`
> / the JSONL oracle manifest. The ledger copies predate that migration.

### Bucket C — coupled to ledger storage → become API endpoints / offline ops

| Binary | Couples to | Verdict |
|---|---|---|
| `seed-session` | ledger `store` (Postgres) | admin, light → `baseproof ledger session …` (admin API) |
| `backfill-node-index` | ledger `store`, `bytestore` | admin, HEAVY but live-safe → `baseproof ledger reindex` (Plane-3 operation) |
| `rebuild-projection` | `recovery`, `store`, `bytestore`, `tessera` | HEAVY + BLOCKING → Plane-4 Job, **hard maintenance** (ledger stopped) |
| `rebuild-tiles` | `builder`, `lifecycle`, `store`, `tessera` | HEAVY + BLOCKING → Plane-4 Job, **hard maintenance** ("stop the ledger first") |

These touch the ledger's own Postgres/tile internals. They cannot move into a client
binary without violating LAW 1. The live-safe ones become admin endpoints; the
offline disaster-recovery ones stay ops binaries (an honest design — they run with
the ledger stopped, so they can't be live endpoints).

### Bucket D — repo-internal dev/CI tooling → stay put

`baseproof/cmd/audit` (mutation + scope audit), `baseproof/cmd/lint-binding` (AST
lint), `tooling/e2e/cmd/e2e` (e2e runner — already drives `libs/cli`),
`tooling/services/witness/cmd/gen-fixtures`, `tooling/services/ledger/scripts/ctx-*`.
None are user-facing.

### The compat shim — delete it (and the drift has already started)

When this doc was first drafted, `tooling/baseproof-cli/commands.go` was
**byte-identical** to `cli/commands.go`. It no longer is: the JN write-through
change (PR #69 — `WriteEndpoint`, `--cosigner-keys`, `--cosign`) landed on the
**shim's** commands.go while the extracted `cli` repo did not receive it. That is
exactly the drift keeping two front ends invites, and it upgrades this item from
"nice cleanup" to "actively diverging surface." The shim's own `go.mod` comment
promised "extraction to its OWN repository next sprint" — the extraction is done
(the `cli` repo is the live one). Deletion is now a two-step: port the JN-write
flag surface to the `cli` repo's commands.go (the logic already lives in
`libs/cli`, shared by both), then remove the shim.

## The principle that splits Bucket B from Bucket C

It is not "user-facing vs not." It is **who holds the trust / the key**:

- **Operator holds a key or makes a trust decision → CLI command.**
  `admission-authority` / `signature-policy` sign a `WriteAuthorization` with a
  governance G-key over a witness-cosigned, verified horizon. That key must stay
  client-side; making it a server endpoint would force the ledger to hold governance
  keys — inverting the zero-trust model and LAW 3 ("the keystore is linked, not
  dialed"). → `baseproof ledger …`
- **Pure server-side state mutation, no external key → API endpoint.**
  `seed-session` writes rows; `backfill-node-index` scans tiles. → `/v1/admin/…`
- **Offline storage surgery (ledger stopped) → ops binary.**
  `rebuild-projection` / `rebuild-tiles` cannot honestly be live endpoints.

## Target surface — a gcloud-style noun → verb model

A 15-year operator should never guess a command. The model is gcloud's: a small,
**consistent verb vocabulary** applied to **resources**, with long-running work
surfaced as **operations** you poll rather than commands that block your terminal.

**Verb vocabulary** (the same verbs mean the same thing on every resource):

| Verb | Meaning |
|---|---|
| `list` | enumerate resources (read) |
| `describe` | full detail of one resource (read); `get` is an alias |
| `create` | author a new resource |
| `update` | publish a new state of an existing resource (declarative — replaces, not patches) |
| `delete` / `revoke` | remove / invalidate |
| domain verbs | `submit`, `verify`, `wait`, `cancel` where a resource needs them |

**Plane 1 — network-agnostic client (works against *any* bound network; stays
top-level).** These are the universal verbs; the flat names you have today become
the ergonomic aliases of canonical resource forms.

```
baseproof config      {get, set, list}                 # CLI defaults (active network, …)
baseproof network     {create, list, describe, use, delete, init}
                      #  create  ← was `add`   (--from-ledger | --from)
                      #  describe← was `show` + the rich `info` (--verify, --federation)
                      #  use     ← set the active network        init ← was genesis-ceremony dev
baseproof entries     {submit, describe}                # submit ← top-level `submit` alias
baseproof proof       {create, verify}                  # create ← `proof`; verify ← `verify`
baseproof witnesses   {list, describe}                  # list ← `witnesses` (--at N)
baseproof auditors    {list, describe}
baseproof load        ...                               # loadgen (unchanged)
```

**Plane 2 — operating a ledger (`baseproof ledger …`; the namespaced ops).**
Governance + admin, all in one place. Light, online, key-holding or admin-only:

```
baseproof ledger admission-authority {describe, update}   # update = publish the FULL declarative set (G-key)
baseproof ledger signature-policy    {describe, update}   # update = publish the FULL policy (incl. PQ cutover; G-key)
baseproof ledger session             {create, list, describe, revoke}   # credits/tokens (admin API; was seed-session)
baseproof ledger audit               run                  # light-client K-of-N checkpoint + SMT sampling
```

**Plane 3 — heavy/async work as operations (gcloud `operations` pattern).** The CLI
*requests* the job; the **ledger** runs it and tracks it; the CLI polls. Nothing
heavy blocks the terminal, and every job has a durable handle and an audit trail:

```
baseproof ledger maintenance {enable, disable, status}    # toggle SOFT maintenance (reject admissions, keep reads)
baseproof ledger reindex                                  # → returns an operation id (online-safe; was backfill-node-index)
baseproof ledger prune  --before <date>                   # retention → operation
baseproof ledger compact-tiles                            # cold-storage migration → operation
baseproof ledger operations  {list, describe, wait, cancel}
```

**Plane 4 — hard maintenance / cold DR (NOT client commands).** When the ledger is
*down* (Postgres wiped, tile format change) there is no API to call, so these stay
ops binaries you run as one-shot Jobs with the ledger **stopped**:

```
rebuild-projection      # Postgres ← tiles      (DR; ledger stopped)
rebuild-tiles           # Tessera  ← Postgres   (DR / leaf-scheme migration; ledger stopped)
```

Every Plane-1/2 command keeps the established shape: logic in `libs/cli`
`RunX(ctx, args)` → thin Cobra wrapper in the `cli` repo → exercised by
`tooling/e2e`. Identical to how `submit` / `load` already work. Plane-3 verbs are
thin clients over the ledger admin API; Plane-4 binaries are unchanged.

## Operational classes at a 15-year horizon

Imagine this network at year 15: billions of entries, terabytes of tiles, an SMT
and a Postgres projection far too large to rebuild casually. The question that
matters is no longer "is it a CLI?" but **"can this run while the log is live, and
who is allowed to run it?"** Three things decide it: *online-safe* (can the builder
keep admitting?), *blocking* (does it hold the single-writer / corrupt reads
mid-run?), and *authority* (anyone / operator / key-holder).

| Operation | Who | Online-safe | Blocking | Class → surface |
|---|---|---|---|---|
| submit · proof · verify · info · witnesses · load · `ledger audit` | anyone | yes | no | **routine** → Plane 1 / 2 |
| `admission-authority update` (rotate/enroll/revoke) | G-key holder | yes | no | **admin, light** → Plane 2 |
| `signature-policy update` (incl. PQ-crypto cutover) | G-key holder | yes | no | **admin, light** → Plane 2 |
| `session create` / `revoke` (credits) | operator | yes | no | **admin, light** → Plane 2 (admin API) |
| witness / auditor governance (endpoints, scope) | operator | yes | no | **admin, light** → Plane 2 |
| `reindex` (node index; any index a migration adds over 15y) | operator | **yes** (idempotent, `ON CONFLICT DO NOTHING`) | no (throttle) | **admin, HEAVY** → Plane 3 operation |
| `prune` (retention of gossip/evidence) | operator | yes | no | **admin, heavy** → Plane 3 operation |
| `compact-tiles` (migrate cold tiles to archival storage) | operator | yes | no | **admin, heavy** → Plane 3 operation |
| routine DB migration (additive) | operator | usually | sometimes | **admin** → ledger boot (`LEDGER_DB_MIGRATE_MODE`) |
| **`rebuild-projection`** (schema rebase / Postgres-loss DR) | operator | **NO** | **YES** | **MAINTENANCE** → Plane 4 Job, ledger **stopped** |
| **`rebuild-tiles`** (Tessera rebuild / leaf-scheme migration / DR) | operator | **NO** | **YES** | **MAINTENANCE** → Plane 4 Job, ledger **stopped** |

### What must run in maintenance mode — and why

Two operations are genuinely **heavy + blocking** and must be done with the log
quiesced. At year-15 scale each is an O(entire-history) job measured in hours-to-days:

- **`rebuild-tiles`** replays *every admitted entry* from Postgres into a fresh
  Tessera personality. Mid-rebuild the tree is incomplete, so inclusion proofs are
  invalid, and it is **not idempotent against a running builder** (two writers
  corrupt the tile set). Its own header says *"stop the production ledger first."*
- **`rebuild-projection`** walks the *entire tile set* to repopulate `entry_index`,
  `smt_leaves`, `smt_root_state`, `builder_cursor` — i.e. it rebuilds the very tables
  reads are served from, so reads are inconsistent until it finishes. It is the
  Postgres-loss / schema-rebase DR path.

Both collide with the **single-writer invariant** (the builder loop holds a Postgres
advisory lock). That is exactly why they cannot be live admin endpoints and stay
Plane-4 Jobs.

### Three tiers of maintenance

The dividing line is the **single-writer invariant**: the builder loop holds a
Postgres advisory lock and is the sole writer of tree/tiles/projection. The test
for "must this quiesce?" is mechanical — *needs to BE the writer, or rewrites the
tables the writer/readers depend on* → hard; *read-only or append-idempotent* →
soft/online; *just submits one on-log entry* → fully online.

- **Tier 1 — Hard maintenance (writer stopped); rare, DR-only.** Exactly four
  operations: `rebuild-tiles` (replays every admitted entry into a fresh Tessera;
  not idempotent against a live builder), `rebuild-projection` (rewrites the very
  tables reads are served from), leaf-scheme/tile-format migrations (force a
  `rebuild-tiles`), and schema-rebase DB migrations (force a `rebuild-projection`).
  Run as one-shot Jobs anchored on the **witness-cosigned horizon**, never "now".
- **Tier 2 — Soft maintenance (admissions paused, reads continue).** The ledger
  flips a flag (`baseproof ledger maintenance enable`): `POST /v1/entries` returns
  `503 maintenance`, **GET reads + proofs keep serving**. Heavy *online-safe* work
  runs here, tracked via the operations API: `reindex` (idempotent, `ON CONFLICT DO
  NOTHING`), retention `prune`, tile `compact`/cold-storage migration, checkpoint
  archival, and full re-verification sweeps (e.g. the auditor's authoritative
  rotation log scan). Admissions resume on `disable`; no reads ever go dark.
- **Tier 3 — Online governance (admin key, NO maintenance).** Light, single-entry,
  key-holding: `admission-authority` rotate/enroll/revoke, `signature-policy`
  update, witness-set/auditor rotation, session minting. The **crypto-agility
  cutover** (ECDSA → PQ ML-DSA/SLH-DSA via `--require-hybrid-after`) lives here —
  *staged over wall-clock time* (announce → dual-sign window → flip the floor →
  deprecate), the one governance op that is coordinated rather than instantaneous,
  and it never stops the ledger.

### Why 15-year maintenance is recoverable: bedrock vs cache

- **Bedrock (immutable, durable, async-safe):** the witness-cosigned
  horizon/checkpoints, the tile store (S3/GCS/CDN), the gossip evidence. These
  survive any single component dying.
- **Cache (rebuildable):** the Postgres projection — a CQRS read-model derived
  from bedrock. `rebuild-projection` exists *because* losing it costs a rebuild,
  never evidence. (The auditor's rotation journal carries the same "rebuildable
  cache, not bedrock" contract.)

Three consequences to design around:

1. **Reads stay up during writer maintenance** — `ledger-reader` shares the
   backing store and serves GETs while the writer is stopped. Caveat: during a
   `rebuild-projection`, Postgres-backed reads (queries, `entry_index`) are
   degraded, but tile/proof reads (inclusion, SMT, checkpoints) continue from the
   immutable store.
2. **Maintenance is per-component, never network-wide** — you quiesce *one*
   ledger; peers and auditors keep running and re-verify against the cosigned
   horizon. There is no "stop the network" mode, and the async federation design
   means there can't be one.
3. **Every heavy/DR op anchors on the cosigned horizon, not the live tip** —
   which is exactly why it is safe to run while the rest of the federation moves
   forward asynchronously.

The design rule for the next 15 years: **a heavy or blocking operation is never a
bare verb that blocks a terminal.** It is either a Plane-3 *operation* (online-safe,
polled, audit-trailed) or a Plane-4 *Job* run under hard maintenance — never a casual
command an operator can fire at a live multi-billion-entry log by reflex.

## Migration sequence

1. **Quick wins (no new code).**
   - Delete `tooling/baseproof-cli` (byte-identical duplicate).
   - Delete ledger `submit-stamp` + `backfill` (already covered by `baseproof
     submit` / `load`). Repoint any scripts/e2e/CI references to the `baseproof`
     binary.
2. **`baseproof ledger` namespace (gcloud verbs).**
   - Promote `clienttls` + `retryhttp` to `libs` (or switch the tools to
     `libs/clitools`).
   - Port the SDK-only tools into `libs/cli` `RunLedgerX` seams + Cobra wrappers,
     under the noun → verb model: `admission-authority {describe,update}`,
     `signature-policy {describe,update}`, `audit run`; add `tooling/e2e` coverage.
   - Fold the existing flat commands into resource forms with aliases (`submit` →
     `entries submit`, `show`/`info` → `network describe`, `add` → `network create`).
   - Optionally fold `genesis-ceremony dev` into `baseproof network init`.
3. **Ledger admin API + operations.**
   - Add `POST /v1/admin/sessions` (→ `ledger session …`, replaces `seed-session`).
   - Add the operations API: `POST /v1/admin/operations` + `GET
     /v1/admin/operations/{id}` backing `ledger reindex` (replaces
     `backfill-node-index`), `prune`, `compact-tiles`, and `ledger operations
     {list,describe,wait,cancel}`.
   - Add a soft-maintenance flag + `ledger maintenance {enable,disable,status}`.
   - All behind the existing admin/mTLS auth.
4. **Leave alone:** the five daemons; the Plane-4 cold-DR binaries
   (`rebuild-projection`, `rebuild-tiles` — run under hard maintenance); all Bucket D
   dev/CI tooling.

## Non-goals / risks

- **Not touching offline DR.** `rebuild-projection` / `rebuild-tiles` stay binaries;
  forcing them into a live API would be dishonest about their stop-the-ledger
  contract.
- **LAW 1 is the guardrail.** Any port that accidentally drags in a
  `services/ledger/...` import will fail CI's dependency law — by design. The helper
  promotion in step 2 must land first.
- **Don't import the ledger into the client.** The `cli` repo is technically
  unscanned by the dependency law, but importing the ledger (with its `third_party/
  tessera` submodule) into the universal client is rejected on layering + binary-size
  grounds. Ledger-coupled logic goes behind the service API, never into the client.
- **Reference cleanup.** Deleting `submit-stamp`/`backfill`/`baseproof-cli` requires
  sweeping `Makefile`s, compose files, `e2e`, CI workflows, and docs for invocations.
