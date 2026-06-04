# Design: Collapse the horizon to a single CT checkpoint

Status: **implemented — federation sign-off still required on the finality-semantics change (§5.2 / §10)** ·
Scope: `services/ledger` slice — horizon / checkpoint publication / SMT proof serving ·
SDK pin: `baseproof v1.55.0` ·
Tracking: baseproof/tooling#56

> **Implementation note (landed on this branch).** The single-clock design below
> is now code, not just proposal: `builder/checkpoint_loop.go` (the lagging
> cosign+publish loop), `builder/receipt_ranger.go` (per-checkpoint ReceiptRoot),
> the builder's pre-commit cosign (Steps 6/7) deleted from `builder/loop.go`, and
> the legacy `builder/tile_reconciler.go` + `store/horizon_publisher.go`
> (LatestCosigned-by-`tree_size` + the size gate) removed. Wiring moved to a
> single `CheckpointLoop` in `cmd/ledger/boot/wire`. Validated:
> `builder/checkpoint_loop_test.go` proves *published ⇒ tile-present* even when the
> commit cursor jumps over intermediate roots (the exact 30K failure shape), and
> the embedded-Postgres integration suite (determinism over 1000 entries, the full
> HTTP witness pipeline, real-tree multi-rotation horizons) passes. The
> finality-semantics change in §5.2 (cosign moves off the commit path; the horizon
> lags) is a policy decision and **still needs federation sign-off** — the open
> questions in §10 stand.

> One-line ask: **stop reconciling three independently-advanced position clocks by
> integer `tree_size`, and instead define the horizon as the witness-cosignature
> over the root the tile layer just made durable — produced lagging, like a CT log
> signs its integrated tree, never its tip.**

This RFC asks the federation to approve a semantic change (cosign moves off the
commit hot-path; the published checkpoint *lags* the bleeding edge) **before** any
code lands. The defect section is evidence-only (file:line against the current
`services/ledger` tree); the proposal and impact sections are what need sign-off.

---

## 0. TL;DR

- `GET /v1/smt/proof` over the `tiles` source returns **HTTP 500
  `horizon root unknown (publish/tile-durability gate violated)`** at scale
  (reproduced: 30,000-entry credit-basis run, all 3,000 sampled proofs 500). The
  ledger published a horizon whose `SMTRoot` has **no tile**, so every membership
  proof anchored on it fails to resolve.
- **Root cause is structural, not a one-off bug.** The horizon is selected by
  crossing three independently-maintained position representations
  (Merkle/seq, SMT-commit, tile-durability) **by an integer `tree_size`
  comparison**, while the cosignature binds the **bleeding-edge** SMT root that the
  tile layer has not yet made durable. Any skew between those clocks — and several
  code paths produce skew — publishes a root the tile layer never wrote.
- The current mitigations (the frontier size-gate; the half-built `SizeBoundCosign`
  path) do not close it; one is the seam that leaks, the other deadlocks. A
  "publish by root identity" patch closes *this* leak but keeps the multi-clock
  structure and its next leak.
- **Proposal: one clock.** The authoritative position becomes the *published
  cosigned checkpoint*, produced **only over already-durable data**, lagging the
  commit cursor. Durability is *derived from the tile substrate*
  (`IntegratedSize` / `TilesCoverRoot`), not asserted by a separate mutable
  watermark. The cosigned `SMTRoot` *is* the tiled root, by construction — there is
  nothing left to reconcile, so the drift class is eliminated.
- **Headline impact (needs sign-off): finality semantics change** from
  "committed ⇒ already witness-cosigned" (strict STH on the commit path) to
  "committed ⇒ durable; witness-cosigned ⇒ under the horizon, lagging." This is
  *more* CT-aligned (it matches the SCT-promise / lagging-STH model the ledger
  already issues SCTs for) and **decouples admission from witness liveness**
  (filings keep being accepted when a witness is briefly unreachable).

---

## 1. Background — what the horizon is, and why proofs depend on it

A trust-rooted SMT membership proof must be anchored on a **witness-cosigned**
root; the ledger cannot certify its own state. The read-front anchor is the
**horizon**: the latest published `CosignedTreeHead` (`RootHash` + `SMTRoot` +
`ReceiptRoot` + K-of-N witness signatures), served verbatim at
`GET /v1/tree/horizon` and used as the as-of anchor by
`GET /v1/smt/proof`.

`NewSMTProofHandler` resolves the anchor in priority order
(`services/ledger/api/proofs.go:112-152`): explicit `?smt_root=` → else the
published horizon (`deps.Horizon.ReadHorizon(ctx) → head.SMTRoot`,
`api/proofs.go:132-147`) → else the live committed root. The proof is then
generated **as-of that fixed root** over the configured substrate
(`pg` / `tiles` / `shadow`).

For the `tiles` substrate the proof walk reads nodes from the content-addressed
SMT tile store. The walk is purely structural: it starts at the anchor root and
descends. **If the anchor root's node is not present in the tile store, the very
first read misses and the walk returns `ErrUnknownRoot`.** That maps to HTTP 500
on the horizon-anchored path (the ledger published a head whose own substrate it
cannot serve — `api/proofs.go:170-181`).

---

## 2. The defect — evidence (code only)

### 2.1 Three position clocks, advanced by three actors

The running code maintains **three** representations of "where are we," written by
three different goroutines/processes. They are *supposed* to track 1:1 but are
maintained independently:

| Clock | Durable store | Advanced by | Keyed on |
|---|---|---|---|
| **Merkle / seq** | Tessera log + `tree_heads.tree_size` | **sequencer** `s.tessera.AppendLeaf(hash[:])` assigns the seq (`sequencer/loop.go:320`); the builder samples Tessera's published checkpoint via `Head()` at cosign time | Tessera leaf count |
| **SMT commit** | `smt_root_state.{current_root, committed_through_seq}` | **builder** atomic commit, CAS (`builder/loop.go:965`) | entry seq |
| **Tile durability** | `tile_frontier.{frontier_root, frontier_seq}` | **reconciler**, only after a PUT-ack (`store/tile_frontier.go:60` `AdvanceFrontier`) | committed seq |

The canonical seq↔tree_size conversion is `tree_size = committed_through_seq + 1`
and lives in exactly one place (`store/smt_root_state.go:107-109`).

These are *intended* to align: the sequencer appends the entry's WAL canonical
hash (= `EntryIdentity`), the builder re-appends the same `EntryIdentity`
(`builder/loop.go:669-674`) so Tessera's antispam dedups and returns the same
index, and the committer guarantees **dense, gap-free** seqs via a min-heap
contiguous-prefix drain (`sequencer/committer.go:36-46`, `:426-462`). In the happy
path `Tessera index == entry seq` and all three clocks agree.

"Intended to align" is doing all the work. Each store is written by a different
actor at a different time, and **the publish reconciles them by an integer, not by
identity.**

### 2.2 The drift seam — the publish crosses clocks by `tree_size`

`HorizonPublisher.PublishWithinFrontier` (`store/horizon_publisher.go:62-81`):

```go
head, _ := p.heads.LatestCosigned(ctx, p.quorumK)         // ORDER BY tree_size DESC  → Merkle clock
if head == nil { return nil }
if head.TreeSize > TreeSizeForCommittedSeq(frontierSeq) {  // compare to tile clock, BY INTEGER
    return nil                                             // hold
}
return p.appender.PublishCosignedCheckpoint(ctx, sdkHead)  // publishes head.SMTRoot
```

- `LatestCosigned` returns the **global max `tree_size`** with quorum, and **that
  row's `SMTRoot`** (`store/tree_heads.go:151-161`, `ORDER BY h.tree_size DESC LIMIT 1`).
- The **only** gate is the integer inequality `head.TreeSize ≤ frontierSeq+1`.
- The reconciler passes the publisher **only `frontierSeq`** — never `frontier_root`
  (`builder/tile_reconciler.go:168` and `:195`). The root that was actually made
  durable is read by `ReadFrontier` (`store/tile_frontier.go:37-52`) and **discarded.**

So the published `SMTRoot` is *selected* off the Merkle clock and *gated* off the
tile clock, and **nothing checks `head.SMTRoot == frontier_root`.** Three stores,
crossed by a `uint64` comparison.

### 2.3 The cosignature binds the bleeding edge, not a durable root

The builder cosigns **pre-commit** and binds the **just-computed** SMT root:

- `builder/loop.go:764` (Step 6b): `head.SMTRoot = result.NewRoot` — this batch's new
  root, computed in Step 4, **committed only later** in Step 8.
- `builder/loop.go:837-863` (Step 7): `RequestCosignatures(head)` — a HARD-STALL that
  persists `head` to `tree_heads` and collects the quorum.
- `builder/loop.go:1020-1029`: tile emission + horizon publication are explicitly
  **not** done here — they are owned by the async reconciler.

So `tree_heads` is populated with `(tree_size, SMTRoot)` rows whose `SMTRoot` is
**not durable at the moment it is recorded**; the reconciler may tile it later — or
skip it.

### 2.4 The reconciler makes exactly one root durable per tick

`TileReconciler.ReconcileOnce` (`builder/tile_reconciler.go:148-196`):

- reads the commit cursor `(cSeq, cRoot)` (`:149`);
- `EmitDurable(ctx, fromRoot, cRoot, cSeq)` (`:185`) → `smt.BuildTiles(nodes,
  committedRoot=cRoot, …)` (`store/tile_emitter.go:46`) — tiles **`cRoot` only**;
- `AdvanceFrontier(cSeq, cRoot)` (`:192`);
- `PublishWithinFrontier(cSeq)` (`:195`).

It runs on a ticker (interval `0`→`1s`, `builder/tile_reconciler.go:117-119`,
wired with `0` at `cmd/ledger/boot/wire/wire.go:299`). At the ~487 entries/s
observed in the scale run, the commit cursor advances hundreds–thousands of roots
between ticks. **Every intermediate committed root is skipped and never tiled.**

### 2.5 Why an un-tiled root is a hard 500 — SDK tile mechanics (proven)

Tiles are content-addressed by their **top node's hash**, fixed `TileHeight=8`
(`baseproof@v1.55.0/core/smt/tile.go:45-49`); the tree root is always a tile top.
`TiledNodeStore.Get(hash)` fetches by using the **node hash directly as the tile
ID** (`baseproof@v1.55.0/core/smt/tiled_nodestore.go:162`), so a tile for a given root
exists **iff `BuildTiles(thatRoot)` was called.** The walk's first `Get(root)`
returning nil is exactly `ErrUnknownRoot` (`baseproof@v1.55.0/core/smt/proof_gen.go:199-201`,
`ErrUnknownRoot = "smt: root not found in node store"`). Tiles are written
fsync-durably and **never deleted** (content-addressed, append-only —
`store/smt_tiles.go:217-259`), so "root absent" can only mean "`BuildTiles` was
never called with it."

The proof's tile store and the reconciler's emit store are the **same** object —
both built by `smtTileStore(d.ByteStore, tileDir)` (emit: `wire.go:297`; read:
`wire.go:813`; helper `wire.go:417-422`). So "different store" is ruled out; the
root is genuinely never written.

### 2.6 The skew triggers (any one is sufficient)

Even with dense seqs, `head.SMTRoot ≠ frontier_root` arises from code, not luck:

1. **Cosign races commit.** Step 7 cosign is pre-commit (`loop.go:837`), Step 8
   commit is after (`loop.go:923`). At any instant `LatestCosigned`'s global-max
   `tree_size` is *ahead* of the durable frontier, so the size gate
   (`horizon_publisher.go:73`) holds and the horizon stalls on / falls back to an
   older head whose root the reconciler skipped.
2. **Ghost leaves.** A canonical-hash collision appends a duplicate Tessera leaf
   at `AttemptedSeq` with the canonical row at `ExistingSeq` — "mathematically
   valid in the log, dropped from the projection" (`sequencer/committer.go:567-641`).
   That makes **Merkle `tree_size` > SMT `committed_seq + 1` permanently**, so the
   cosigned head carrying `cRoot` sits *above* `frontierSeq+1` and is excluded by
   the gate; the publisher falls to a lower, never-tiled root.
3. **Reconciler tick granularity.** §2.4 — the 1s tick skips intermediate roots at
   load.

Each is a divergence between two of the three clocks that the integer-size publish
cannot see.

### 2.7 Reproduction

Mode-A credit basis, 30,000 entries, single network, `SCALE_PROOF_SOURCE=tiles`.
Commit completes (`tree_size=30001`, no drops, ~487/s). The light-client audit's
sampled `/v1/smt/proof` calls return **HTTP 500** with ledger log
`smt proof: horizon root unknown (publish/tile-durability gate violated)
root=b6545b03… source=tiles`, persistent over the full audit window. The N=64
smoke did **not** catch it (smoke verifies `/v1/tree/inclusion`, not
`/v1/smt/proof`), which is consistent with the defect being **volume-sensitive**:
at low volume a tick usually lands on the latest committed root and the published
root happens to be tiled.

> Evidence honesty: the *structural* defect above is code-proven. **Which** skew
> (cosign-ahead vs ghost leaf vs tick) produced `b6545b03` in this specific run is
> not yet pinned to a DB row; a confirming query is in §9. The proposed fix removes
> all three regardless of which one fired, so the fix does not depend on that
> attribution.

---

## 3. Why the current/half-built mitigations don't close it

- **The frontier size-gate (`horizon_publisher.go:73`)** is the leak itself: it
  reasons about `tree_size`, but durability is a property of a specific *root*.
  It can hold the bleeding edge yet still publish a *different*, never-tiled root
  ≤ the frontier size.
- **The `SizeBoundCosign` "CT-aligned" path** (`builder/loop.go:98-122, 685-732,
  1145-1232`) is the design *reaching* for CT-correctness — it derives the Merkle
  root deterministically from durable tiles via `RootAtSize`/`IntegratedSize`
  (`tessera/root_at_size.go`, `tessera/embedded_appender.go:564`). But it is
  **off** (never set — `composeBuilderLoop` only sets `BatchSize/PollInterval/
  DeltaWindow`, `wire.go:616-631`) **and incomplete**: Step 6a skips the cosign
  whenever `frontier_seq < myTreeSize` (`loop.go:1183-1197`), which is *always*
  true for the in-flight batch (its root is not tiled yet), and there is no
  at-rest trigger (`processBatch` returns early on an empty dequeue,
  `loop.go:553-555`). Enabled as-is, it would defer the cosign indefinitely and
  freeze the horizon. It also still binds `result.NewRoot` (the bleeding edge).
- **"Publish by root identity" (a minimal patch)** — have the reconciler pass
  `frontier_root` and the publisher select the cosigned head whose `SMTRoot ==
  frontier_root`. This closes *this* leak, but it **keeps three position stores and
  the bleeding-edge cosign**; the multi-clock surface remains and the next skew
  finds the next size-based crossing. Rejected as the authoritative fix (kept as a
  fallback hotfix — §7).

---

## 4. Proposal — one clock: the CT checkpoint

### 4.1 Principle

> The authoritative position is the **published cosigned checkpoint**. It is
> produced **only over data that is already durable**, and it **lags** the commit
> cursor — exactly as a CT log signs a checkpoint over its *integrated* tree, never
> its tip. Durability is **derived from the tile substrate**, not asserted by a
> separate watermark.

The commit cursor, tile emission, and the frontier do not disappear — they become
*bookkeeping in service of producing that one checkpoint*. Crucially, **no second
clock is ever reconciled against the published artifact by integer size.** The
cosigned `SMTRoot` *is* the tiled root, by identity, because the same loop tiles it
and then cosigns it.

### 4.2 The checkpoint loop (replaces the reconciler→publisher seam)

A single loop owns durability → cosign → publish:

```
loop every tick (event-coalesced after commits; idle-sleep otherwise):
  (cSeq, cRoot) ← commitCursor.Read()                      # bleeding edge (smt_root_state)
  if cRoot == lastPublishedRoot: continue                  # nothing new

  # 1) make this root's substrate durable (Merkle tiles already integrated;
  #    SMT tiles emitted + PUT-ack + fsync). Idempotent, content-addressed,
  #    incremental (BuildDirtyTiles over lastDurableRoot→cRoot).
  emitDurable(cRoot)                                        # returns only on PUT-ack
  frontier.Advance(cSeq, cRoot)                             # durable resume cursor

  # 2) build the head AT the durable root — no tree_size selection
  head := TreeHead{
      TreeSize: cSeq + 1,
      RootHash: merkle.RootAtSize(cSeq+1),                  # deterministic from durable tiles
      SMTRoot:  cRoot,                                       # the root we JUST tiled
      ReceiptRoot: receiptRootAt(cSeq+1),
  }

  # 3) cosign + publish that exact head
  cosigned := witness.RequestCosignatures(head)             # K-of-N over the durable head
  appender.PublishCosignedCheckpoint(cosigned)              # horizon := this
  lastPublishedRoot = cRoot
```

Properties, by construction:

- **published ⇒ durable.** `emitDurable(cRoot)` returns only on PUT-ack, *before*
  the cosign, and we cosign **`cRoot`** — the exact root tiled. A proof anchored on
  the horizon always resolves.
- **No integer crossing.** There is no `LatestCosigned`-by-`tree_size`, no
  `head.TreeSize > frontierSeq+1` gate, no discarded `frontier_root`. The single
  comparison left is the identity `cRoot == lastPublishedRoot` (skip-if-unchanged).
- **Lagging, melt-proof.** Witnesses gate only the *checkpoint*, not ingestion.
  A witness outage freezes the horizon; commits and tiles continue.

### 4.3 What is deleted / changed

- **Delete from the builder hot path:** Step 6b/6c/7 — the bleeding-edge
  `head.SMTRoot = result.NewRoot` bind and the pre-commit `RequestCosignatures`
  HARD-STALL (`loop.go:740-866`). The builder's contract shrinks to: admit → commit
  SMT + advance cursor (Steps 1-5, 8). The witness wiring moves to the checkpoint
  loop.
- **Delete from the publisher:** `LatestCosigned`-by-`tree_size` selection and the
  `tree_size` gate (`horizon_publisher.go:60-81`). Publication becomes "publish the
  head we just cosigned."
- **Keep:** `tile_frontier` (now the checkpoint loop's *durable resume cursor*, not
  a clock the publish crosses); `tree_heads`/`tree_head_sigs` (the append-only
  cosign audit record + peer-witness sync target); `RootAtSize`/`IntegratedSize`
  (now the *primary* Merkle-root source, as intended).
- **Repurpose:** the existing `SizeBoundCosign` primitives become the default and
  only path — but cosigning the **frontier** (durable) size, not the in-flight one,
  which is what makes them actually terminate.

### 4.4 Durability derived from the substrate (kill the lying watermark)

`emitDurable` + the published checkpoint must reflect *actual* tile presence, not a
watermark that a crash can desynchronize (issue #189). The oracle already exists:
`TilesCoverRoot(ctx, tiles, cache, root)` (`store/smt_tiles.go:128-140`) Gets the
root node from the tile store and reports presence. The checkpoint loop consults it
(or relies on `EmitDurable`'s PUT-ack + the POSIX/S3 fsync contract,
`store/smt_tiles.go:217-259`) so the frontier never *claims* durability the
substrate can't back.

---

## 5. Impact assessment

### 5.1 Correctness / safety — strictly improved

- The proof-serving 500 class is **eliminated by construction**: the only root
  ever published is one whose tiles were PUT-ack'd in the same loop iteration.
- Removes the entire family of "Merkle vs SMT vs frontier" skew bugs (§2.6),
  including ghost-leaf and cosign-race induced drift, without having to enumerate
  them.
- No new trust assumption: the published checkpoint is still a K-of-N
  witness-cosigned head over `(RootHash, SMTRoot, ReceiptRoot, TreeSize)`; the
  light-client verification path is unchanged.

### 5.2 Finality semantics — the change that needs sign-off

| | Today (strict STH on commit) | Proposed (CT-lagging checkpoint) |
|---|---|---|
| On `202`/SCT | promise of inclusion | promise of inclusion *(unchanged)* |
| Commit | SMT state advances **only after** a quorum cosign of a covering head (`loop.go:218-225` finality stall) | SMT state advances on durable commit; **no cosign on the path** |
| Witness-cosigned | true at commit time | true **under the horizon**, lagging by ≤ the checkpoint cadence |
| Witnesses unreachable | builder stalls → `MaxBuilderLag` → admission **503** | commits + tiles continue; **horizon freezes**; admission unaffected (until an optional horizon-lag gate, §5.3) |

This is **more** CT-aligned, not less: the ledger already issues SCTs
(`api/sct.go`) — a *promise* of future inclusion within a merge delay — which is
precisely the CT contract where the signed checkpoint lags. "Strict STH on commit"
is *stronger* than CT requires and is exactly what couples admission to witness
liveness. For a court network the practical question is: **is "durable + tamper-
evident but not-yet-cosigned for a bounded lag" an acceptable state for an accepted
filing?** We argue yes (the entry is in the append-only log and durable; external
finality lags), but **this is the federation's call and the reason this is an RFC.**

### 5.3 Liveness / melt-proofing

- **Admission decouples from witness availability** — a strict improvement for a
  bursty court network (filings accepted through a transient witness blip).
- The melt-proof bound shifts from "witness reachable" to "**tiles durable**": the
  existing tile-frontier max-lag gate (`LEDGER_SMT_MAX_TILE_LAG`, default 100,000 —
  `wire.go:424-431`, `loop.go:521-529`) already 503s admission if durability falls
  too far behind. We **add** an optional *horizon*-lag gate (commit cursor −
  published horizon) so an operator can still bound how far un-cosigned-but-durable
  state may run if their policy requires it. Off by default (pure CT); configurable.

### 5.4 Performance & scale (100 → 30K → 8–10M/day, batch cap 1024)

| Daily volume | Commit path | Checkpoint loop | Verdict |
|---|---|---|---|
| 100–300/day | idle-poll, tiny batches | event-coalesced cosign per commit; trivial | fine; now *provably* correct (today it's correct only by luck) |
| ~30K burst | ~30 batches @ ~487/s | cosign lags, catches up at rest; horizon converges to `cRoot` | the reproduced 500 disappears |
| 8–10M/day (~115/s avg, multi-k/s peaks) | batch ≤1024 bounds tail/tx/vacuum (`loop.go:125-137`); peaks → 503 backpressure, never corruption | **must** use incremental `BuildDirtyTiles` (delta-cost) — the current `BuildTilesEmitter` does a **full** `BuildTiles(cRoot)` O(tree) walk per cycle (`tile_emitter.go:42-66`), which is an O(10M)/cycle CPU sink at this scale | correct at any volume; the incremental-tiles work is the real 10M dependency |

Key property: **correctness becomes volume-invariant.** Today, published-horizon
validity is *inversely* coupled to load (more entries/tick ⇒ more skipped roots ⇒
higher 500 probability). After the change, volume only changes *how far the horizon
lags*, never whether it is provable. Do **not** raise the 1024 batch cap to chase
throughput — it is the melt-proof bound; add cycles, not batch width.

### 5.5 Storage / GC

- No change to tile content-addressing or immutability. The checkpoint loop tiles
  each *published* root; with `BuildDirtyTiles` the incremental tile set per root is
  ∝ changed paths. A historical-root GC policy (which past checkpoints' tiles to
  retain) is **out of scope** here and unchanged by this RFC.

### 5.6 Failure modes & recovery

- **Crash mid-loop:** the durable `tile_frontier` is the resume cursor; on boot the
  loop re-derives the gap to `cRoot` and re-emits (idempotent, content-addressed),
  then cosigns + publishes. A crash between advance and publish self-heals (next
  iteration republishes at the frontier root).
- **Blob-store outage:** `emitDurable` errors → loop holds → horizon freezes →
  commits continue (melt-proof). No partial/forged horizon.
- **Witness outage:** cosign fails → loop holds → horizon freezes → commits + tiles
  continue. Recovers when witnesses return.
- **#189 lying watermark:** closed by deriving durability from the substrate
  (`TilesCoverRoot`) + fsync Put (`smt_tiles.go:217-259`), not a bare watermark.

### 5.7 API / consumer compatibility

- `GET /v1/tree/horizon`, `GET /v1/smt/proof`, `GET /v1/smt/proof?smt_root=…`:
  **unchanged shapes**; `/v1/smt/proof` simply stops 500-ing on the tiles source.
- `GET /v1/tree/head` (latest cosigned) will now **lag** `GET /v1/smt/root` (live
  committed) by the checkpoint cadence. Today they coincide under strict finality.
  Consumers that (incorrectly) treated `/v1/smt/root` as trust-rooted are already
  warned it carries no witness binding (`api/proofs.go:349-362`); the correct
  trust-rooted reads (`/v1/tree/head`, `/v1/tree/horizon`) remain trust-rooted and
  converge to "latest durable cosigned."
- **Integrity / equivocation detector must become frontier-aware.** It compares the
  cosigned head's `SMTRoot` against the committed root; under a lagging horizon a
  naive *latest-vs-latest* comparison false-positives. It must compare *at the same
  size* (`GetBySize`) — the `smt_root_state.go:38-41` comment already documents this
  exact `+1`/size-alignment hazard. **This is a required companion change**, not
  optional.

### 5.8 Observability

New/locked metrics for the cutover and for SRE: `checkpoint_lag_entries`
(commit cursor − published horizon), `checkpoint_cosign_seconds`,
`tile_emit_seconds` + `tiles_put_total`, `horizon_publish_total`,
`checkpoint_holds_total{reason=blob|witness}`. The reproduced failure should be a
**named alert** (proof 500 on the tiles source) that this change drives to zero.

### 5.9 Security

- No new external surface; witnesses still gate the checkpoint and the binding is
  the same canonical payload. The *only* shift is *when* the cosign happens
  (lagging, off the commit path). Equivocation detection is **preserved** (and made
  correct under lag, §5.7). A malicious read-path swap of the horizon is still
  defeated by out-of-band K-of-N verification — unchanged.

### 5.10 Migration / rollout (flagged, evidence-gated)

1. **Companion fixes first** (no behavior change): frontier-aware integrity
   detector; `BuildDirtyTiles` incremental emitter wired behind the existing
   interface.
2. **Checkpoint loop behind a flag** (`LEDGER_CHECKPOINT_MODE=lagging`),
   default off. In shadow it runs alongside today's path and logs
   `would-publish(root)` vs `did-publish(root)` to prove the lagging root is always
   tile-present while the legacy root is not.
3. **Cutover** gated on the 30K + (scaled) 8–10M validation in §9 going green on
   `SCALE_PROOF_SOURCE=tiles`.
4. **Remove** the legacy pre-commit cosign + size-gate publisher after one release
   of soak.

### 5.11 Blast radius / what could go wrong

- **Biggest risk:** the finality-semantics change is user-visible policy, not just
  an internal refactor — hence this RFC. If the federation requires
  cosign-before-acknowledge for some entry classes, we keep a per-class
  synchronous-cosign option (admission waits for the horizon to cover the entry)
  layered on top of the single-clock core.
- **Detector false-positives** if §5.7 lands late — sequencing matters; the
  detector change ships *before* the loop flips on.
- **10M without `BuildDirtyTiles`** would move the CPU sink, not remove it — the
  incremental emitter is a hard dependency for that regime, not a nice-to-have.

---

## 6. Invariants (what we assert after the change)

1. **Published ⇒ durable:** every byte the horizon advertises (`RootHash`,
   `SMTRoot`) is backed by tiles that were PUT-ack'd before the cosign of that head.
2. **Published ⇒ witnessed:** the horizon is a K-of-N cosigned head (unchanged).
3. **Single authoritative position:** the horizon is the *only* artifact consumers
   anchor on; no other clock is reconciled against it by integer size.
4. **Monotone:** the horizon's `tree_size` and the durable frontier are
   non-decreasing; a crash never regresses or forks them.
5. **Lag is bounded and observable:** `commit − horizon` is a metric and may be
   gated by policy, but never affects correctness.

---

## 7. Alternatives considered

| Alternative | Why not (or: kept as) |
|---|---|
| **Publish by `frontier_root` identity** (minimal patch) | Closes the current leak but keeps three clocks + bleeding-edge cosign; next skew leaks again. **Kept as an emergency hotfix** if the federation needs the 500 gone *before* the semantic discussion concludes. |
| **Complete `SizeBoundCosign` as-is** | Still binds the bleeding edge and gates the cosign on `frontier ≥ in-flight size`, which deadlocks (§3). Its primitives are reused; its control flow is not. |
| **Keep strict-STH, make the reconciler tile every intermediate cosigned root** | Re-tiles O(commits) roots/sec — unbounded write amplification; doesn't address the cosign-race or ghost-leaf skews; entrenches three clocks. |
| **Raise batch size / speed the reconciler tick** | Narrows the window, never closes it; abandons the melt-proof batch bound. |

---

## 8. Test & validation plan (cutover gates)

- **Unit:** checkpoint loop publishes `cosign(cRoot)` and *only* after
  `EmitDurable(cRoot)` returns; a forced blob error holds without publishing; a
  forced witness error holds without publishing; crash/restart resumes from the
  durable frontier and republishes the same root.
- **Property:** drive N commits past K reconcile ticks; assert
  `GET /v1/smt/proof` over `tiles` is `200` for every committed key for the *entire*
  run (not just at rest), and the horizon root is always tile-present.
- **Scale gate (must be green to cut over):** the 30K credit-basis run with
  `SCALE_PROOF_SOURCE=tiles`; then a scaled run toward the 8–10M/day envelope with
  `BuildDirtyTiles` enabled, watching `checkpoint_lag_entries` and
  `tile_emit_seconds`.
- **Regression:** the named "proof 500 on tiles" alert stays at zero across a
  witness-outage and a blob-outage chaos injection.

---

## 9. Confirming the specific 30K trigger (parallel to sign-off; not blocking)

Run against the scale stack's Postgres to attribute `b6545b03`:

```sql
-- published horizon root: cosigned at what tree_size?
SELECT tree_size, encode(smt_root,'hex') FROM tree_heads
 WHERE smt_root = decode('b6545b03b9ad48d7757bcc57a6195c80098cec841f11cbd0329d35c947afa9de','hex');
-- the durable root vs the committed root
SELECT frontier_seq, encode(frontier_root,'hex') FROM tile_frontier WHERE id=1;
SELECT committed_through_seq, encode(current_root,'hex') FROM smt_root_state WHERE id=1;
-- is Merkle ahead of SMT? (ghost-leaf skew)  -- compare Tessera size to committed_through_seq+1
```

Expected under the §2 thesis: `frontier_root ≠ b6545b03`, and either
`b6545b03`'s `tree_size` < `frontier_seq+1` (skipped intermediate) or Tessera size
> `committed_through_seq+1` (ghost-leaf skew). The proposed design fixes all of
these; this query only attributes which one fired.

---

## 10. Open questions for federation sign-off

1. **Finality (§5.2):** is "accepted ⇒ durable + tamper-evident, witness-cosigned
   under a bounded lag" acceptable for all entry classes, or do specific classes
   (e.g. seals, certain judicial dispositions) require synchronous cosign-before-ack
   (the per-class option in §5.11)?
2. **Horizon-lag gate (§5.3):** off (pure CT) by default, or do we ship a default
   max horizon lag for admission backpressure?
3. **Detector ownership (§5.7):** confirm the frontier-aware integrity-detector
   change ships in the same series and *before* the loop flips on.
4. **10M dependency (§5.4):** approve `BuildDirtyTiles` as a hard prerequisite for
   the high-volume regime in the same program.

---

## Appendix A — evidence index (current `services/ledger`, `baseproof v1.55.0`)

- Publish seam: `store/horizon_publisher.go:62-81`; `store/tree_heads.go:151-161`;
  `store/smt_root_state.go:107-109`.
- Reconciler: `builder/tile_reconciler.go:148-196`; emit `store/tile_emitter.go:42-66`;
  frontier `store/tile_frontier.go:37-71`.
- Bleeding-edge cosign: `builder/loop.go:764, 837-863, 1020-1029`; resolveCosignHead
  / SizeBoundCosign `builder/loop.go:1145-1232`; flag unset `cmd/.../wire.go:616-631`.
- Serve path: `api/proofs.go:112-152, 170-181`; `api/horizon.go:75-91`.
- SDK tile/proof mechanics: `baseproof@v1.55.0/core/smt/tiled_nodestore.go:141-192`;
  `…/proof_gen.go:177-203`; `…/tile.go:45-49`.
- Clocks/assignment: sequencer append `sequencer/loop.go:320`; builder re-append
  `builder/loop.go:669-674`; gap-free committer `sequencer/committer.go:36-46, 426-462`;
  ghost leaves `sequencer/committer.go:567-641`.
- CT-aligned primitives: `tessera/root_at_size.go`; `tessera/embedded_appender.go:564`;
  `tessera/proof_adapter.go:108-115`.
- Same emit/read tile store: `cmd/.../wire.go:297` vs `:813`, helper `:417-422`.
