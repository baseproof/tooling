# Design: Scale & Forking — Ledger slice

Status: **proposed (program, post-1.17)** · Scope: `ledger` slice ·
Companion: `baseproof/docs/design/scale-and-forking.md` (SDK slice) ·
Tracking: clearcompass-ai/ledger#115 ↔ clearcompass-ai/baseproof#48

This is the **ledger half** of the scale & forking program — where most of the
work lands. The SDK half (primitives + vocabulary) is the companion doc above.
The two docs share one layer-split table (below).

---

## Scope boundary — READ FIRST

**Tracks A/B/C are NOT part of SDK v1.17.0.** v1.17.0 ships exactly one SDK
**seam** — `core/smt.GenerateProofAt(nodes NodeStore, root, key)` — which Track
**A3** consumes. Nothing in A/B/C is in v1.17.0; even Track A's other items
(A1 cache, A2 single-writer) are ledger storage changes with their own benchmark
gates. This program begins after the v1.16.0 adoption bump
(`baseproof v1.15.0 → v1.16.0`, then `→ v1.17.0`) and is its own benchmark-gated
PR series.

**Intra-log sharding is deferred from the entire program** (last section).

Targets: **1K+ TPS sustained / 5K spikes · 10B+ entries · 15 networks × 50
exchanges · forking.** Horizontal-first; the commit hot-path (Ledger P5/P7/P9)
must not regress.

**The key insight for 1K+ TPS:** depth (10B in one log), breadth (many logs),
and forking are different problems with different blast radii. **Most of the
scale you need is horizontal and never touches the per-log hot-path.**

---

## Layer-split table (shared with the SDK doc)

| Concern | baseproof (SDK) owns | ledger owns |
|---|---|---|
| Historical SMT proof | `GenerateProofAt(NodeStore,…)` primitive (v1.17.0); tile-backed `NodeStore` reader (later) | **as-of proof endpoints; SMT tile-publishing; GC invariant** |
| SMT node cache | — (agnostic) | **real LRU, hot-set sizing (A1)** |
| Trust federation | `LogTrustProvider`/`MultiLog` vocabulary + HTTP-provider wire contract; re-verify (A6) | **implement endpoints; consume `MultiLog`; ledger-backed provider** |
| Multi-tenancy | — (agnostic) | **control plane, one-log-per-process, per-network routing** |
| Peer/anchor topology | anchor verify primitives (exist) | **registry + discovery + relays** |
| Forking | genesis-from-anchor; witness-set-handoff vocabulary | **consume bootstrap; handoff; cross-fork resolution** |
| Intra-log sharding (**DEFERRED**) | 2-level SMT composition primitive | range-sharded tables + per-shard builder |

---

## Track A — Depth: 10B entries at 1K+ TPS, per network (vertical, single-writer)

| # | Change | Evidence | 1K-TPS impact |
|---|---|---|---|
| A1 | Replace the in-process SMT node cache (1M nodes, **O(N·log N) full-sort eviction**) with a real LRU sized for the hot upper levels (`hashicorp/golang-lru` already in go.sum) | `store/smt_state.go:277,527` | **The actual hot-path bottleneck.** The builder's dirty-root recompute reads ~33 nodes/leaf; a thrashing cache forces cold single-row PG reads on the commit path. Highest-priority, cheapest win. |
| A2 | Keep single-writer per log (the global advisory lock is **correct** per-log) — do not shard intra-log yet (deferred) | `store/postgres.go:216`; helm `replicas:1`/`Recreate` | Single-writer at 1K TPS is fine once A1 lands; the builder is batched. |
| A3 | Tile-publish SMT nodes to the object store (the dense log already is) so historical proofs + auditor recompute are CDN-served, not Postgres; add **as-of proof endpoints** (`?tree_size=N`/`?smt_root=hex` on `/v1/smt/proof`, `/v1/smt/leaf`, `/v1/tree/inclusion`) + a **witness-set endpoint**, consuming SDK `GenerateProofAt` | `store/migrations/0003`; P10/P15 | Moves historical-proof read fan-out **off** the ledger CPU — directly serves the melt-proof mandate at 10B. Pairs with v1.17.0's `GenerateProofAt`. |

**GC invariant (write it down now):** any future SMT-node GC MUST be
mark-and-sweep rooted at **all** retained cosigned heads, and **never**
time-based — else historical proof serving silently breaks
(`store/smt_state.go:40-44`; nodes are content-addressed and currently immortal).

**Gate:** sustained 1K TPS + 5K spike at 1B then 10B node counts; p99 commit
latency, builder lag, cache hit-rate.

---

## Track B — Breadth: 15 networks / 50 exchanges (horizontal, control plane — off the hot-path)

| # | Change | Evidence | Note |
|---|---|---|---|
| B1 | Keep **one log = one process = one DB** (it already scales horizontally by adding logs). Do **not** multi-tenant a single process — that reintroduces cross-tenant lock contention and breaks P9 (per-originator parallelism). | `cmd/ledger/config.go:406,456`; `store/entries.go:600` hard-binds one logDID | The clean scalable model is **more processes**, not a fatter one. |
| B2 | Control plane: per-network config/DSN/LogDID routing + deployment templating | `deploy/` | Pure ops; zero hot-path. |
| B3 | **Peer/anchor registry + discovery** to replace the static CSV mesh | `gossipnet/wiring.go:379-398`; `config.go:118` static `AnchorSources` | 50 exchanges = unmanageable as hand-edited env CSV. |
| B4 | Gossip relays/hub to avoid an O(N²) mesh | pull-based + CDN already help (A11/P11) | Gossip is async transparency — stays off the commit clock (P12). |
| B5 | The deferred HTTP-backed `LogTrustProvider` + `MultiLog` federation (each network verifies the others) | v1.16.0 `MultiLog`/`ForeignLogFromAnchor` | Lands **here**, after the ledger's as-of endpoints exist. Must re-verify, never trust the API (A6). |

**1K-TPS note:** this entire track is deployment/topology. Each log keeps its
melt-proof guarantees untouched.

---

## Track C — Forking (protocol/SDK + ledger; control-plane, off the hot-path)

| # | Change | Evidence |
|---|---|---|
| C1 | Consume the SDK **genesis-from-anchor** primitive: bootstrap a new child `LogDID` from a parent's verified cosigned head | composes existing `anchor.{ForeignLogFromAnchor, BuildCosignedAnchorEntry}` |
| C2 | Witness-set handoff across fork legs | `types/witness_rotation.go`, A3 topology rotation |
| C3 | Dynamic parent↔child / peer topology registry (overlaps B3) | none today — `api/submission.go:524` is "cross-log hard-no, async reconcile" |
| C4 | Ledger consumes a `MultiLog`/`LogTrustProvider` for cross-fork authority (today `delegationresolver/` is single-log) | `delegationresolver/ledger_source.go` |

**1K-TPS note:** forking is bootstrap/control-plane. Cross-log admission stays
"hard no, async reconcile" — the commit path never blocks on a foreign log. This
is exactly what keeps forking compatible with 1K+ TPS.

---

## Deferred — intra-log sharding (do NOT over-engineer)

Parallel builders / a **2-level sharded SMT** (shard sub-roots → super-root) is
the genuinely hard distributed-systems problem, and **you don't need it for 1K+
TPS at 10B.** A single network at 1K TPS is single-writer-bounded by the SMT
dirty-root recompute, which **Track A1 (cache fix)** resolves; 10B is reachable
vertically. Intra-log sharding is required only if **one** network must sustain
throughput beyond a single writer (e.g. a 5K-TPS single jurisdiction). On the
ledger side this means range-sharding `jellyfish_nodes`/`smt_leaves`/`entry_index`
+ a per-shard builder lock (replacing the single global `BuilderLockID`,
`store/postgres.go:216`) + the SDK's 2-level SMT. Named here as the future
escape hatch; build it only when a network proves it needs it. Building it
speculatively would be the opposite of a clean scalable solution.

---

## PR series order (each `-race` + benchmark gated, Ledger P15)

`go.mod → v1.16.0` (adoption) → `→ v1.17.0` → **A1 (cache)** → **A3 (SMT tiles +
as-of endpoints)** → **B (control plane / registry / MultiLog)** → **C (fork
primitives)**. Each PR is complete and benchmark-proven; none rides another.

**Gates:** sustained 1K TPS + 5K spike at 1B then 10B node counts — p99 commit
latency, builder lag, cache hit-rate, and proof that historical-proof reads stay
off the ledger CPU (A3 served from tiles/CDN).
