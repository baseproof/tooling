# Design: Recoverability Foundations — Operational Gaps Before Bounding Postgres

Status: **proposed** · Scope: `ledger` (`tooling/services/ledger`) + JN e2e ·
Companion: `baseproof/tooling#29` (EPIC: PG as a bounded, recoverable cache) ·
Tracing convention: `ledger/…` = `tooling/services/ledger/…`; `baseproof/…` = SDK.

> **TL;DR** — The cold-serve / object-store-as-system-of-record machinery is built
> and unit-tested, but a code-traced review surfaced **four operational gaps** that
> sit *between* "the library is correct" and "an operator can rely on it." Until
> these close, **Postgres cannot be safely bounded** (rows evicted) for any real
> network: pre-existing history has no runnable backfill (G1), the cold path is never
> proven end-to-end with PG actually down (G2), one archive writer is fail-open while
> its sibling is fail-closed (G3), and the receipt-archive docs contradict the code
> (G4). Every claim below is traced to a file:line against the current branch.

---

## Why this exists (the precondition chain)

Bounding PG (the #29 EPIC) is only safe if **every byte evicted from PG is already
reconstructable from the object store**. That holds *forward* — the live writer ships
log tiles, archives the per-size checkpoint + size index, archives receipt
commitments, and (fail-closed) withholds the horizon until those are durable. But the
guarantee has holes at the edges:

1. **Backwards (pre-feature history):** archives are forward-only. A log with entries
   older than the archive code has **no cold form in S3** for those entries. The job
   that fixes this exists but **cannot be invoked**. → **G1**
2. **End-to-end proof:** "PG down ⇒ cold seq still verifies" is asserted nowhere on a
   live stack. → **G2**
3. **Durability symmetry:** the POSIX per-size checkpoint archive is fail-open; the S3
   one is fail-closed. A cold reader served by the fail-open path can see a horizon
   ahead of durable cold data. → **G3**
4. **Doc/code drift:** the receipt archive is fail-closed in code but documented as
   best-effort — an invitation to regress the guarantee G1–G3 depend on. → **G4**

The eviction work (#29 Phase 2) must not start until G1–G4 are closed.

---

## G1 — `ArchiveBackfillJob` has no entrypoint *(the #1 gap)*

### Evidence (traced)
- The job is fully implemented and unit-tested: `ledger/store/archive_backfill.go`
  defines `ArchiveBackfillJob`, `NewArchiveBackfillFromStores(...)`, and `Run(ctx)` —
  it walks the cosigned ladder (`CosignedSizeAtOrAbove`), is idempotent, and recovers
  witness signatures from PG `tree_heads` (`HeadToSDK`). Correct for a DR/operator job.
- **No caller exists.** `grep -rn 'ArchiveBackfillJob|NewArchiveBackfillFromStores'
  --include=*.go` (minus tests) returns **only `store/archive_backfill.go`** — no
  `cmd/` wrapper, no boot hook in `cmd/ledger/boot/wire/wire.go`.
- `cmd/backfill/main.go` is an unrelated **load generator** ("generates VALID,
  INTERCONNECTED entries that … populate the … SMT indexes"), not an archive job.

### Why it matters
Every archive is **forward-only**: receipts (`store/receipt_archive_writer.go`), the
per-size checkpoint + size index (`store/horizon_s3.go`), and the rotation index are
written *as new checkpoints publish*. A network that accumulated history **before**
this code shipped has those entries' tiles in S3 (the shipper backfills tiles) but
**no archived receipts, no per-size checkpoint, no size-index entries** for the old
range. The `ArchiveBackfillJob` is precisely the tool to regenerate them from PG
(`tree_heads` + `entry_index.web3_receipts`) into S3. With no entrypoint, an operator
**cannot run it**, so the cold form for pre-feature history never exists — and the
moment PG is bounded below that range, those entries' receipt proofs and
covering-checkpoint lookups **fail**. This blocks bounding PG for every non-greenfield
log, which is all of them in production.

### Fix
Respect the CLI-deletion rule — logic in a library, triggered by a service hook, not a
new `cmd/`:
1. **Library:** add `recovery.ArchiveBackfill(ctx, deps)` (lands beside the just-extracted
   `recovery.Rebuild`) wrapping `NewArchiveBackfillFromStores(...).Run(ctx)`.
2. **Trigger:** an **env-gated one-shot boot hook** in `wire.go` —
   `LEDGER_ARCHIVE_BACKFILL_ON_BOOT=1` runs it once (the stores it needs —
   `TreeHeadStore`, `S3CheckpointPublisher`, `ReceiptArchiveWriter`, the rotation
   archiver — are already wired) before the server serves, then the operator clears the
   flag. The future single CLI calls the same `recovery.ArchiveBackfill`.

### Acceptance
- Integration: build a log of N entries; **delete the forward archives** (receipts/,
  checkpoints/, checkpoint-index/) to simulate pre-feature history; run
  `ArchiveBackfill`; assert a **PG-off reader serves a full v2 proof for the OLDEST
  seq** (receipt + covering checkpoint resolve from S3). Re-run → idempotent (no
  duplicate objects, same result).
- This is the missing half of `federation.dr`: not just "PG rebuilds," but "the cold
  archives a bounded PG depends on can be (re)generated for history that predates them."

---

## G2 — no end-to-end PG-stopped cold proof

### Evidence (traced)
- `e2e/runner/proof_pgoff.go`: the **writer's PG stays up**; only the *reader* points at
  a dead-host DSN; it proves `st.Leaves[0]` (a **recent** seq); skips if no reader port.
- `e2e/runner/proof_cold.go:24,46`: cold-seq coverage runs `backfillDrained(t,…)` +
  `proveEntry(ctx, name, t, coldKey)` where **`t` is the writer** (PG-backed), not the
  reader.
- `e2e/runner/dr.go`: Wait → `WipeLedgerProjection` → `UpRebuildJob` → assert
  `RebuiltProjectionState` (count==tree_size, smt_root==cosigned). **No `proveEntry`
  after the wipe, no read-availability check, no RTO/RPO.**
- `e2e/runner/shadow.go`: proves writer + reader and checks distinct `smt_root`; **never
  diffs the two proofs**; the real PG-vs-tiles compare is in-ledger only under
  `LEDGER_SMT_PROOF_SOURCE=shadow` (`store/smt_tiles.go:54,73`), and the e2e runs
  `proof=tiles`, so it is neither computed nor asserted.

### Why it matters
The cold path is **"correct by construction"** — each piece is unit-tested and the v2
assembly is SDK-tested in-memory — but **nothing stops Postgres and mints+verifies a
full cold-seq v2 proof through the real S3 archive readers on a live stack**. #29 §8
makes exactly this the rollout gate for eviction; today it is unproven.

### Fix (JN e2e recipes)
- `federation.proof.pgoff.cold` — stop the **writer's** Postgres, advance the horizon
  past an early entry (so it is genuinely cold), then mint+verify that early entry
  against the **PG-off reader** through the real archive readers.
- `federation.dr.serve` — assert the reader keeps answering `/v1/tree/horizon` + a cold
  proof **while** PG is down and `rebuild-projection` runs; record rebuild time (RTO).
- *(optional)* `verify.shadow.zero` — bring a writer up with
  `LEDGER_SMT_PROOF_SOURCE=shadow`, scrape the `smt proof shadow mismatch` signal, assert
  it stays 0 over a soak.

### Acceptance
All three pass on the `federation` stack; `proof.pgoff.cold` fails if PG is *not*
actually stopped (guard against a false-green that secretly used PG).

---

## G3 — fail-posture asymmetry (POSIX fail-open vs S3 fail-closed)

### Evidence (traced)
- **POSIX is fail-open.** `ledger/tessera/embedded_appender.go:640-655`
  (`publishCheckpoint`): the horizon is written first (load-bearing); the per-size
  archive is *"Best-effort: never fail the publish on the archive"* — a failure is
  logged and **swallowed, horizon advances**. Pinned by
  `tessera/checkpoint_archive_test.go:118` ("publish must SUCCEED despite a failed
  archive write").
- **S3 is fail-closed.** `ledger/store/horizon_s3.go` (`PublishCosignedCheckpoint`):
  per-size archive + size index are written **before** the horizon and a failure is
  returned (the horizon never advances past non-durable cold data).
- **Rotation index — fail-open, but a DIFFERENT structural class:**
  `ledger/witnessclient/rotation_handler.go:364-371` (Step 6) refreshes the
  witness-rotation index best-effort. Unlike the checkpoint archive it CANNOT be
  fail-closed: Step 6 runs *after* the rotation is already committed on-log (Step 2b) and
  in PG (Step 3), so there is no horizon to withhold and returning an error would falsely
  fail a rotation that already applied — violating the handler's own contract ("Any
  failure in steps 1–4 leaves the handler in its previous state"). Its cold-durability is
  instead provided by the **backfill** (`store.RotationIndexArchiveJob`, run by
  `recovery.ArchiveBackfill` / G1; a stale/v1 index is regenerated there). So the rotation
  index is the *same symptom* (forward best-effort) but the *correct remedy is G1*, not a
  fail-closed forward write.

### Why it matters
A cold reader resolves a covering checkpoint from the **per-size archive**. If that
archive is written fail-open, the horizon can advance past a size whose archived
checkpoint never became durable → a cold read for that size **misses**. Safe **today**
because the cold/PG-off path is S3-only (fail-closed), but the asymmetry is a trap: any
future POSIX deployment that serves cold reads (or any rotated network relying on the
rotation index) inherits a silent durability hole.

### Fix (DONE for the checkpoint archive)
Made POSIX symmetric: `publishCheckpoint` now writes the per-size archive **before** the
horizon and **propagates** its error (fail-closed, matching S3), withholding the horizon
on an archive fault. The now-dead `ctx`/`logger` params (they only fed the swallowed
warn-log) are dropped, matching the file's own FS helpers (`archiveCheckpoint`,
`atomicWriteFile`). `checkpoint_archive_test.go` is inverted to assert the publish FAILS
and the horizon is **not** written.

The rotation index is deliberately **not** changed: as traced above it cannot be
fail-closed (commit precedes the archive), and its cold-durability is the backfill's job
(G1). No "POSIX is advisory" cop-out was needed — symmetry was the right default.

### Acceptance (met)
`tessera/checkpoint_archive_test.go::TestPublishCheckpoint_ArchiveFailure_WithholdsHorizon`:
a forced POSIX per-size-archive write failure **fails the publish** and leaves the horizon
absent — the POSIX mirror of `horizon_s3_test.go`'s index-failure-withholds-horizon test.

---

## G4 — receipt-archive docs contradict the (now fail-closed) code

### Evidence (traced)
Step 9a of the checkpoint loop withholds the horizon on a receipt-archive failure
(`ledger/builder/checkpoint_loop.go`, the `checkpoint: receipt-commit archive at %d not
durable, withholding horizon` path). But these comments on the **forward** receipt-archive
path still describe the old best-effort behavior (a code read found 8 spots, not the 4
first catalogued):
- `ledger/builder/checkpoint_loop.go:276` — `SetReceiptArchiver injects the best-effort
  archiver…`
- `ledger/store/receipt_archive_writer.go:4` — `ReceiptArchiveWriter — best-effort
  writer…`
- `ledger/store/receipt_archive_writer.go:12` — `Best-effort: …never stalls a checkpoint
  …; the backfill job regenerates any gaps.`
- `ledger/store/receipt_archive_writer.go:56` — `…treats archiving as best-effort and
  never stalls publish on it.`
- `ledger/store/receipt_archive.go:12` — `…best-effort: the archive never gates a publish…`
- `ledger/api/horizon.go:123` — `…the builder's best-effort write.`
- `ledger/cmd/ledger/boot/wire/wire.go:374` — `best-effort archive …; an object-store
  write error never stalls a checkpoint.`
- `ledger/store/receipt_archive_writer_test.go:76` — `…(the loop logs it best-effort)…`

The boundary matters: the **backfill** path (`ledger/store/archive_backfill.go`,
`ledger/recovery/archive_backfill.go`) is GENUINELY best-effort per item by design (G1,
off the hot path), and the POSIX per-size **checkpoint-head** archive in
`ledger/tessera/embedded_appender.go` is the separate G3 fail-open gap — neither is a G4
target.

### Why it matters
The receipt archive being durable **before** the horizon is the invariant a PG-off
reader's receipt proof depends on (there is no PG fallback to degrade to). A maintainer
reading these comments could "restore" the documented best-effort behavior and silently
reopen the exact hole G1–G3 exist to close. Doc/code drift on a load-bearing invariant
is a latent correctness regression.

### Fix
Rewrite these forward-path comments to state **fail-closed / withholds the horizon**,
leaving the genuinely best-effort backfill comments untouched. Pure doc, zero risk.
(Done correctly, `grep -i best-effort` over the forward receipt-archive surface returns
nothing.)

### Acceptance
Doc-only; no behavior change. A grep guard in review: no "best-effort" on the forward
receipt-archive path (checkpoint_loop SetReceiptArchiver / Step 9a, receipt_archive_writer,
receipt_archive, api/horizon receiptArchiveObject, the wire wiring) — while the backfill
and POSIX-checkpoint paths keep theirs.

---

## Sequencing & ownership

| Order | Fix | Repo / area | Why this order |
|---|---|---|---|
| 1 | **G1** — `recovery.ArchiveBackfill` + boot hook | tooling (`recovery`, `wire`) | unblocks bounding for **real** (non-greenfield) logs; nothing else matters until pre-feature history can be archived |
| 2 | **G4** — reconcile 4 comments | tooling (docs in code) | 5-minute, zero-risk, stops a regression of the invariant G1 relies on |
| 3 | **G3** — POSIX fail-closed symmetry | tooling (`tessera`) | defense-in-depth; closes the latent durability asymmetry |
| 4 | **G2** — pgoff-cold / dr-serve / shadow-zero | JN e2e | the acceptance proofs that **gate eviction** (#29 Phase 2) |

G1/G3/G4 are tooling and land in libraries (`recovery`/`tessera`/`store`) — consistent
with the CLI-deletion plan (no new `cmd/`). G2 is JN recipes.

## Non-goals
- Eviction itself (#29 Phase 2) — gated behind these four.
- `smt_leaves` bounding — it is `O(active entities)` and stays whole (not row-capped).
- BLS cosignature aggregation, gossipstore/WAL migration — separate epics.

## Code-evidence index
`ledger/store/archive_backfill.go` (job, no caller) · `ledger/cmd/backfill/main.go`
(load generator) · `ledger/tessera/embedded_appender.go:640-655` +
`tessera/checkpoint_archive_test.go:118` (POSIX fail-open) ·
`ledger/store/horizon_s3.go` (S3 fail-closed) ·
`ledger/witnessclient/rotation_handler.go:369` (rotation fail-open) ·
`ledger/builder/checkpoint_loop.go:276` + `:538-549` (Step 9a fail-closed vs stale doc) ·
`ledger/store/receipt_archive_writer.go:4,56` · `ledger/api/horizon.go:123` ·
`e2e/runner/{proof_pgoff.go, proof_cold.go:24/46, dr.go, shadow.go}` ·
`ledger/store/smt_tiles.go:54,73` (in-ledger shadow compare, unasserted in e2e).
