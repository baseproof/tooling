/*
FILE PATH: builder/checkpoint_loop.go

CheckpointLoop — the single authoritative position of the log.

THE ONE CLOCK

	The published cosigned checkpoint is the only artifact consumers anchor on.
	It is produced ONLY over data that is already durable, and it LAGS the commit
	cursor — exactly as a CT log signs a checkpoint over its integrated tree, never
	its tip. There is no second clock reconciled against it by integer size: the
	loop tiles a root and then cosigns THAT SAME root, so the published SMTRoot is
	the tiled root by identity.

	Each cycle, for the latest committed (cSeq, cRoot):
	  1. EmitDurable(cRoot) — make every SMT tile reachable from cRoot durable.
	     Returns only on a PUT-ack/fsync, BEFORE the cosign.
	  2. AdvanceFrontier(cSeq, cRoot) — persist the durable resume cursor.
	  3. Build the head AT the durable root: TreeSize = cSeq+1,
	     RootHash = RootAtSize(cSeq+1) (deterministic from durable Merkle tiles),
	     SMTRoot = cRoot (the root we just tiled), ReceiptRoot = the delta receipts.
	  4. RequestCosignatures(head) — K-of-N over the durable head (persists to
	     tree_heads, gossips).
	  5. PublishCosignedCheckpoint(cosigned) — horizon := this.

INVARIANT (published ⇒ durable)

	A proof anchored on the published horizon's SMTRoot always resolves over the
	tile substrate, because the tiles for that exact root were PUT-ack'd in step 1
	before the cosign in step 4. The HTTP-500 "horizon root unknown" class is
	eliminated by construction.

MELT-PROOF (lagging, not stalling)

	Witnesses gate only the checkpoint, never ingestion. A blob-store outage
	(step 1 errors) or a witness outage (step 4 errors) HOLDS the loop: the horizon
	freezes, the commit cursor keeps advancing, and admission is unaffected until
	the durable-tile max-lag backpressure (builder/loop.go) fires. No partial or
	forged horizon is ever published.

RECOVERY

	The durable tile_frontier is the resume cursor. On boot the loop re-derives the
	gap to cRoot and re-emits (idempotent, content-addressed), then cosigns +
	publishes. A crash between AdvanceFrontier and publish self-heals: the next
	cycle re-emits (no-op) and republishes at the same root.
*/
package builder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/baseproof/tooling/services/ledger/store"
	optessera "github.com/baseproof/tooling/services/ledger/tessera"
)

// checkpointTracerName is the OTel instrumentation scope for the checkpoint loop.
const checkpointTracerName = "github.com/baseproof/tooling/services/ledger/builder"

// CommitCursorReader reports the durable commit cursor: the highest committed seq
// and the SMT root at that seq. Satisfied by store.SMTCommitCursor over
// smt_root_state.
type CommitCursorReader interface {
	ReadCommit(ctx context.Context) (committedSeq uint64, committedRoot [32]byte, err error)
}

// TileFrontierStore is the durable resume cursor for tile emission. Read returns
// the last confirmed frontier; Advance persists it forward AFTER the tiles for
// root are PUT-ack'd. Monotonic and forward-only. Satisfied by
// store.PgTileFrontier.
type TileFrontierStore interface {
	ReadFrontier(ctx context.Context) (frontierSeq uint64, frontierRoot [32]byte, err error)
	AdvanceFrontier(ctx context.Context, frontierSeq uint64, frontierRoot [32]byte) error
}

// TileEmitter makes every SMT tile reachable from committedRoot durable in the
// object store. It MUST return a nil error ONLY after the backend has acknowledged
// the writes (PUT-ack / fsync). It is idempotent and content-addressed, so
// re-emitting an already-present set is cheap. fromRoot lets an implementation
// emit incrementally (fromRoot→committedRoot delta). It returns the content hashes
// of every node now durable in those tiles (the set the reconciler evicts from the
// in-memory tail to bound it); the set is nil/empty on an error or a no-tile root.
// Satisfied by store.BuildTilesEmitter.
type TileEmitter interface {
	EmitDurable(ctx context.Context, fromRoot, committedRoot [32]byte, committedSeq uint64) (durable map[[32]byte]struct{}, err error)
}

// TailPruner evicts a set of now-durable nodes from the in-memory SMT node tail,
// bounding it to the un-tiled gap. *store.TailedNodeStore satisfies it (PruneTiled).
// Optional (SetTailPruner): nil ⇒ no tail eviction. Its absence is the unbounded-
// memory regression — the tail then accumulates every committed node (O(history))
// until the writer OOMs — so a wired pruner is load-bearing for any object-store
// deployment, and tail-bound is pinned by a regression test.
type TailPruner interface {
	PruneTiled(ctx context.Context, exists func(ctx context.Context, id [32]byte) (bool, error))
}

// TailGCAuditor (optional, satisfied by *store.TailedNodeStore) NON-DESTRUCTIVELY
// checks the safety assumption the future orphan-prune will rely on: every tail
// node not reachable from committedRoot (the prune's drop set) is either durable
// in tiles or unreachable from any retained published root (published ⇒ durable).
// It returns the count of VIOLATIONS — would-drop nodes a published root needs
// that are NOT durable — which must stay 0. Wired only when OnTailGCAudit is set.
type TailGCAuditor interface {
	TailGCAudit(committedRoot [32]byte, publishedRoots [][32]byte) (candidates, violations int, sample [32]byte)
}

// TailOrphanPruner (optional, satisfied by *store.TailedNodeStore) evicts tail
// nodes unreachable from the latest committed root — the cross-batch orphans —
// bounding the in-memory tail to the un-tiled gap (O(gap), not O(history)). Safe
// per the published⇒durable invariant (proven by the always-on TailGCAudit); the
// tail is rebuildable from smt_leaves regardless. Returns the count dropped.
// Enabled only when EnableTailOrphanPrune is set (LEDGER_TAIL_GC_PRUNE).
type TailOrphanPruner interface {
	PruneOrphans() (dropped int)
}

// CheckpointRooter derives the deterministic RFC 6962 Merkle root at a tree size
// from durable tiles, and reports the integrated (durable) tree size. Satisfied
// by *tessera.TesseraAdapter (RootAtSize + IntegratedSize).
type CheckpointRooter interface {
	RootAtSize(ctx context.Context, treeSize uint64) ([32]byte, error)

	// IntegratedSize is the inclusive upper bound on tree sizes whose RFC 6962
	// Merkle root is durably derivable from tiles right now. The loop gates on it
	// for two purposes:
	//
	//   - Merkle-durability HOLD: the head binds RootAtSize(treeSize), so treeSize
	//     must be covered (treeSize > integrated ⇒ HOLD until Tessera integrates).
	//   - Genesis disambiguation: smt_root_state is BYTE-IDENTICAL for a fresh log
	//     and for one committed commentary entry — both (committed_through_seq=0,
	//     current_root=EmptyHash), because a commentary entry advances the log
	//     (a Merkle leaf, builder/loop.go Step 5) without mutating the SMT root.
	//     IntegratedSize (0 vs 1) is the ONLY signal that tells them apart, so a
	//     genuinely empty log holds while a commentary seed cosigns.
	IntegratedSize(ctx context.Context) (uint64, error)
}

// CheckpointPublisher writes the published cosigned-checkpoint object (the
// horizon). Satisfied by *tessera.TesseraAdapter (POSIX dir) and by
// *store.S3CheckpointPublisher (object store) — the wiring picks the one that
// matches the byte store, exactly as the legacy publisher did.
type CheckpointPublisher interface {
	PublishCosignedCheckpoint(ctx context.Context, head types.CosignedTreeHead) error
}

// ReceiptRanger computes the ReceiptRoot over the entries the checkpoint newly
// covers — committed seqs in [fromSeq, toSeq] (both 0-indexed, inclusive). It
// preserves the per-increment Web3-receipt binding the head carries, at
// checkpoint granularity. An empty range returns the zero hash (the
// smt.ReceiptRoot "no receipts" sentinel).
type ReceiptRanger interface {
	ReceiptRoot(ctx context.Context, fromSeq, toSeq uint64) ([32]byte, error)
}

// ReceiptCommitArchiver durably archives the dense receipt-commitment set a
// published checkpoint's ReceiptRoot is computed over (to the object store), so
// receipt proofs reconstruct PG-free (store.ArchiveReceiptRanger). OPTIONAL but
// LOAD-BEARING when wired: the loop calls it BEFORE publishing the horizon and
// WITHHOLDS the horizon on an archive error (fail-closed), so a PG-off read front —
// which has no PG fallback — can always reconstruct the receipt proof for any entry
// the published head covers. coveringSize is the published tree_size; [fromSeq, toSeq]
// is the same delta the ReceiptRoot was computed over. nil ⇒ no receipt archiving
// (POSIX single-node: receipts read from PG only).
type ReceiptCommitArchiver interface {
	ArchiveReceiptCommits(ctx context.Context, coveringSize, fromSeq, toSeq uint64) error
}

// EntryTraceReader resolves the W3C traceparent stored on the WAL Meta of the
// entry at a committed seq (the admission trace captured at Submit). Used to LINK
// the checkpoint.cycle span to a bounded sample of the entries it commits, so an
// operator can pivot checkpoint ⇄ entry trace. Satisfied by an adapter over
// *wal.Committer (HashAt → MetaState → Meta.TraceContext). Optional: nil (or a
// "" result for an unsampled/old entry) ⇒ that link is simply skipped.
type EntryTraceReader interface {
	TraceContextAt(ctx context.Context, seq uint64) (string, error)
}

// CheckpointLoop produces the horizon as the cosignature over the latest durable
// root. It replaces the legacy reconciler→publisher seam AND the builder's
// pre-commit cosign: there is exactly one place a head is cosigned and published,
// and it is always over an already-tiled root.
type CheckpointLoop struct {
	commit    CommitCursorReader
	frontier  TileFrontierStore
	emitter   TileEmitter
	tail      TailPruner // optional (SetTailPruner); evicts now-durable nodes from the tail
	rooter    CheckpointRooter
	publisher CheckpointPublisher
	witness   WitnessCosigner
	receipts  ReceiptRanger // optional; nil ⇒ ReceiptRoot bound as the empty hash
	interval  time.Duration
	logger    *slog.Logger

	// receiptArchiver, when non-nil, archives each published checkpoint's dense
	// receipt-commitment set so receipt proofs reconstruct PG-free (1.2a). Injected by
	// the composition root (SetReceiptArchiver) for object-store deployments; the loop
	// archives BEFORE publishing and a write error WITHHOLDS the horizon (fail-closed),
	// since a PG-off read front has no PG fallback. nil ⇒ receipts read from PG only.
	receiptArchiver ReceiptCommitArchiver

	// onWitnessQuorumFailure, when non-nil, fires once per cycle the K-of-N
	// witness cosign is unavailable (the "witness_quorum_unavailable" hold) —
	// the SRE Backpressure-Stall signal. Injected by the composition root
	// (cmd/ledger/boot/wire) so this core loop carries no metrics/gossip
	// dependency; nil ⇒ no-op (tests, metric-free deployments).
	onWitnessQuorumFailure func(context.Context)

	// entryTrace, when non-nil, resolves committed entries' admission traceparents
	// so the checkpoint.cycle span LINKs to a bounded sample of the entries it
	// commits (N:1). Injected by the composition root over the WAL; nil ⇒ the
	// checkpoint is still an always-on batch trace, just without entry links.
	entryTrace EntryTraceReader

	// lastPublishedSize is the tree_size of the most recently published horizon;
	// 0 ⇒ nothing published yet. The skip-if-unchanged guard keys on THIS (the
	// CT-native commit position), never the SMT root — a commentary entry advances
	// the position without moving the root.
	lastPublishedSize uint64
	// lastHoldReason coalesces per-tick HOLD logging: a hold is logged at Info the
	// cycle it begins (or its reason changes) and at Debug while it persists, so a
	// multi-minute blob/witness/merkle stall is ONE Info line, not one per tick.
	lastHoldReason string

	// metricCommitted / metricPublished mirror the latest committed head tree_size
	// and the latest published (witness-cosigned) horizon tree_size for the
	// Phase-2 horizon-lag gauge. Written from the single loop goroutine, read from
	// the metric-scrape goroutine — hence atomic. lag = committed - published.
	metricCommitted atomic.Uint64
	metricPublished atomic.Uint64

	// metricFrontierLag mirrors committed_seq − frontier_seq (the un-tiled gap ≈ the
	// in-memory SMT node tail size in entries). Written from the loop goroutine each
	// working cycle (including a hold, where it grows), read from the metric-scrape
	// goroutine AND the sequencer's backpressure gate — hence atomic. This is the
	// memory-bounding signal: if tiling stalls, this climbs and admission backs off.
	metricFrontierLag atomic.Uint64

	// recentPublishedRoots is a bounded ring of the most recently PUBLISHED
	// (cosigned) checkpoint roots — the historical roots as-of regeneration must
	// keep servable. Used only by the optional tail-GC audit to confirm none of
	// them still reaches into the in-memory tail (published ⇒ durable). Written
	// and read from the single loop goroutine.
	recentPublishedRoots [][32]byte
	// onTailGCAudit, when set (OnTailGCAudit), runs the non-destructive tail-GC
	// safety audit each cycle and reports its result. Injected by the composition
	// root behind LEDGER_TAIL_GC_AUDIT so the core loop stays metrics-free; nil ⇒
	// the audit does not run.
	onTailGCAudit func(ctx context.Context, candidates, violations int, sample [32]byte)

	// pruneOrphans, when true (EnableTailOrphanPrune / LEDGER_TAIL_GC_PRUNE), makes
	// Step 5a additionally evict cross-batch orphans from the tail — the O(history)
	// fix. Off by default; the audit stays on as a live safety net when enabled.
	pruneOrphans bool

	// metricOrphansDropped / metricAuditViolations mirror the cumulative tail-GC
	// orphan evictions and the audit violation count for the metric scrape (the
	// scrape-able gate for a long soak). Written from the loop goroutine, read from
	// the scrape goroutine — hence atomic. metricAuditViolations MUST stay 0.
	metricOrphansDropped  atomic.Uint64
	metricAuditViolations atomic.Uint64
}

// OrphansDropped / AuditViolations expose the cumulative tail-GC counters for the
// metric scrape. AuditViolations must remain 0 (published ⇒ durable holds).
func (l *CheckpointLoop) OrphansDropped() int64  { return int64(l.metricOrphansDropped.Load()) }
func (l *CheckpointLoop) AuditViolations() int64 { return int64(l.metricAuditViolations.Load()) }

const maxRecentPublishedRoots = 64

// OnTailGCAudit installs the non-destructive tail-GC safety audit hook (see
// TailGCAuditor). Set before Run; nil disables it. Temporary validation: it
// proves the orphan-prune is safe (zero violations) before that prune is enabled.
func (l *CheckpointLoop) OnTailGCAudit(fn func(ctx context.Context, candidates, violations int, sample [32]byte)) {
	l.onTailGCAudit = fn
}

// EnableTailOrphanPrune turns on the cross-batch orphan eviction in Step 5a (the
// O(history)→O(gap) tail bound). Set before Run. The audit should stay wired as a
// live safety net while this is on. Requires the tail to satisfy TailOrphanPruner.
func (l *CheckpointLoop) EnableTailOrphanPrune() {
	l.pruneOrphans = true
}

// HorizonLag returns committed head tree_size minus the published (witness-
// cosigned) horizon tree_size — how far the durable, witnessed horizon trails
// the committed log. ~0 in steady state; a sustained positive value is the
// Phase-2 "checkpoint is falling behind" signal (blob/witness/merkle stall, or
// the checkpoint loop not keeping up at load).
func (l *CheckpointLoop) HorizonLag() int64 {
	c := l.metricCommitted.Load()
	p := l.metricPublished.Load()
	if c <= p {
		return 0
	}
	return int64(c - p)
}

// FrontierLag returns committed_seq − frontier_seq: the number of committed entries
// whose SMT tiles are not yet durable — the un-tiled gap that lives in the in-memory
// node tail. ~0 in steady state; a sustained climb means tiling (EmitDurable → object
// store) is falling behind commit, so the tail is growing toward an OOM. It is the
// gauge AND the sequencer's tail-backpressure trigger. Reads a cached value updated
// each working cycle, so it is cheap and lock-free (safe to call from the drain gate).
func (l *CheckpointLoop) FrontierLag() int64 {
	return int64(l.metricFrontierLag.Load())
}

// NewCheckpointLoop wires the loop. interval <= 0 defaults to 1s. receipts may be
// nil (the checkpoint then binds the empty ReceiptRoot — valid per the cosign
// payload contract, used only by deployments with no Web3 receipts).
func NewCheckpointLoop(
	commit CommitCursorReader,
	frontier TileFrontierStore,
	emitter TileEmitter,
	rooter CheckpointRooter,
	publisher CheckpointPublisher,
	witness WitnessCosigner,
	receipts ReceiptRanger,
	interval time.Duration,
	logger *slog.Logger,
) *CheckpointLoop {
	if interval <= 0 {
		interval = time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &CheckpointLoop{
		commit:    commit,
		frontier:  frontier,
		emitter:   emitter,
		rooter:    rooter,
		publisher: publisher,
		witness:   witness,
		receipts:  receipts,
		interval:  interval,
		logger:    logger,
	}
}

// OnWitnessQuorumFailure registers a hook fired once per cycle the witness
// K-of-N cosign is unavailable (the "witness_quorum_unavailable" hold). The
// composition root binds it to the canonical SRE counter
// (gossipnet.IncWitnessQuorumFailure) so this core loop never imports the
// gossip/metrics layer. Pass nil to disable. Set before Run; not safe to
// change concurrently with a running loop.
func (l *CheckpointLoop) OnWitnessQuorumFailure(fn func(context.Context)) {
	l.onWitnessQuorumFailure = fn
}

// SetEntryTraceReader injects the reader used to LINK the checkpoint.cycle span
// to the entries it commits. Set before Run; not safe to change concurrently
// with a running loop. nil disables entry links (the default).
func (l *CheckpointLoop) SetEntryTraceReader(r EntryTraceReader) {
	l.entryTrace = r
}

// SetReceiptArchiver injects the fail-closed archiver that durably retains each
// published checkpoint's dense receipt-commitment set (1.2a) BEFORE the horizon
// advances — the source receipt proofs reconstruct from PG-free. A write error
// WITHHOLDS the horizon (Step 9a), since a PG-off read front has no PG fallback. Set
// before Run; not safe to change concurrently with a running loop. nil disables
// receipt archiving (the default) — receipts then read from PG only.
func (l *CheckpointLoop) SetReceiptArchiver(a ReceiptCommitArchiver) {
	l.receiptArchiver = a
}

// SetTailPruner injects the in-memory SMT node tail so the loop evicts the nodes it
// just made durable after each frontier advance, bounding the tail to the un-tiled
// gap. Without it the tail grows O(history) and the writer OOMs (the de-pollution
// node DAG lives only in the tail until tiled). Set before Run; not safe to change
// concurrently with a running loop. nil disables tail eviction (POSIX/no-tail or a
// substrate that is not a TailedNodeStore).
func (l *CheckpointLoop) SetTailPruner(p TailPruner) {
	l.tail = p
}

// maxCheckpointLinks bounds the number of entry links on a checkpoint.cycle span.
// The checkpoint may commit thousands of entries; linking all of them would mean
// an O(N) WAL read per cycle and would blow the SDK's per-span link cap. Instead
// we link an EVENLY-SPACED sample (including both ends of the delta), giving
// checkpoint ⇄ entry navigability at O(maxCheckpointLinks) reads, independent of
// how many entries the cycle covers.
const maxCheckpointLinks = 16

// gatherCommittedTraceparents returns up to maxCheckpointLinks admission
// traceparents sampled evenly across the committed delta [fromSeq, toSeq] (both
// inclusive — the entries this checkpoint newly covers). Entries with no stored
// trace context (unsampled / pre-V3) or that error are skipped. Returns nil when
// no reader is wired. Bounded reads regardless of delta size.
func (l *CheckpointLoop) gatherCommittedTraceparents(ctx context.Context, fromSeq, toSeq uint64) []string {
	if l.entryTrace == nil || toSeq < fromSeq {
		return nil
	}
	span := toSeq - fromSeq + 1 // count of seqs in the inclusive delta
	n := span
	if n > maxCheckpointLinks {
		n = maxCheckpointLinks
	}
	seen := make(map[uint64]struct{}, n)
	out := make([]string, 0, n)
	for i := uint64(0); i < n; i++ {
		// Evenly spaced; n==1 picks fromSeq, otherwise both ends are included.
		seq := fromSeq
		if n > 1 {
			seq = fromSeq + (span-1)*i/(n-1)
		}
		if _, dup := seen[seq]; dup {
			continue
		}
		seen[seq] = struct{}{}
		tp, err := l.entryTrace.TraceContextAt(ctx, seq)
		if err != nil || tp == "" {
			continue
		}
		out = append(out, tp)
	}
	return out
}

// CheckpointOnce performs one cycle. Exported for tests and for an explicit
// boot-time catch-up before serving.
//
// Returns nil on a successful publish, on a benign skip (nothing new, or no
// witness collector wired), AND on a HOLD (blob/witness/tile-durability not
// ready) — a hold is not an error, it just leaves the horizon where it is for the
// next cycle. The only non-nil returns are genuine faults (a DB read failure, a
// RootAtSize fault that is not the durability sentinel) that the caller logs.
func (l *CheckpointLoop) CheckpointOnce(ctx context.Context) error {
	tr := otel.Tracer(checkpointTracerName)

	// ── Step 1: read the commit cursor — the input the whole cycle keys off ──
	cSeq, cRoot, err := l.commit.ReadCommit(ctx)
	if err != nil {
		return fmt.Errorf("checkpoint: read commit cursor: %w", err)
	}
	// treeSize is the CT-native position the head binds; the +1 lives ONLY in
	// store.TreeSizeForCommittedSeq (see store/smt_root_state.go — never re-derive).
	treeSize := store.TreeSizeForCommittedSeq(cSeq)
	l.metricCommitted.Store(treeSize) // horizon-lag gauge numerator (every cycle)

	// Skip-if-unchanged BEFORE opening any span: an idle tick (nothing newly
	// committed) must NOT emit a checkpoint.cycle span, or the always-on batch
	// trace floods the tracer at the loop cadence. The checkpoint clock is the
	// COMMIT POSITION (tree_size), the CT-native position — NOT the SMT root (a
	// commentary entry advances tree_size without moving the root; keying on the
	// root would freeze the horizon across a commentary run AND, at the first
	// entry, is indistinguishable from genesis). lastPublishedSize 0 ⇒ none yet.
	if treeSize <= l.lastPublishedSize {
		l.logger.DebugContext(ctx, "checkpoint step: skip — nothing new committed",
			"tree_size", treeSize, "last_published_size", l.lastPublishedSize)
		return nil
	}

	// ── Step 2: read the durable resume cursor (frontier) ── read here, BEFORE the
	// span, so the cycle span can LINK to the entries this checkpoint newly covers
	// (the delta (fSeq, cSeq]). The read is side-effect-free; the frontier is only
	// ADVANCED after tiles are durable (Step 5). Drives both the incremental-emit
	// fromRoot and the receipt delta's lower bound.
	fSeq, fRoot, err := l.frontier.ReadFrontier(ctx)
	if err != nil {
		return fmt.Errorf("checkpoint: read frontier: %w", err)
	}
	// Frontier-lag (un-tiled gap, in entries) for the gauge + the sequencer's
	// tail-backpressure gate. Updated every working cycle, INCLUDING a hold (where cSeq
	// advances but fSeq is frozen, so this climbs — exactly when admission must back
	// off). The frontier never leads the commit cursor, so cSeq ≥ fSeq.
	if cSeq >= fSeq {
		l.metricFrontierLag.Store(cSeq - fSeq)
	}
	// fromRoot is the prior durably-tiled root — the anchor the incremental emitter
	// warms from: it fetches the same-position prior tile so a re-emitted tile's
	// unchanged interiors resolve after the in-memory tail is pruned (without it the
	// emit faults "interior node missing"). It is ALWAYS a valid warm anchor —
	// EmptyHash at genesis (seeded by migration 0012) or a real durable tile root
	// (AdvanceFrontier never writes the zero value). An empty delta (fRoot == cRoot)
	// warms cRoot's own tile and re-emits it idempotently, so no special-casing is
	// needed; passing the zero value here would instead fault the warm-walk.
	fromRoot := fRoot

	// checkpoint.cycle — the N:1 batch span. A NEW ROOT (its own trace) marked
	// AlwaysSampleAttr so it is ALWAYS recorded even under sparse per-entry
	// sampling (the durability path must never go dark), and LINKED via the stored
	// admission traceparents to a BOUNDED sample of the entries this checkpoint
	// newly commits — so an operator can pivot checkpoint ⇄ entry without an O(N)
	// read. Child spans (emit_tiles / cosign / publish) carry this ctx so deeper
	// spans — and the outbound cosign→witness hop — nest under it. Working cycles
	// only (idle ticks returned above).
	links := l.gatherCommittedTraceparents(ctx, fSeq, cSeq)
	ctx, span := sdklog.StartLinked(ctx, tr, "checkpoint.cycle", links,
		trace.WithNewRoot(),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			sdklog.AlwaysSampleAttr,
			attribute.Int64("ledger.committed_seq", int64(cSeq)),
			attribute.Int64("ledger.tree_size", int64(treeSize)),
			attribute.Int("ledger.linked_entries", len(links)),
		),
	)
	defer span.End()
	l.logger.DebugContext(ctx, "checkpoint step: read commit cursor",
		"committed_seq", cSeq,
		"committed_root", fmt.Sprintf("%x", cRoot[:8]),
		"tree_size", treeSize,
		"last_published_size", l.lastPublishedSize,
	)
	l.logger.DebugContext(ctx, "checkpoint step: read frontier",
		"frontier_seq", fSeq,
		"frontier_root", fmt.Sprintf("%x", fRoot[:8]),
		"from_root", fmt.Sprintf("%x", fromRoot[:8]),
	)

	// ── Step 3: Merkle-durability + genesis gate ──
	// The head binds RootAtSize(treeSize), so the Merkle tiles must cover treeSize.
	// IntegratedSize is the inclusive durable upper bound. This single comparison
	// ALSO resolves genesis: a genuinely empty log has IntegratedSize 0 (< the
	// treeSize=1 the committed_through_seq 0-sentinel implies) → HOLD; a single
	// committed commentary entry has IntegratedSize 1 → proceed. The smt_root_state
	// row is byte-identical in both cases, so this is the only thing that tells them
	// apart.
	integrated, err := l.rooter.IntegratedSize(ctx)
	if err != nil {
		return fmt.Errorf("checkpoint: integrated size: %w", err)
	}
	l.logger.DebugContext(ctx, "checkpoint step: integrated size",
		"tree_size", treeSize, "integrated_size", integrated)
	if treeSize > integrated {
		// Empty log (integrated 0) OR Merkle integration lagging the commit — either
		// way the head's RootHash is not yet derivable; hold the horizon.
		span.SetAttributes(attribute.String("checkpoint.hold", "merkle_not_durable"))
		return l.hold(ctx, "merkle_not_durable",
			"tree_size", treeSize, "integrated_size", integrated, "committed_seq", cSeq)
	}

	// ── Step 4: make cRoot's SMT tiles durable. Returns only on PUT-ack; a blob
	//    outage HOLDS (horizon frozen, commit cursor unaffected). EmptyHash (a
	//    commentary/seed root) is a no-op success — there are no SMT tiles. ──
	emitCtx, emitSpan := tr.Start(ctx, "checkpoint.emit_tiles",
		trace.WithAttributes(attribute.Int64("ledger.committed_seq", int64(cSeq))))
	durable, eErr := l.emitter.EmitDurable(emitCtx, fromRoot, cRoot, cSeq)
	if eErr != nil {
		emitSpan.RecordError(eErr)
		emitSpan.SetStatus(codes.Error, eErr.Error())
	}
	emitSpan.End()
	if eErr != nil {
		span.SetAttributes(attribute.String("checkpoint.hold", "smt_tiles_not_durable"))
		return l.hold(ctx, "smt_tiles_not_durable",
			"committed_seq", cSeq, "frontier_seq", fSeq,
			"committed_root", fmt.Sprintf("%x", cRoot[:8]), "error", eErr)
	}
	l.logger.DebugContext(ctx, "checkpoint step: emit durable ok",
		"committed_root", fmt.Sprintf("%x", cRoot[:8]), "committed_seq", cSeq)

	// ── Step 5: advance the durable resume cursor to the root we just tiled ──
	if aErr := l.frontier.AdvanceFrontier(ctx, cSeq, cRoot); aErr != nil {
		return fmt.Errorf("checkpoint: advance frontier to %d: %w", cSeq, aErr)
	}
	l.logger.DebugContext(ctx, "checkpoint step: advance frontier",
		"frontier_seq", cSeq, "frontier_root", fmt.Sprintf("%x", cRoot[:8]))

	// ── Step 5a: evict the now-durable nodes from the in-memory SMT node tail. ──
	// cRoot's tiles are durable (Step 4) and the frontier has advanced past them
	// (Step 5), so every node in `durable` is servable from tiles — retaining it in
	// the tail only grows the heap. The oracle is membership in the just-durable set,
	// so eviction is fail-closed (evict iff durable), honoring the retention invariant
	// (store/tailed_node_store.go). WITHOUT this the tail accumulates every committed
	// node, O(history), and the writer OOMs. nil pruner (no tail) ⇒ skip.
	if l.tail != nil && len(durable) > 0 {
		l.tail.PruneTiled(ctx, func(_ context.Context, h [32]byte) (bool, error) {
			_, ok := durable[h]
			return ok, nil
		})
	}

	// ── Step 5a′ (temporary, LEDGER_TAIL_GC_AUDIT): non-destructive tail-GC safety
	// audit. The future orphan-prune will drop tail nodes unreachable from the
	// committed root; this confirms that is safe — that NO retained published root
	// still reaches a non-durable tail node (published ⇒ durable). Reports via the
	// injected hook; a non-zero violation count means the assumption is false. cRoot
	// is the just-committed, now-durable SMT root. ──
	if l.onTailGCAudit != nil {
		if auditor, ok := l.tail.(TailGCAuditor); ok && len(l.recentPublishedRoots) > 0 {
			cand, viol, sample := auditor.TailGCAudit(cRoot, l.recentPublishedRoots)
			if viol > 0 {
				l.metricAuditViolations.Add(uint64(viol))
			}
			l.onTailGCAudit(ctx, cand, viol, sample)
		}
	}

	// ── Step 5b (LEDGER_TAIL_GC_PRUNE): evict CROSS-BATCH orphans — tail nodes
	// unreachable from the latest committed root. PruneTiled (Step 5a) only drops
	// nodes that became durable; nodes superseded across batches are never tiled,
	// so without this they accumulate O(history). This bounds the tail to the
	// un-tiled gap. Safe per the published⇒durable invariant the always-on audit
	// verifies; the tail is rebuildable from smt_leaves regardless. ──
	if l.pruneOrphans {
		if pruner, ok := l.tail.(TailOrphanPruner); ok {
			if dropped := pruner.PruneOrphans(); dropped > 0 {
				l.metricOrphansDropped.Add(uint64(dropped))
				l.logger.DebugContext(ctx, "checkpoint step: tail orphan prune",
					"dropped", dropped, "committed_root", fmt.Sprintf("%x", cRoot[:8]))
			}
		}
	}

	// ── Step 6: Merkle root at the committed size (deterministic from durable
	//    tiles). Step 2 already gated treeSize <= integrated, so ErrTilesNotDurable
	//    here is only a tight race against a shrinking view — HOLD rather than fault. ──
	rootHash, rErr := l.rooter.RootAtSize(ctx, treeSize)
	if rErr != nil {
		if errors.Is(rErr, optessera.ErrTilesNotDurable) {
			return l.hold(ctx, "merkle_root_not_durable",
				"tree_size", treeSize, "integrated_size", integrated, "error", rErr)
		}
		return fmt.Errorf("checkpoint: RootAtSize(%d): %w", treeSize, rErr)
	}
	l.logger.DebugContext(ctx, "checkpoint step: root at size",
		"tree_size", treeSize, "root_hash", fmt.Sprintf("%x", rootHash[:8]))

	// ── Step 7: receipt root over the entries newly covered since the last PUBLISH
	//    (the delta [lastPublishedSize, cSeq]) — keyed off the cosigned ladder, not
	//    the tile frontier, so a cosign hold can't orphan the held delta's receipts. ──
	receiptRoot, rcErr := l.receiptRootForCheckpoint(ctx, cSeq)
	if rcErr != nil {
		return fmt.Errorf("checkpoint: receipt root [%d..%d]: %w", l.lastPublishedSize, cSeq, rcErr)
	}
	l.logger.DebugContext(ctx, "checkpoint step: receipt root",
		"from_seq", l.lastPublishedSize, "to_seq", cSeq,
		"receipt_root", fmt.Sprintf("%x", receiptRoot[:8]))

	head := types.TreeHead{
		TreeSize:    treeSize,
		RootHash:    rootHash,
		SMTRoot:     cRoot,
		ReceiptRoot: receiptRoot,
	}

	// ── Step 8: cosign the durable head (K-of-N). A witness-quorum failure HOLDS
	//    (horizon frozen, commit unaffected). A zero-TreeSize return means no
	//    collector is wired (read-only / test ledger) — nothing to publish. ──
	l.logger.DebugContext(ctx, "checkpoint step: request cosignatures",
		"tree_size", head.TreeSize,
		"root_hash", fmt.Sprintf("%x", head.RootHash[:8]),
		"smt_root", fmt.Sprintf("%x", head.SMTRoot[:8]),
		"receipt_root", fmt.Sprintf("%x", head.ReceiptRoot[:8]),
	)
	cosignCtx, cosignSpan := tr.Start(ctx, "checkpoint.cosign",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.Int64("ledger.tree_size", int64(head.TreeSize))))
	cosigned, cErr := l.witness.RequestCosignatures(cosignCtx, head)
	if cErr != nil {
		cosignSpan.RecordError(cErr)
		cosignSpan.SetStatus(codes.Error, cErr.Error())
	}
	cosignSpan.End()
	if cErr != nil {
		// SRE signal (Backpressure Stall): a failed K-of-N cosign request IS a
		// witness-quorum failure. Fire per cycle so a sustained stall shows a
		// positive rate(); the hook no-ops until the composition root wires it.
		if l.onWitnessQuorumFailure != nil {
			l.onWitnessQuorumFailure(ctx)
		}
		span.SetAttributes(attribute.String("checkpoint.hold", "witness_quorum_unavailable"))
		return l.hold(ctx, "witness_quorum_unavailable", "tree_size", treeSize, "error", cErr)
	}
	if cosigned.TreeSize == 0 {
		l.logger.DebugContext(ctx, "checkpoint step: no witness collector wired — nothing to publish",
			"tree_size", treeSize)
		return nil
	}
	l.logger.DebugContext(ctx, "checkpoint step: cosignatures collected",
		"tree_size", treeSize, "signatures", len(cosigned.Signatures))

	// ── Step 9a: archive the receipt commitments BEFORE publishing the horizon. ──
	// The dense receipt-commitment set this checkpoint's ReceiptRoot was computed over
	// must be durable in the object store before the horizon advertises this size, so a
	// PG-OFF read front can reconstruct the receipt proof for any entry the published
	// head covers. Fail-closed — a receipt-archive error withholds the horizon (the
	// same posture as the tile shipper + the per-size checkpoint archive), because a
	// cold reader has no PG fallback to degrade to. Uses the not-yet-advanced
	// lastPublishedSize as the delta start — the exact [fromSeq, cSeq] the ReceiptRoot
	// was computed over at Step 7, covering size = published tree_size. The archiver is
	// wired only for object-store deployments (SetReceiptArchiver); a POSIX single-node
	// co-locates PG and never sets it, so this is a no-op there.
	if l.receiptArchiver != nil && cSeq >= l.lastPublishedSize {
		arCtx, arSpan := tr.Start(ctx, "checkpoint.receipt-archive",
			trace.WithAttributes(attribute.Int64("ledger.tree_size", int64(treeSize))))
		aErr := l.receiptArchiver.ArchiveReceiptCommits(arCtx, treeSize, l.lastPublishedSize, cSeq)
		if aErr != nil {
			arSpan.RecordError(aErr)
			arSpan.SetStatus(codes.Error, aErr.Error())
		}
		arSpan.End()
		if aErr != nil {
			return fmt.Errorf("checkpoint: receipt-commit archive at %d not durable, withholding horizon: %w", treeSize, aErr)
		}
	}

	// ── Step 9b: publish. The horizon now advertises a root whose tiles, per-size
	// checkpoint archive, size index, and receipt commitments are ALL durable. ──
	pubCtx, pubSpan := tr.Start(ctx, "checkpoint.publish",
		trace.WithAttributes(attribute.Int("ledger.signatures", len(cosigned.Signatures))))
	pErr := l.publisher.PublishCosignedCheckpoint(pubCtx, cosigned)
	if pErr != nil {
		pubSpan.RecordError(pErr)
		pubSpan.SetStatus(codes.Error, pErr.Error())
	}
	pubSpan.End()
	if pErr != nil {
		return fmt.Errorf("checkpoint: publish checkpoint at %d: %w", treeSize, pErr)
	}

	span.SetAttributes(attribute.Int("ledger.signatures", len(cosigned.Signatures)))
	l.lastPublishedSize = treeSize
	l.metricPublished.Store(treeSize) // horizon-lag gauge denominator (on publish)
	if l.onTailGCAudit != nil {       // retain the published SMT root for the tail-GC audit
		l.recentPublishedRoots = append(l.recentPublishedRoots, cRoot)
		if n := len(l.recentPublishedRoots); n > maxRecentPublishedRoots {
			l.recentPublishedRoots = l.recentPublishedRoots[n-maxRecentPublishedRoots:]
		}
	}
	l.lastHoldReason = ""
	l.logger.InfoContext(ctx, "checkpoint published",
		"tree_size", treeSize,
		"smt_root", fmt.Sprintf("%x", cRoot[:8]),
		"root_hash", fmt.Sprintf("%x", rootHash[:8]),
		"receipt_root", fmt.Sprintf("%x", receiptRoot[:8]),
		"integrated_size", integrated,
		"signatures", len(cosigned.Signatures),
	)
	return nil
}

// hold logs a HOLD outcome with full input context and returns nil — a HOLD is
// not an error; it leaves the horizon where it is for the next cycle. To keep a
// long stall from spamming one line per tick, the hold is logged at Info the cycle
// it BEGINS (or its reason changes) and at Debug while the SAME reason persists.
// A successful publish clears lastHoldReason, so the recovery transition logs at
// Info too (the next hold, if any, is "new" again).
func (l *CheckpointLoop) hold(ctx context.Context, reason string, attrs ...any) error {
	args := make([]any, 0, len(attrs)+2)
	args = append(args, "reason", reason)
	args = append(args, attrs...)
	if reason == l.lastHoldReason {
		l.logger.DebugContext(ctx, "checkpoint hold (persisting; horizon frozen, commit unaffected)", args...)
		return nil
	}
	l.lastHoldReason = reason
	l.logger.InfoContext(ctx, "checkpoint hold (horizon frozen, commit unaffected)", args...)
	return nil
}

// receiptRootForCheckpoint computes the ReceiptRoot over the entries this
// checkpoint newly covers, as the delta [lastPublishedSize, cSeq].
//
// The lower bound is the last PUBLISHED (witness-cosigned) tree_size — NOT the
// tile-durability frontier. The frontier advances at Step 5 (before cosign), so a
// cosign HOLD leaves it ahead of the horizon; keying the receipt delta off it then
// (a) ORPHANS the held checkpoint's receipts (its delta root is never published)
// and (b) desyncs from the receipt-proof handler, which keys its range off the
// cosigned ladder (CosignedSizeBelow). The last published checkpoint at tree_size
// lastPublishedSize covers seqs [0, lastPublishedSize-1], so the entries not yet in
// a published checkpoint are [lastPublishedSize, cSeq] — exactly the handler's
// reconstruction range, and across a hold this delta SPANS the held region (no
// orphaning). lastPublishedSize 0 ⇒ genesis ⇒ the whole committed range [0, cSeq].
// nil ranger ⇒ the empty ReceiptRoot (the cosign payload accepts a zero ReceiptRoot
// as "no off-chain receipts").
func (l *CheckpointLoop) receiptRootForCheckpoint(ctx context.Context, cSeq uint64) ([32]byte, error) {
	if l.receipts == nil {
		return [32]byte{}, nil
	}
	fromSeq := l.lastPublishedSize
	if fromSeq > cSeq {
		// Nothing new since the last publish (e.g. a re-tick at the same size).
		return [32]byte{}, nil
	}
	return l.receipts.ReceiptRoot(ctx, fromSeq, cSeq)
}

// Run loops CheckpointOnce on the configured interval until ctx is cancelled.
// A skip-if-unchanged check inside CheckpointOnce makes idle ticks near-free, so
// the ticker doubles as the event-coalescing mechanism (a busy log publishes
// every tick; a quiet one no-ops).
func (l *CheckpointLoop) Run(ctx context.Context) {
	l.logger.Info("checkpoint loop started", "interval", l.interval)
	t := time.NewTicker(l.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			l.logger.Info("checkpoint loop stopped")
			return
		case <-t.C:
			if err := l.CheckpointOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
				l.logger.Warn("checkpoint cycle failed; horizon held (writer unaffected)", "error", err)
			}
		}
	}
}
