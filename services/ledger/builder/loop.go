/*
Package builder — loop.go

DESCRIPTION:

	The continuous builder loop — THE core operational loop of the ledger.
	Dequeues admitted entries, calls SDK ProcessBatch, commits state atomically,
	appends entry identities to the Merkle tree, publishes commitments, and
	requests witness cosignatures.

KEY ARCHITECTURAL DECISIONS:
  - Single goroutine: determinism requires exactly one builder per log.
    Advisory lock prevents concurrent instances.
  - Atomic commit: leaf mutations + delta buffer + queue status in ONE
    Postgres transaction. No partial state on crash.
  - Overlay SMT Store: SDK ProcessBatch runs against an in-memory overlay
    to guarantee functional purity. If batch validation fails, the overlay
    is discarded and Postgres remains completely untouched.
  - Entry-identity Merkle tree:
    Step 6 sends envelope.EntryIdentity(entry) — SHA-256 of the entry's
    canonical bytes, NOT the wire-bytes-including-signature hash — to
    the Tessera personality, which wraps it with RFC 6962's 0x00 leaf
    prefix internally. Full wire bytes (canonical + sig_envelope) stay
    in the ledger's own storage. Tessera never sees full entry data.
    Critical: do NOT use envelope.EntryLeafHash here — that would double-
    apply the RFC 6962 prefix because tessera-personality's NewEntry
    already applies it.
  - SDK MerkleTree interface: builder touches only the MerkleAppender
    interface, never tessera/client.go directly. Swappable backend.
  - Idempotent: replaying the same batch produces identical state.
  - Context-aware: every Postgres call checks ctx.Done() first.

SDK ALIGNMENT:
  - Read-side abstraction is types.EntryFetcher with the
    Fetch(pos LogPosition) (*EntryWithMetadata, error) signature.
    sdkbuilder.ProcessBatch accepts types.EntryFetcher.

OVERVIEW:

	Run loop: dequeue → fetch → split → ProcessBatch → atomic commit →
	Merkle append (entry-identity hash) → commitment → witness cosig.

	Step 6 (Merkle append) is POST-COMMIT and best-effort. Crash between
	commit and append → re-append on restart is safe (Tessera deduplicates
	by identity hash). The ledger's atomic state is in Postgres.

CONSUMER VERIFICATION FLOW:
 1. Fetch wire bytes from ledger's byte store.
 2. envelope.Deserialize(canonical) → entry (signatures inline).
 3. envelope.EntryIdentity(entry) → 32-byte hash.
 4. Fetch inclusion proof for position N, verify path hashes to the
    tree head published in the signed checkpoint.

KEY DEPENDENCIES:
  - github.com/baseproof/baseproof/builder: ProcessBatch, BatchResult,
    SchemaResolver, DeltaWindowBuffer.
  - github.com/baseproof/baseproof/core/envelope: EntryIdentity.
  - github.com/baseproof/baseproof/types: EntryFetcher (read-side
    abstraction, moved from builder/ in ).
  - tessera/proof_adapter.go: TesseraAdapter implements MerkleAppender.
  - store/smt_state.go: PostgresLeafStore.SetTx for atomic leaf writes.
  - store/entries.go: PostgresEntryFetcher implements types.EntryFetcher.
*/
package builder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/store"
	optessera "github.com/baseproof/tooling/services/ledger/tessera"
)

// -------------------------------------------------------------------------------------------------
// 1) Configuration
// -------------------------------------------------------------------------------------------------

// LoopConfig configures the builder loop.
type LoopConfig struct {
	LogDID       string
	BatchSize    int
	PollInterval time.Duration
	DeltaWindow  int
}

const (
	// defaultBatchSize is the builder's per-cycle dequeue when unset.
	defaultBatchSize = 1000

	// MaxBatchSize caps the builder's per-cycle dequeue. BeginBatch already
	// enforces the requested size via SQL LIMIT (store.SequenceCursor.Next);
	// this bounds the CONFIGURED value so LEDGER_BATCH_SIZE can never set that
	// LIMIT pathologically high. A batch sizes three things that all scale with
	// it: the in-memory node tail accumulated before the reconciler tiles it,
	// the atomic-commit critical section (and the vacuum/bloat pressure it
	// creates on builder_cursor + smt_leaves), and the per-commitment mutation
	// set. 1024 keeps all three bounded; the default (1000) sits just under it.
	MaxBatchSize = 1024
)

// DefaultLoopConfig returns production defaults.
func DefaultLoopConfig(logDID string) LoopConfig {
	return LoopConfig{
		LogDID:       logDID,
		BatchSize:    defaultBatchSize,
		PollInterval: 100 * time.Millisecond,
		DeltaWindow:  10,
	}
}

// clampBatchSize normalizes a configured batch size into (0, MaxBatchSize]: a
// non-positive value falls back to defaultBatchSize, and anything above
// MaxBatchSize is capped (logged once at construction). This is the single
// enforcement point, so every BuilderLoop — production wiring or test — runs
// with a bounded batch regardless of how BatchSize was configured.
func clampBatchSize(n int, logger *slog.Logger) int {
	if n <= 0 {
		return defaultBatchSize
	}
	if n > MaxBatchSize {
		if logger != nil {
			logger.Warn("builder: configured BatchSize exceeds MaxBatchSize; clamping",
				"configured", n, "max", MaxBatchSize)
		}
		return MaxBatchSize
	}
	return n
}

// -------------------------------------------------------------------------------------------------
// 2) Interfaces
// -------------------------------------------------------------------------------------------------

// MerkleAppender is the subset of the Merkle tree interface used by the builder.
//
// AppendLeaf takes a 32-byte SHA-256 entry identity (envelope.EntryIdentity).
// Tessera stores this hash in its entry tiles and computes the Merkle leaf
// hash as H(0x00 || hash_bytes) per RFC 6962. The ledger does NOT apply
// the RFC 6962 prefix here — that's Tessera's job.
//
// Full entry bytes (canonical + signature envelope) stay in the ledger's
// own storage. Tessera never sees them.
//
// PublishCosignedCheckpoint writes the K-of-N cosigned tree head to the
// public publication path (CDN-fronted file). Called by the builder
// AFTER the atomic commit and AFTER witness quorum has been collected.
// Implementations MUST write atomically (write-tmp + rename) so partial
// state is never visible to auditors. Empty publication path on the
// concrete implementation is a graceful no-op so dev / test runs that
// don't set a public path still work.
type MerkleAppender interface {
	AppendLeaf(ctx context.Context, data []byte) (uint64, error)
}

// WitnessCosigner requests K-of-N cosignatures on a tree head and, on success,
// persists the (head + signatures) to tree_heads and returns the assembled
// CosignedTreeHead. Used by the CheckpointLoop (NOT the builder hot path): the
// checkpoint cosigns a head over an already-durable root, lagging the commit
// cursor, so a witness-quorum failure HOLDS the horizon without ever stalling
// ingestion. Satisfied by *witnessclient.HeadSync.
type WitnessCosigner interface {
	RequestCosignatures(ctx context.Context, head types.TreeHead) (types.CosignedTreeHead, error)
}

// -------------------------------------------------------------------------------------------------
// 3) BuilderLoop
// -------------------------------------------------------------------------------------------------

// BuilderLoop is the continuous builder goroutine.
//
// # V0.3.0 ARCHITECTURE
//
// Each cycle wraps the persistent leafStore + nodeStore in overlays
// (smt.OverlayLeafStore + smt.OverlayNodeStore), runs the SDK's
// ProcessBatch against an overlay-backed Tree seeded with priorRoot,
// then commits the overlay's leaf + node mutations transactionally
// alongside the cursor advance and the new SMT root. Failure at any
// pre-commit step discards the overlays — the persistent state is
// untouched.
//
// The persistent `tree` field is the read-side handle shared with
// API handlers. After a successful commit the builder calls
// `tree.SetRoot(newRoot)` so handlers observe the new root without
// going through Postgres for every request.
type BuilderLoop struct {
	cfg       LoopConfig
	db        *pgxpool.Pool
	tree      *smt.Tree
	leafStore *store.PostgresLeafStore
	nodeStore *store.TailedNodeStore // de-polluted substrate: tiles + in-memory tail
	// reader is the CT-native log-tailing follower that reads new
	// sequences from entry_index and advances builder_cursor in the
	// builder's atomic commit. See builder/cursor_reader.go.
	reader      BatchReader
	fetcher     types.EntryFetcher
	schema      sdkbuilder.SchemaResolver
	buffer      *sdkbuilder.DeltaWindowBuffer
	bufferStore *DeltaBufferStore
	commitPub   *CommitmentPublisher
	merkle      MerkleAppender
	logger      *slog.Logger

	// rootStore is OPTIONAL but production-required. It holds the
	// authoritative smt_root_state.current_root that the builder
	// advances each batch. /v1/smt/root reads it in O(1). When nil,
	// the builder still runs but advances only the in-memory
	// tree.rootHash — useful for tests that don't bootstrap the
	// singleton row.
	rootStore *store.SMTRootStateStore

	// tileFrontier + maxTileLag: the max-lag backpressure gate. processBatch holds
	// the cursor when committed_through_seq - tile_frontier_seq > maxTileLag so the
	// checkpoint loop catches up — bounding the in-memory node tail. nil/0 ⇒ off.
	tileFrontier tileFrontierReader
	maxTileLag   uint64

	// Observability counters (atomic, lock-free).
	totalBatches   atomic.Int64
	totalEntries   atomic.Int64
	totalErrors    atomic.Int64
	consecutiveErr atomic.Int32
}

// NewBuilderLoop creates a builder loop with all dependencies.
func NewBuilderLoop(
	cfg LoopConfig,
	db *pgxpool.Pool,
	tree *smt.Tree,
	leafStore *store.PostgresLeafStore,
	nodeStore *store.TailedNodeStore,
	reader BatchReader,
	fetcher types.EntryFetcher,
	schema sdkbuilder.SchemaResolver,
	buffer *sdkbuilder.DeltaWindowBuffer,
	bufferStore *DeltaBufferStore,
	commitPub *CommitmentPublisher,
	merkle MerkleAppender,
	logger *slog.Logger,
) *BuilderLoop {
	// Single enforcement point for the per-cycle dequeue cap — every batch is
	// bounded to (0, MaxBatchSize] regardless of how BatchSize was configured.
	cfg.BatchSize = clampBatchSize(cfg.BatchSize, logger)
	return &BuilderLoop{
		cfg:         cfg,
		db:          db,
		tree:        tree,
		leafStore:   leafStore,
		nodeStore:   nodeStore,
		reader:      reader,
		fetcher:     fetcher,
		schema:      schema,
		buffer:      buffer,
		bufferStore: bufferStore,
		commitPub:   commitPub,
		merkle:      merkle,
		logger:      logger,
	}
}

// WithRootStore wires the SMTRootStateStore that holds the
// authoritative current SMT root + committed-through-seq. When set,
// processBatch reads priorRoot from it, computes newRoot
// incrementally via Tree.ComputeDirtyRoot, and persists the new
// value inside the same atomic commit transaction that writes the
// batch's leaves + cursor advance.
//
// Returns the receiver for chaining (mirroring the WithReplayer
// pattern used by the sequencer).
func (bl *BuilderLoop) WithRootStore(rs *store.SMTRootStateStore) *BuilderLoop {
	bl.rootStore = rs
	return bl
}

// tileFrontierReader reports the durable tile-frontier seq (store.PgTileFrontier).
type tileFrontierReader interface {
	ReadFrontier(ctx context.Context) (uint64, [32]byte, error)
}

// WithTileFrontierGate wires the max-lag backpressure gate: when
// committed_through_seq - tile_frontier_seq exceeds maxLag, processBatch holds
// the cursor until the reconciler catches up (bounds the in-memory tail).
// maxLag == 0 disables it.
func (bl *BuilderLoop) WithTileFrontierGate(fr tileFrontierReader, maxLag uint64) *BuilderLoop {
	bl.tileFrontier = fr
	bl.maxTileLag = maxLag
	return bl
}

// tileLagExceeded reports whether the tile frontier is more than maxLag behind
// the commit cursor.
func tileLagExceeded(committedSeq, frontierSeq, maxLag uint64) bool {
	return maxLag > 0 && committedSeq > frontierSeq && committedSeq-frontierSeq > maxLag
}

// Tree returns the builder's SMT tree — the SAME instance the builder
// advances via SetRoot on every commit. API proof handlers MUST read from
// this tree (not a second smt.NewTree) so proofs are generated at the LIVE
// committed root, matching the cosigned smt_root and the emitted tiles. A
// separate, never-advanced tree serves proofs at the stale genesis root, so
// every tile/pg proof fails to verify against the witnessed root.
func (bl *BuilderLoop) Tree() *smt.Tree {
	return bl.tree
}

// -------------------------------------------------------------------------------------------------
// 4) Run — main loop with clean shutdown and panic recovery
// -------------------------------------------------------------------------------------------------

// Run executes the builder loop until ctx is cancelled.
// MUST be called from a single goroutine.
func (bl *BuilderLoop) Run(ctx context.Context) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			bl.logger.Error("builder loop panic recovered",
				"panic", fmt.Sprintf("%v", r),
				"stack", string(buf[:n]),
			)
			retErr = fmt.Errorf("builder/loop: panic: %v", r)
		}
	}()

	bl.logger.Info("builder loop started",
		"log_did", bl.cfg.LogDID,
		"batch_size", bl.cfg.BatchSize,
		"poll_interval", bl.cfg.PollInterval,
	)

	if err := ctx.Err(); err != nil {
		return nil
	}
	recovered, err := bl.reader.RecoverOnStartup(ctx)
	if err != nil {
		if isContextError(err) {
			bl.logger.Info("builder loop stopped during recovery")
			return nil
		}
		return fmt.Errorf("builder/loop: recover on startup: %w", err)
	}
	if recovered > 0 {
		bl.logger.Warn("recovered stale queue entries", "count", recovered)
	}

	for {
		if err := ctx.Err(); err != nil {
			bl.logger.Info("builder loop stopped",
				"batches", bl.totalBatches.Load(),
				"entries", bl.totalEntries.Load(),
				"errors", bl.totalErrors.Load(),
			)
			return nil
		}

		processed, err := bl.processBatch(ctx)

		if err != nil {
			if isContextError(err) {
				bl.logger.Info("builder loop stopped",
					"batches", bl.totalBatches.Load(),
					"entries", bl.totalEntries.Load(),
				)
				return nil
			}
			// LIVENESS GUARD — Tessera shutdown is a one-way state
			// transition. Treat the same as ctx-cancel: clean exit,
			// no error log, no consecutive_errors bump. Same restart-
			// recovery story as the sequencer (see
			// sequencer/loop.go::handleEntryError): entries stay in
			// WAL StatePending, antispam dedupes on next-process
			// AppendLeaf. The matching boundary translation lives in
			// tessera/embedded_appender.go::AppendLeaf; the pinning
			// test is TestEmbeddedAppender_AppendLeaf_TypedShutdownError.
			if errors.Is(err, optessera.ErrAppenderShutdown) {
				bl.logger.Info("builder loop stopped — tessera appender shut down",
					"batches", bl.totalBatches.Load(),
					"entries", bl.totalEntries.Load(),
				)
				return nil
			}

			bl.totalErrors.Add(1)
			consecutive := bl.consecutiveErr.Add(1)

			bl.logger.Error("batch processing failed",
				"error", err,
				"consecutive_errors", consecutive,
			)

			backoff := bl.cfg.PollInterval * time.Duration(min(int(consecutive), 10))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}

		bl.consecutiveErr.Store(0)

		if processed > 0 {
			bl.totalBatches.Add(1)
			bl.totalEntries.Add(int64(processed))
			continue
		}

		select {
		case <-ctx.Done():
			bl.logger.Info("builder loop stopped",
				"batches", bl.totalBatches.Load(),
				"entries", bl.totalEntries.Load(),
			)
			return nil
		case <-time.After(bl.cfg.PollInterval):
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 5) processBatch — one builder cycle, fully atomic
// -------------------------------------------------------------------------------------------------

func (bl *BuilderLoop) processBatch(ctx context.Context) (int, error) {
	var priorRoot [32]byte
	var priorSeq uint64 // committed_through_seq read at batch start; the CAS guard at commit
	if bl.rootStore != nil {
		// Authoritative path: read priorRoot from smt_root_state.
		// The persisted root is the source of truth across builder
		// restarts; the in-memory tree.rootHash mirrors it after each
		// successful commit.
		st, err := bl.rootStore.Read(ctx)
		if err != nil {
			return 0, fmt.Errorf("read smt root state: %w", err)
		}
		priorRoot = st.CurrentRoot
		priorSeq = st.CommittedThroughSeq

		// Max-lag backpressure (the Tile Clock): if the durable tile frontier has
		// fallen too far behind the commit cursor, hold the cursor so the
		// reconciler can catch up. Bounds the in-memory tail — and therefore
		// restart-recovery time. Like the witness HARD-STALL it stalls the writer
		// (admission's MaxBuilderLag then 503s); it never corrupts.
		if bl.tileFrontier != nil && bl.maxTileLag > 0 {
			if fSeq, _, fErr := bl.tileFrontier.ReadFrontier(ctx); fErr != nil {
				bl.logger.Warn("max-lag gate: read tile frontier failed; proceeding", "error", fErr)
			} else if tileLagExceeded(st.CommittedThroughSeq, fSeq, bl.maxTileLag) {
				bl.logger.Warn("builder backpressure: tile frontier too far behind; holding the cursor until the reconciler catches up",
					"committed_seq", st.CommittedThroughSeq, "frontier_seq", fSeq, "max_lag", bl.maxTileLag)
				return 0, nil
			}
		}
	} else {
		var err error
		priorRoot, err = bl.tree.Root(ctx)
		if err != nil {
			return 0, fmt.Errorf("prior root: %w", err)
		}
	}

	// ── Step 1: Dequeue batch ───────────────────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	beginStart := time.Now()
	var seqs []uint64
	dqErr := store.WithReadCommittedTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		var iErr error
		seqs, iErr = bl.reader.BeginBatch(ctx, tx, bl.cfg.BatchSize)
		return iErr
	})
	if dqErr != nil {
		return 0, fmt.Errorf("dequeue: %w", dqErr)
	}
	if len(seqs) == 0 {
		return 0, nil
	}
	beginDur := time.Since(beginStart)

	// Contiguity check on the dequeued seqs. BeginBatch returns
	// `WHERE seq > cursor ORDER BY seq ASC LIMIT N`, so the result
	// should be a contiguous run [cursor+1, cursor+N] when the
	// sequencer has gap-free entry_index visibility. Non-contiguous
	// returns mean entry_index has a transient hole — usually from
	// per-entry-tx commits in sequencer.processOne landing out of
	// order. CommitBatch advances cursor to max(seqs), so any
	// non-contiguous return causes the cursor to LEAPFROG over the
	// missing seqs; once that happens those seqs are skipped
	// forever (the next BeginBatch's `seq > cursor` filter excludes
	// them when they finally commit).
	//
	// firstSeq / lastSeq derived from the ASC-ordered slice; the
	// prior cursor value is implicitly firstSeq-1 because BeginBatch
	// returns rows strictly greater than cursor.
	firstSeq := seqs[0]
	lastSeq := seqs[len(seqs)-1]
	priorCursor := int64(firstSeq) - 1
	expectedIfContiguous := int(lastSeq - firstSeq + 1)
	contiguous := expectedIfContiguous == len(seqs)
	gapsInBatch := expectedIfContiguous - len(seqs)
	if !contiguous {
		// WARN — this is the leapfrog-imminent moment. Surface the
		// first ~16 seqs returned so the operator can correlate the
		// gap pattern with sequencer commit order. The full set is
		// reconstructable from prior commits via firstSeq..lastSeq.
		previewN := len(seqs)
		if previewN > 16 {
			previewN = 16
		}
		bl.logger.Warn("BeginBatch returned non-contiguous seqs — cursor will leapfrog on commit",
			"prior_cursor", priorCursor,
			"first_seq", firstSeq,
			"last_seq", lastSeq,
			"count", len(seqs),
			"expected_if_contiguous", expectedIfContiguous,
			"gaps_in_batch", gapsInBatch,
			"preview_seqs", seqs[:previewN],
		)
	}

	// ── Step 2: Fetch entries in sequence order ──────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	fetchStart := time.Now()
	metas := make([]*types.EntryWithMetadata, 0, len(seqs))
	for _, seq := range seqs {
		p := types.LogPosition{LogDID: bl.cfg.LogDID, Sequence: seq}
		meta, fetchErr := bl.fetcher.Fetch(ctx, p)
		if fetchErr != nil || meta == nil {
			return 0, fmt.Errorf("fetch seq=%d: not found or error: %w", seq, fetchErr)
		}
		metas = append(metas, meta)
	}
	fetchDur := time.Since(fetchStart)

	// ── Step 3: Split EntryWithMetadata → entries + positions ─────────
	entries := make([]*envelope.Entry, len(metas))
	positions := make([]types.LogPosition, len(metas))
	for i, ewm := range metas {
		entry, desErr := envelope.Deserialize(ewm.CanonicalBytes)
		if desErr != nil {
			return 0, fmt.Errorf("deserialize seq=%d: %w", seqs[i], desErr)
		}
		entries[i] = entry
		positions[i] = ewm.Position
	}

	// ── Step 4: SDK ProcessBatch (overlay-backed) ───────────────────
	//
	// Both stores are wrapped in overlays so pre-commit failures (Tessera
	// AppendLeaf, witness cosignature, downstream PG error) leave the
	// persistent leafStore + nodeStore untouched. On commit success the
	// overlay mutations are extracted and persisted atomically below.
	overlayLeaves := smt.NewOverlayLeafStore(bl.leafStore)
	overlayNodes := smt.NewOverlayNodeStore(bl.nodeStore)
	overlayTree := smt.NewTree(overlayLeaves, overlayNodes)
	overlayTree.SetRoot(priorRoot)

	processStart := time.Now()
	result, err := sdkbuilder.ProcessBatch(
		ctx,
		overlayTree, entries, positions,
		bl.fetcher, bl.schema, bl.cfg.LogDID, bl.buffer,
	)
	if err != nil {
		return 0, fmt.Errorf("ProcessBatch: %w", err)
	}
	processDur := time.Since(processStart)

	// ── Step 5: Append entry identities to the Merkle tree ────────────
	//
	// SDK alignment: send envelope.EntryIdentity(entry) — the 32-byte SHA-256 of
	// the entry's canonical bytes. Tessera wraps it with the RFC 6962 leaf prefix
	// (0x00) internally and is idempotent via antispam (re-Add of the same
	// identity returns the same index), so retrying a batch produces no duplicate
	// state.
	//
	// Cosign + horizon publication no longer happen here. They are owned by the
	// CheckpointLoop (builder/checkpoint_loop.go), which cosigns a head over an
	// already-durable root, LAGGING this commit. The builder's contract is now
	// just: admit → commit SMT + advance cursor. Witnesses gate the checkpoint,
	// never ingestion.
	appendStart := time.Now()
	if bl.merkle != nil {
		for i, ewm := range metas {
			identity, idErr := envelope.EntryIdentity(entries[i])
			if idErr != nil {
				return 0, fmt.Errorf("EntryIdentity seq=%d: %w",
					ewm.Position.Sequence, idErr)
			}
			if _, appendErr := bl.merkle.AppendLeaf(ctx, identity[:]); appendErr != nil {
				return 0, fmt.Errorf("tessera AppendLeaf seq=%d: %w",
					ewm.Position.Sequence, appendErr)
			}
		}
	}
	appendDur := time.Since(appendStart)

	// ── Steps 6-7 (cosign) — REMOVED, moved to the CheckpointLoop ─────
	//
	// The witness cosignature and horizon publication no longer run on the commit
	// hot path. The CheckpointLoop (builder/checkpoint_loop.go) cosigns a head
	// over an already-durable (tiled) root, LAGGING this commit, so the published
	// horizon's SMTRoot always has its tiles present — the single-clock invariant.
	// The builder therefore does not wait on a Tessera head, bind an SMT/receipt
	// root into a head, or request cosignatures here; it commits SMT state and
	// advances the cursor, and the checkpoint loop catches up asynchronously.

	// ── Step 8a: New SMT root (v0.3.0 — produced by ProcessBatch) ────
	//
	// In v0.3.0, ProcessBatch advances the overlay tree's rootHash
	// incrementally via SDK Tree.SetLeaves → jellyfishInsert (O(log N)
	// node writes per leaf, exactly 2N-1 nodes total for N live leaves).
	// result.NewRoot is therefore the committed-after-this-batch root
	// already — no materialisation, no extra walk.
	//
	// The overlay's node store captured every dirty node along the
	// insert paths; we extract those below and hand them to the in-memory
	// node tail (TailedNodeStore) AFTER the commit — they are NOT written
	// to PG (de-pollution). The reconciler folds the tail into
	// content-addressed tiles; on crash the DAG is re-derived from
	// smt_leaves, so this is never data loss.
	newRoot := result.NewRoot
	var maxBatchSeq uint64
	for _, s := range seqs {
		if s > maxBatchSeq {
			maxBatchSeq = s
		}
	}

	// Snapshot the overlay's node mutations reachable from the new committed root,
	// BEFORE entering the atomic transaction. ReachableMutations (NOT Mutations) excludes
	// the intermediate node versions SetLeaves buffers and then supersedes mid-batch —
	// each jellyfishInsert rewrites the root path, so a 64-entry batch buffers ~63 dead
	// intermediate roots + their branches. Those are unreachable from newRoot and thus
	// never tiled, so promoting them into the in-memory tail would leak O(inserts × depth)
	// orphaned nodes the durability-gated prune can never reclaim (the writer-OOM). The
	// reachable set is exactly the final-tree delta — every node the committed root
	// references for a servable proof, and nothing else.
	dirtyNodes := overlayNodes.ReachableMutations(newRoot)

	// Pre-build the leaf slice and node slice OUTSIDE the atomic tx
	// so the tx's wire critical section is as short as possible (a
	// long-running tx blocks vacuum and inflates dead-tuple bloat on
	// builder_cursor + smt_leaves). All of the serialization /
	// allocation work happens here; the tx body below is just three
	// batched INSERTs + the singleton-row UPDATEs.
	leavesToWrite := coalesceLeafMutations(result.Mutations)
	nodesToWrite := make([]smt.Node, 0, len(dirtyNodes))
	for _, n := range dirtyNodes {
		nodesToWrite = append(nodesToWrite, n)
	}

	// ── Step 8: Atomic commit ───────────────────────────────────
	if cErr := ctx.Err(); cErr != nil {
		return 0, cErr
	}

	var leavesAffected, nodesAffected int64
	commitStart := time.Now()
	commitErr := store.WithSerializableTx(ctx, bl.db, func(ctx context.Context, tx pgx.Tx) error {
		// Leaves first — every mutation produced by ProcessBatch
		// becomes a row in smt_leaves. SetBatchTx collapses the N
		// row-upserts into ONE round-trip via `unnest($1::bytea[],
		// $2::bytea[], $3::bytea[])`. This is THE per-batch latency
		// fix: the prior `for _, mut := range result.Mutations` loop
		// paid one synchronous PG hop per leaf, capping builder
		// throughput at ~loop-overhead × per-row-rtt ≈ ~200 ent/sec
		// even with cosign fully parallel.
		var setErr error
		leavesAffected, setErr = bl.leafStore.SetBatchTx(ctx, tx, leavesToWrite)
		if setErr != nil {
			return fmt.Errorf("set leaves batch (n=%d): %w", len(leavesToWrite), setErr)
		}
		// Invariant: every input leaf is either inserted (new key)
		// or updated (existing key) — PG counts both as 1 affected
		// row under ON CONFLICT DO UPDATE. A mismatch is pathological
		// and means the in-batch slice had a duplicate leaf_key
		// (which sha256(LogDID||seq) makes near-impossible across
		// distinct seqs). Surface it loudly inside the tx so we see
		// the exact batch.
		if leavesAffected != int64(len(leavesToWrite)) {
			bl.logger.Warn("SetBatchTx rows-affected mismatch — leaves silently collapsed via ON CONFLICT",
				"input_leaves", len(leavesToWrite),
				"rows_affected", leavesAffected,
				"collapsed", int64(len(leavesToWrite))-leavesAffected,
				"first_seq", firstSeq,
				"last_seq", lastSeq,
			)
		}

		// De-pollution: the Jellyfish node DAG is NOT written to PG. The atomic tx
		// is leaves + root + cursor (the irreducible state). The batch's dirty nodes
		// are handed to the in-memory tail post-commit (bl.nodeStore.PutBatch below)
		// and tiled by the reconciler; lost on crash → re-derived from smt_leaves on
		// boot (recovery). root = f(smt_leaves), so this is never data loss.

		// New root atomic with leaves so readers never see a
		// {root, store} mismatch. CAS on (priorRoot, priorSeq) read at batch start:
		// a mismatch means another writer advanced the root, so abort rather than
		// clobber a newer root with this batch's older one (ErrRootCASMismatch).
		if bl.rootStore != nil {
			if rErr := bl.rootStore.SetTxCAS(ctx, tx, newRoot, maxBatchSeq, priorRoot, priorSeq); rErr != nil {
				return fmt.Errorf("set smt root state: %w", rErr)
			}
		}

		if bl.bufferStore != nil && result.UpdatedBuffer != nil {
			if bufErr := bl.bufferStore.SaveTx(ctx, tx, result.UpdatedBuffer); bufErr != nil {
				return fmt.Errorf("save buffer: %w", bufErr)
			}
		}

		// commit_intent — emitted INSIDE the atomic tx, immediately
		// before CommitBatch advances the cursor. Pairs with the
		// BeginBatch-side contiguity log to give end-to-end evidence
		// of every cursor movement. Especially useful at leapfrog
		// time: if `delta > count` the cursor advanced further than
		// the seq count justifies, and the difference is the number
		// of seqs lost.
		bl.logger.Info("commit_intent",
			"prior_cursor", priorCursor,
			"new_cursor", lastSeq,
			"delta", int64(lastSeq)-priorCursor,
			"seqs_count", len(seqs),
			"contiguous", contiguous,
			"leaves_in_tx", len(leavesToWrite),
			"nodes_in_tx", len(nodesToWrite),
		)
		if qErr := bl.reader.CommitBatch(ctx, tx, seqs); qErr != nil {
			return fmt.Errorf("commit batch: %w", qErr)
		}

		return nil
	})
	if commitErr != nil {
		return 0, fmt.Errorf("atomic commit: %w", commitErr)
	}
	commitDur := time.Since(commitStart)

	// Advance the read-side tree's rootHash to match the persisted
	// state. API handlers reading from bl.tree now observe the new
	// root. (The handler's Tree shares the same TailedNodeStore and
	// PostgresLeafStore; SetRoot is the in-memory cursor.)
	bl.tree.SetRoot(newRoot)

	// De-pollution handoff: the batch's dirty nodes go to the in-memory tail (NOT
	// PG), so the next batch reads them as siblings until the reconciler tiles them
	// and prunes. Lost on crash → re-derived from smt_leaves on boot (recovery).
	// PutBatchCommitted (not PutBatch): record newRoot atomically with the nodes so
	// the checkpoint loop's orphan-prune can walk from a root always consistent
	// with the tail (race-free; see TailedNodeStore.PruneOrphans).
	bl.nodeStore.PutBatchCommitted(nodesToWrite, newRoot)
	nodesAffected = int64(len(nodesToWrite))

	// ───────────────────────────────────────────────────────────────────────
	// POST-COMMIT: best-effort publishing. Failure here doesn't roll
	// back the durable Postgres + Tessera + tree-head-sigs state.
	// ───────────────────────────────────────────────────────────────

	// ── SMT tiles + horizon: owned by the CheckpointLoop, NOT here ────
	// Tile emission and cosigned-checkpoint publication are done by the async
	// builder.CheckpointLoop (builder/checkpoint_loop.go): it makes every SMT tile
	// reachable from the committed root durable (EmitDurable), advances the durable
	// tile_frontier ONLY after that PUT-ack, and publishes the horizon gated on the
	// frontier — so a published root never advertises an SMTRoot whose tiles are
	// missing. Keeping that off the commit hot path is what makes admission melt-proof
	// under a blob-store outage (the commit cursor keeps advancing; the frontier holds).
	// The builder's only contract with the tile world: the atomic tx above persists
	// smt_leaves + root + cursor — NOT the node DAG (see the de-pollution note) — and
	// root = f(smt_leaves), so the CheckpointLoop can (re)derive every tile from
	// smt_leaves. The dirty nodes handed to the in-memory tail (bl.nodeStore.PutBatch
	// below) are a read-cache optimization, lost on crash and re-derived on boot
	// (RecoverTail). See store/{tile_emitter,tile_frontier}.go + builder/checkpoint_loop.go.

	// ── Step 10: Publish derivation commitment ───────────────────────
	if bl.commitPub != nil && len(positions) > 0 {
		bl.commitPub.MaybePublish(ctx, len(seqs),
			positions[0], positions[len(positions)-1],
			priorRoot, result)
	}

	if result.UpdatedBuffer != nil {
		bl.buffer = result.UpdatedBuffer
	}

	// Per-stage timing — surfaces which step dominates each batch.
	// Stages match the inline section headers above:
	//   begin     = Step 1  (BeginBatch dequeue)
	//   fetch     = Step 2  (PG entry fetch loop)
	//   process   = Step 4  (SDK ProcessBatch — overlay SMT mutations)
	//   append    = Step 5  (Tessera AppendLeaf loop)
	//   commit    = Step 8  (atomic PG tx: leaves+nodes+root+buffer+cursor+fsync)
	// total = sum of the above; gives the per-batch latency floor. (Cosign is no
	// longer on this path — it lags in the CheckpointLoop.)
	//
	// leaves_written / nodes_written verify the N+1 fix landed: every batch
	// must show ONE log line covering leaves_written N AND nodes_written M,
	// NOT N+M separate round-trips. Pair leaves_written with `commit` duration
	// to compute the effective LEAF-write throughput of SetBatchTx (the batched
	// PG tx); a regression to per-row SetTx would show up immediately as commit
	// climbing back into the seconds. nodes_written M is the in-memory tail
	// handoff (bl.nodeStore.PutBatch) — NOT a PG write (de-pollution), so it
	// never loads the commit tx.
	//
	// process_per_leaf / nodes_per_leaf / cum_seq answer the SCALING
	// question: at 10M leaves, does the SDK's jellyfishInsert path
	// remain constant-time per leaf? The Jellyfish-Patricia tree's
	// theoretical depth is ⌈log2(N)⌉ ≈ 23 at N=10M, so per-leaf node
	// touches should converge to ~24 in steady state regardless of
	// cum_seq. A rising process_per_leaf with cum_seq names PG /
	// LRU cache thrash; a flat curve names "constant per leaf as
	// designed". Either way the decision is data-driven.
	processPerLeafUs := int64(0)
	nodesPerLeaf := float64(0)
	if len(seqs) > 0 {
		processPerLeafUs = processDur.Microseconds() / int64(len(seqs))
		nodesPerLeaf = float64(nodesAffected) / float64(len(seqs))
	}
	// cum_seq = sequences processed before this batch + this batch.
	// Used as a proxy for "cumulative SMT working set"; SMT root is
	// monotonically advancing with seqs so this directly characterises
	// the test's scale axis when comparing log lines across cycles.
	cumSeqs := bl.totalEntries.Load() + int64(len(seqs))
	totalDur := beginDur + fetchDur + processDur + appendDur + commitDur
	bl.logger.Info("batch processed",
		"entries", len(seqs),
		"new_leaves", result.NewLeafCounts,
		"leaves_written", len(leavesToWrite),
		"leaves_affected", leavesAffected,
		"nodes_written", len(nodesToWrite),
		"nodes_affected", nodesAffected,
		"nodes_skipped_existing", int64(len(nodesToWrite))-nodesAffected,
		"process_per_leaf_us", processPerLeafUs,
		"nodes_per_leaf", fmt.Sprintf("%.2f", nodesPerLeaf),
		"cum_seq", cumSeqs,
		"path_a", result.PathACounts,
		"path_b", result.PathBCounts,
		"path_c", result.PathCCounts,
		"path_d", result.PathDCounts,
		"commentary", result.CommentaryCounts,
		"contiguous", contiguous,
		"begin", beginDur.Round(time.Microsecond),
		"fetch", fetchDur.Round(time.Microsecond),
		"process", processDur.Round(time.Microsecond),
		"append", appendDur.Round(time.Microsecond),
		"commit", commitDur.Round(time.Microsecond),
		"total", totalDur.Round(time.Microsecond),
	)

	return len(seqs), nil
}

// -------------------------------------------------------------------------------------------------
// 6) Observability
// -------------------------------------------------------------------------------------------------

func (bl *BuilderLoop) Stats() (batches, entries, errs int64) {
	return bl.totalBatches.Load(), bl.totalEntries.Load(), bl.totalErrors.Load()
}

// -------------------------------------------------------------------------------------------------
// 7) Helpers
// -------------------------------------------------------------------------------------------------

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// coalesceLeafMutations collapses the SDK's ORDERED per-entry mutation log
// (result.Mutations from Tree.StopTracking — one append per leaf write) into ONE
// SMTLeaf per leaf_key, keeping the LAST write.
//
// WHY: within a single builder batch the same leaf_key can be written more than
// once — a root and a same-batch amendment of it (Path A advances the origin tip on
// the SAME authority leaf), or several amendments of one authority. The atomic
// commit persists leaves via a single `INSERT … ON CONFLICT (leaf_key) DO UPDATE`
// statement (store.SetBatchTx), and Postgres rejects a statement that presents the
// same conflict key twice — "ON CONFLICT DO UPDATE command cannot affect row a
// second time" (SQLSTATE 21000) — which wedged the builder under high-throughput
// amendment load. The committed root (result.NewRoot, computed by the overlay tree
// after applying every mutation in order) reflects the FINAL state of each leaf, so
// keeping the last write per key persists exactly that — and keeps leaves_affected
// == len(leavesToWrite), so the post-commit collapse check stays a true invariant
// rather than firing on every amendment batch.
func coalesceLeafMutations(muts []types.LeafMutation) []types.SMTLeaf {
	leaves := make([]types.SMTLeaf, 0, len(muts))
	idx := make(map[[32]byte]int, len(muts))
	for _, m := range muts {
		leaf := types.SMTLeaf{
			Key:          m.LeafKey,
			OriginTip:    m.NewOriginTip,
			AuthorityTip: m.NewAuthorityTip,
		}
		if i, ok := idx[m.LeafKey]; ok {
			leaves[i] = leaf // same leaf written earlier in this batch — last write wins
			continue
		}
		idx[m.LeafKey] = len(leaves)
		leaves = append(leaves, leaf)
	}
	return leaves
}
