// FILE PATH: tests/rotation_appender_e2e_test.go
//
// End-to-end test for the PRODUCTION witnessclient.ProductionRotationAppender
// against REAL components — replacing the fakeRotationAppender coverage.
//
// PHYSICS, NOT MOCKS. Every artifact is real:
//   - a real tessera.EmbeddedAppender tree (tile bytes on a temp POSIX dir),
//   - a real K-of-N witness cosign round (httptest witness fixture over HTTP,
//     persisted to the real tree_heads via witnessclient.HeadSync),
//   - a real RFC 6962 inclusion proof from the real tessera.TesseraAdapter.
//
// The appender wraps a rotation payload in a ledger-signed envelope.Entry,
// drives it through the real sequencing effect (tessera.AppendLeaf — the exact
// call sequencer/loop.go makes) + a real witness cosign, builds the inclusion
// proof, binds the on-log-entry leaf (OnLogEntryLeafHash), and SELF-VERIFIES the
// proof against the real cosigned root before returning. We then re-verify via
// the SDK consumer path (witness.VerifyRotationInclusion — the exact check
// findings.WitnessRotationFinding.VerifyInclusion delegates to) and prove the
// leaf model + root binding are load-bearing via two mutations.
//
// Gated on BASEPROOF_TEST_DSN (Postgres); skips otherwise.
package tests

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	opbuilder "github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// singleLeafMerkle is the DETERMINISTIC, SELF-CONSISTENT Merkle half for the
// dual-commitment representative below: one leaf, whose RFC 6962 single-leaf
// tree root IS the leaf hash and whose inclusion proof is the empty path. It
// serves both seams that must agree — the checkpoint loop's CheckpointRooter
// (RootAtSize / IntegratedSize) and the appender's proof builder — so the
// appender's self-verify reconstructs to exactly the root the loop bound into
// the cosigned head. Deliberately fake-but-consistent: the REAL-Merkle join
// (tessera tiles + this loop at one size) is PR-1.5's capstone; this test's
// concern is the dual-commitment cosign path, with zero tessera-alignment
// exposure. It NEVER builds a head — only the loop's named factory does.
type singleLeafMerkle struct {
	mu       sync.Mutex
	leafHash [32]byte
	size     uint64 // 0 until the leaf integrates, then 1
}

func (m *singleLeafMerkle) integrate(leaf [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.leafHash, m.size = leaf, 1
}

func (m *singleLeafMerkle) IntegratedSize(context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.size, nil
}

func (m *singleLeafMerkle) RootAtSize(_ context.Context, treeSize uint64) ([32]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if treeSize != 1 || m.size != 1 {
		return [32]byte{}, fmt.Errorf("singleLeafMerkle: root requested at size %d (integrated %d); only 1 exists", treeSize, m.size)
	}
	return m.leafHash, nil // RFC 6962: the single-leaf tree's root IS the leaf hash
}

// TypedInclusionProof is the appender's proof seam: the single leaf's proof is
// the empty audit path (LeafHash is bound by the appender itself).
func (m *singleLeafMerkle) TypedInclusionProof(position, treeSize uint64) (*types.MerkleProof, error) {
	if position != 0 || treeSize != 1 {
		return nil, fmt.Errorf("singleLeafMerkle: proof requested at (%d,%d); only (0,1) exists", position, treeSize)
	}
	return &types.MerkleProof{LeafPosition: 0, TreeSize: 1, Siblings: nil}, nil
}

// horizonRecorder captures the heads the checkpoint loop publishes (the driver
// goroutine writes; the test reads after the driver exits).
type horizonRecorder struct {
	mu    sync.Mutex
	heads []types.CosignedTreeHead
}

func (r *horizonRecorder) PublishCosignedCheckpoint(_ context.Context, head types.CosignedTreeHead) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.heads = append(r.heads, head)
	return nil
}

func (r *horizonRecorder) published() []types.CosignedTreeHead {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]types.CosignedTreeHead(nil), r.heads...)
}

// checkpointDrivenPipeline backs the appender's submit + seq-lookup seams the
// way production does: Submit assigns the leaf and commits the SMT batch —
// and NOTHING ELSE. No head is built here (the harness-drift incident): the
// cosigned covering head appears only when the REAL CheckpointLoop's named
// factory builds it from the committed cursor and the REAL validating witness
// cosigns it, asynchronously, exactly as in a live ledger.
type checkpointDrivenPipeline struct {
	pool    *pgxpool.Pool
	tree    *smt.Tree
	merkle  *singleLeafMerkle
	logDID  string
	seqByID map[[32]byte]uint64
}

func (p *checkpointDrivenPipeline) Submit(
	ctx context.Context, hash [32]byte, wire []byte, _ int64, _ []types.Web3VerificationReceipt,
) error {
	const seq = uint64(0) // first leaf of the fresh log
	p.seqByID[hash] = seq

	// Commit the entry's SMT leaf — the builder's atomic-commit effect: the
	// tree mutates, then smt_root_state records (root, committed_through_seq).
	pos := types.LogPosition{LogDID: p.logDID, Sequence: seq}
	if err := p.tree.SetLeaves(ctx, []types.SMTLeaf{{Key: hash, OriginTip: pos, AuthorityTip: pos}}); err != nil {
		return fmt.Errorf("SetLeaves: %w", err)
	}
	root, err := p.tree.Root(ctx)
	if err != nil {
		return fmt.Errorf("tree.Root: %w", err)
	}
	if _, err := p.pool.Exec(ctx,
		`UPDATE smt_root_state SET current_root=$1, committed_through_seq=$2 WHERE id=1`,
		root[:], int64(seq),
	); err != nil {
		return fmt.Errorf("commit smt_root_state: %w", err)
	}

	// The Merkle half integrates the same entry at the same position — the
	// single-leaf RFC 6962 tree whose root is the on-log entry leaf hash.
	p.merkle.integrate(envelope.OnLogEntryLeafHash(wire))
	return nil
}

func (p *checkpointDrivenPipeline) FetchPrimarySeqByHash(_ context.Context, hash [32]byte) (uint64, bool, error) {
	seq, ok := p.seqByID[hash]
	return seq, ok, nil
}

// TestProductionRotationAppender_EndToEnd_RealLoopRealCosign is the
// DUAL-COMMITMENT CLASS REPRESENTATIVE (tier T2+, per-PR DB job): the cosigned
// covering head is produced by the REAL CheckpointLoop — its named factory
// building from the real committed SMT cursor — and signed by the REAL
// SDK-validating witness over HTTP. The harness fabricates NO head anywhere
// (the fixture-drift incident this replaces: the old pipeline cosigned a
// hand-built Merkle-only head whose all-zero SMTRoot every witness rejects).
// The appender starts against an EMPTY log and must HOLD-and-poll through the
// pre-first-checkpoint window (the exact boot flow #76's GenesisLogAppender
// standardizes), succeeding only when the loop publishes for real.
func TestProductionRotationAppender_EndToEnd_RealLoopRealCosign(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Clean genesis for the loop's singletons (same pattern as
	// checkpoint_integrity): commit cursor + frontier at the empty root.
	if _, err := pool.Exec(ctx, `UPDATE smt_root_state SET current_root=$1, committed_through_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset smt_root_state: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tile_frontier SET frontier_root=$1, frontier_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset tile_frontier: %v", err)
	}

	// REAL SMT half: in-memory tree, real commit cursor + frontier over PG,
	// real tile emitter onto a POSIX temp dir.
	leafStore := smt.NewInMemoryLeafStore()
	nodeStore := store.NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(leafStore, nodeStore)
	tree.SetRoot(smt.EmptyHash)
	rootStore := store.NewSMTRootStateStore(pool)
	tileStore := store.NewPosixSMTTileStore(t.TempDir())

	// REAL validating witness (K=1) + REAL cosign client persisting to
	// tree_heads(pool) — the signer that rejects malformed heads.
	netID := nonZeroTestNetworkID()
	fixture := newWitnessFixture(t, netID, 1)
	headSync, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  fixture.URLs(),
		QuorumK:           1,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         netID,
		HTTPClient:        newTunedHTTPClient(2 * time.Second),
	}, store.NewTreeHeadStore(pool), logger)
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	// Self-consistent single-leaf Merkle half (see type doc): serves the loop's
	// rooter AND the appender's proof seam from one source of truth.
	merkle := &singleLeafMerkle{}
	recorder := &horizonRecorder{}

	// The REAL production loop — the only head producer in this test.
	loop := opbuilder.NewCheckpointLoop(
		store.NewSMTCommitCursor(rootStore),
		store.NewPgTileFrontier(pool),
		store.NewBuildTilesEmitter(nodeStore, tileStore),
		merkle, recorder, headSync, nil, 0, logger,
	)

	heads := store.NewTreeHeadStore(pool)

	// EMPTY-WINDOW PIN: over a genuinely empty log the loop HOLDS (genesis
	// gate) — no head is built, the witness is never asked, nothing persists.
	if err := loop.CheckpointOnce(ctx); err != nil {
		t.Fatalf("empty-log CheckpointOnce must hold (nil), got %v", err)
	}
	if row, err := heads.LatestCosigned(ctx, 1); err != nil || row != nil {
		t.Fatalf("empty log persisted a cosigned head (row=%v err=%v)", row, err)
	}

	const logDID = "did:web:ledger.rotation-e2e.test"
	pipe := &checkpointDrivenPipeline{
		pool: pool, tree: tree, merkle: merkle,
		logDID: logDID, seqByID: map[[32]byte]uint64{},
	}

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set, err := cosign.NewWitnessKeySet(fixture.PublicKeys(), netID, 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	appender := witnessclient.NewProductionRotationAppender(
		priv, logDID, logDID, quorum.NewManager(set),
		pipe,   // submitter — leaf assignment + SMT commit, NO head building
		pipe,   // seq lookup
		heads,  // real cosigned-head store (written by HeadSync via the loop)
		merkle, // proof seam — same source as the loop's rooter
		logger,
	).WithPolling(10*time.Millisecond, 30*time.Second)

	// Drive the production loop concurrently, as Run() would: the appender's
	// covering-head wait must tolerate the pre-first-checkpoint window and
	// resolve only when the real loop publishes. Loop faults (e.g. the
	// factory's invalid-head class) are collected and fail the test — the
	// boundary diagnoses harness mistakes instead of burning retries.
	driveCtx, stopDriving := context.WithCancel(ctx)
	defer stopDriving()
	loopErrs := make(chan error, 16)
	driverDone := make(chan struct{})
	go func() {
		defer close(driverDone)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-driveCtx.Done():
				return
			case <-tick.C:
				if err := loop.CheckpointOnce(driveCtx); err != nil && !errors.Is(err, context.Canceled) {
					select {
					case loopErrs <- err:
					default:
					}
				}
			}
		}
	}()

	payload := []byte("on-log witness-rotation payload fixture")
	canonical, pos, proof, err := appender.AppendRotationEntry(ctx, payload)
	stopDriving()
	<-driverDone
	if err != nil {
		t.Fatalf("AppendRotationEntry: %v", err)
	}
	select {
	case lerr := <-loopErrs:
		t.Fatalf("the production loop faulted while driving: %v", lerr)
	default:
	}

	// Bindings (the appender already self-verified the proof against the
	// cosigned root before returning).
	if want := envelope.OnLogEntryLeafHash(canonical); proof.LeafHash != want {
		t.Errorf("proof.LeafHash = %x, want OnLogEntryLeafHash(canonical) %x", proof.LeafHash, want)
	}
	if pos.LogDID != logDID || pos.Sequence != 0 {
		t.Errorf("pos = {%q %d}, want {%q 0}", pos.LogDID, pos.Sequence, logDID)
	}

	// THE DUAL-COMMITMENT PIN: the persisted covering head was built by the
	// loop's factory from the COMMITTED cursor — its SMTRoot is the real
	// committed root (non-zero), at the size the loop chose, carrying a REAL
	// validating witness's signature.
	committedRoot, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("tree.Root: %v", err)
	}
	row, err := heads.LatestCosigned(ctx, 1)
	if err != nil || row == nil {
		t.Fatalf("no cosigned covering head persisted (row=%v err=%v)", row, err)
	}
	if row.TreeSize != 1 {
		t.Errorf("cosigned head TreeSize = %d, want 1 (the loop's TreeSizeForCommittedSeq(0))", row.TreeSize)
	}
	if row.SMTRoot != committedRoot {
		t.Errorf("cosigned head SMTRoot = %x, want the committed cursor root %x (dual-commitment)", row.SMTRoot[:8], committedRoot[:8])
	}
	if row.SMTRoot == ([32]byte{}) {
		t.Error("cosigned head SMTRoot is all-zero — the incident shape must be impossible here")
	}

	published := recorder.published()
	if len(published) != 1 {
		t.Fatalf("loop published %d horizon(s), want exactly 1", len(published))
	}
	head := published[0].TreeHead
	if len(published[0].Signatures) < 1 {
		t.Fatal("published horizon carries no witness signatures")
	}

	// CONSUMER PATH: the SDK's positional verifier accepts the proof against
	// the published cosigned head — the check finding.VerifyInclusion runs.
	if err := witness.VerifyRotationInclusion(canonical, proof, head, pos); err != nil {
		t.Fatalf("VerifyRotationInclusion against the published cosigned head: %v", err)
	}

	// MUTATION 1 — the footgun leaf H(0x00||canonical) must be REJECTED, proving
	// the on-log leaf model H(0x00||SHA-256(canonical)) is load-bearing here.
	badLeaf := *proof
	badLeaf.LeafHash = envelope.EntryLeafHashBytes(canonical)
	if err := witness.VerifyRotationInclusion(canonical, &badLeaf, head, pos); err == nil {
		t.Error("footgun leaf H(0x00||canonical) was accepted — on-log leaf model not enforced")
	}

	// MUTATION 2 — a tampered cosigned root must be REJECTED, proving the proof
	// is bound to the REAL cosigned root, not a fabricated one.
	badHead := head
	badHead.RootHash[0] ^= 0xFF
	if err := witness.VerifyRotationInclusion(canonical, proof, badHead, pos); err == nil {
		t.Error("proof verified against a tampered root — not bound to the real cosigned head")
	}
}

// appendOnlyTreePipeline backs the appender's submit + seq seams against a REAL
// Tessera tree with NO Postgres and NO witness fixture: Submit performs the real
// tessera.AppendLeaf (the sequencer's leaf-assigning operation) and records the
// real index. Used by the runnable (DB-free) variant below.
type appendOnlyTreePipeline struct {
	h       *tesseraHarness
	seqByID map[[32]byte]uint64
}

func (p *appendOnlyTreePipeline) Submit(
	ctx context.Context, hash [32]byte, _ []byte, _ int64, _ []types.Web3VerificationReceipt,
) error {
	seq, err := p.h.Embedded.AppendLeaf(ctx, hash[:])
	if err != nil {
		return err
	}
	p.seqByID[hash] = seq
	return nil
}

func (p *appendOnlyTreePipeline) FetchPrimarySeqByHash(_ context.Context, hash [32]byte) (uint64, bool, error) {
	seq, ok := p.seqByID[hash]
	return seq, ok, nil
}

// realTreeHeadSource returns the REAL Tessera tree head (real TreeSize + real
// RootHash) as the appender's "cosigned head". The appender and the SDK
// inclusion verifier consume only (TreeSize, RootHash); witness-signature
// verification is a SEPARATE check (finding.Verify), not part of the inclusion
// proof — so this faithfully exercises the appender's proof path without the
// Postgres-backed cosign persistence.
type realTreeHeadSource struct{ h *tesseraHarness }

func (s *realTreeHeadSource) LatestCosigned(_ context.Context, _ int) (*store.CosignedTreeHead, error) {
	head, err := s.h.Embedded.Head()
	if err != nil {
		return nil, err
	}
	return &store.CosignedTreeHead{TreeSize: head.TreeSize, RootHash: head.RootHash}, nil
}

// TestProductionRotationAppender_RealTree_ReconstructsToRoot runs WITHOUT
// Postgres: it drives the production appender against a REAL Tessera tree and a
// REAL RFC 6962 inclusion proof, proving the proof reconstructs to the real
// tree root with the on-log-entry leaf binding. Complements the DB-gated
// real-witness-cosign test above (which adds the full cosign-persistence path).
func TestProductionRotationAppender_RealTree_ReconstructsToRoot(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// REAL EmbeddedAppender tree over a fresh temp POSIX tile dir. No DB.
	h := newTesseraHarness(t, ctx, logger)

	pipe := &appendOnlyTreePipeline{h: h, seqByID: map[[32]byte]uint64{}}
	headSrc := &realTreeHeadSource{h: h}

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const logDID = "did:web:ledger.rotation-realtree.test"

	appender := witnessclient.NewProductionRotationAppender(
		priv, logDID, logDID,
		quorum.NewManager(nil), // Current()==nil → minSigs defaults to 1
		pipe, pipe, headSrc, h.Adapter, logger,
	).WithPolling(5*time.Millisecond, 5*time.Second)

	payload := []byte("on-log witness-rotation payload fixture")
	canonical, pos, proof, err := appender.AppendRotationEntry(ctx, payload)
	if err != nil {
		t.Fatalf("AppendRotationEntry: %v", err)
	}

	// Reaching here proves the appender's internal smt.VerifyMerkleInclusion
	// against the REAL tree root succeeded. Cross-checks + bindings:
	if want := envelope.OnLogEntryLeafHash(canonical); proof.LeafHash != want {
		t.Errorf("proof.LeafHash = %x, want OnLogEntryLeafHash(canonical) %x", proof.LeafHash, want)
	}
	if pos.Sequence != 0 || pos.LogDID != logDID {
		t.Errorf("pos = {LogDID:%q Seq:%d}, want {%q 0}", pos.LogDID, pos.Sequence, logDID)
	}

	head, err := h.Embedded.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if err := witness.VerifyRotationInclusion(canonical, proof, head, pos); err != nil {
		t.Fatalf("VerifyRotationInclusion against the real tree root: %v", err)
	}

	// MUTATION 1 — footgun leaf H(0x00||canonical) must be rejected.
	badLeaf := *proof
	badLeaf.LeafHash = envelope.EntryLeafHashBytes(canonical)
	if err := witness.VerifyRotationInclusion(canonical, &badLeaf, head, pos); err == nil {
		t.Error("footgun leaf H(0x00||canonical) was accepted — on-log leaf model not enforced")
	}

	// MUTATION 2 — tampered root must be rejected (proof bound to the real root).
	badHead := head
	badHead.RootHash[0] ^= 0xFF
	if err := witness.VerifyRotationInclusion(canonical, proof, badHead, pos); err == nil {
		t.Error("proof verified against a tampered root — not bound to the real tree root")
	}
}

// TestProductionRotationAppender_RealTree_ImperfectScale is the SCALE regression
// for the RFC-6962 inclusion-proof fix (baseproof v1.41.0). The appender
// self-verifies its inclusion proof via smt.VerifyMerkleInclusion before
// returning (rotation_appender.go:206). Pre-v1.41.0 that verifier rejected ~27%
// of valid proofs on IMPERFECT (non-power-of-two) trees — so a rotation
// committed at a "bad-position" leaf in a realistic-size tree would falsely fail
// self-verify and the rotation could not be committed on-log.
//
// This drives the production appender against a real tree of NON-POWER-OF-TWO
// size with hundreds of leaves BEFORE the rotation (an interior position with a
// deep, multi-sibling co-path — the regime the bug lived in), and asserts the
// rotation commits + its proof reconstructs to the real root. At v1.40.1 this
// fails intermittently by leaf position; at v1.42.0 it passes deterministically.
//
// The existing RealTree test rotates at leaf 0 (a 1-leaf tree) and never
// exercises the imperfect-tree co-path — exactly the scale blindness that let
// the SMT bug survive (see e2e-tests issue #24).
func TestProductionRotationAppender_RealTree_ImperfectScale(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()
	h := newTesseraHarness(t, ctx, logger)

	pipe := &appendOnlyTreePipeline{h: h, seqByID: map[[32]byte]uint64{}}
	headSrc := &realTreeHeadSource{h: h}

	// Pre-fill the tree with a deliberately NON-POWER-OF-TWO count of ordinary
	// leaves so the rotation lands at a deep interior position with a real
	// multi-level co-path, and the right edge is imperfect (partial tiles +
	// orphan-promoted subtrees — the previously-buggy branch).
	const fillBefore = 999 // 999 + 1 rotation = 1000 leaves (not 2^k)
	for i := 0; i < fillBefore; i++ {
		var d [32]byte
		copy(d[:], []byte(fmt.Sprintf("filler-leaf-%d", i)))
		if _, err := h.Embedded.AppendLeaf(ctx, d[:]); err != nil {
			t.Fatalf("AppendLeaf filler %d: %v", i, err)
		}
	}

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const logDID = "did:web:ledger.rotation-imperfect-scale.test"
	appender := witnessclient.NewProductionRotationAppender(
		priv, logDID, logDID,
		quorum.NewManager(nil),
		pipe, pipe, headSrc, h.Adapter, logger,
	).WithPolling(5*time.Millisecond, 10*time.Second)

	canonical, pos, proof, err := appender.AppendRotationEntry(ctx, []byte("imperfect-scale rotation payload"))
	if err != nil {
		// At v1.40.1 (buggy verifier) this is exactly where a bad-position
		// rotation fails: "built proof does not reconstruct to cosigned root".
		t.Fatalf("AppendRotationEntry at imperfect scale failed (the SMT-bug regime): %v", err)
	}

	// The rotation landed at an interior, non-zero position with a deep co-path.
	if pos.Sequence != uint64(fillBefore) {
		t.Errorf("rotation pos = %d, want %d (interior)", pos.Sequence, fillBefore)
	}
	if len(proof.Siblings) < 8 {
		t.Errorf("proof has %d siblings; want a deep co-path (>=8) proving a real interior position, not a toy", len(proof.Siblings))
	}

	// Independently re-verify against the real tree head (the consumer path).
	head, err := h.Embedded.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head.TreeSize != uint64(fillBefore)+1 {
		t.Errorf("tree size = %d, want %d (non-power-of-two)", head.TreeSize, fillBefore+1)
	}
	if err := witness.VerifyRotationInclusion(canonical, proof, head, pos); err != nil {
		t.Fatalf("imperfect-scale rotation proof failed to reconstruct to the real root: %v", err)
	}
}

// TestProductionRotationAppender_RealTree_MultiRotationHorizons is the
// MULTI-ROTATION regression the single-rotation tests above do not cover. It
// commits a SEQUENCE of witness rotations at growing, deliberately
// NON-power-of-two horizons over one real tree, then — AFTER the live head has
// advanced well past every rotation — rebuilds each historical rotation's
// inclusion proof bound to ITS OWN horizon (the auditor's
// GET .../proof?tree_size=horizon path; api/tree.go:160-182) and proves it
// still reconstructs to that horizon's captured root.
//
// WHY THIS MATTERS. A rotation is committed against the witness-COSIGNED head
// that covers it; that head is the rotation's HORIZON, and it lags the live,
// un-cosigned head. An auditor rebuilding the rotation chain asks each
// historical proof against its own horizon size, NOT the live head — so the
// load-bearing property is: a proof re-derived at a PAST tree size, long after
// the tree has grown, still reconstructs to the PAST root. A single rotation at
// seq 0 (RealTree) or one interior rotation (ImperfectScale) never exercises
// re-derivation across MULTIPLE horizons on a tree that has moved on — exactly
// the multi-rotation / historical-horizon gap (see e2e-tests issue #24).
//
// PHYSICS, NOT MOCKS: one real EmbeddedAppender tree, real RFC 6962 proofs from
// the real TesseraAdapter at each horizon, the production appender for every
// commit. No DB and no witness fixture — inclusion is independent of
// cosignature verification (see realTreeHeadSource).
func TestProductionRotationAppender_RealTree_MultiRotationHorizons(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()
	h := newTesseraHarness(t, ctx, logger)

	pipe := &appendOnlyTreePipeline{h: h, seqByID: map[[32]byte]uint64{}}
	headSrc := &realTreeHeadSource{h: h}

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const logDID = "did:web:ledger.rotation-multi-horizon.test"
	appender := witnessclient.NewProductionRotationAppender(
		priv, logDID, logDID,
		quorum.NewManager(nil),
		pipe, pipe, headSrc, h.Adapter, logger,
	).WithPolling(5*time.Millisecond, 15*time.Second)

	// One record per state transition: the on-log entry bytes, the position it
	// landed at, the proof the appender committed, and the HORIZON (tree size +
	// root) that proof is bound to.
	type rotationRecord struct {
		canonical   []byte
		pos         types.LogPosition
		committed   *types.MerkleProof
		horizonHead types.TreeHead
	}

	// Deliberately irregular, all NON-power-of-two horizons: each batch of
	// ordinary leaves is appended BEFORE a rotation so every rotation lands on
	// an imperfect tree size. Kept modest so the one-at-a-time real-tree appends
	// stay fast; extend the slice to scale the run (assertions are scale-free).
	fillerCounts := []int{149, 31, 37, 29, 41, 23}

	// A trailing batch appended AFTER the final rotation, so EVERY rotation —
	// including the last — sits at a deep interior position in the live tree
	// (off the right edge), giving a long co-path when re-proved at the head.
	const trailingFill = 64

	var (
		records   []rotationRecord
		leafCount uint64 // running total of leaves appended to the real tree
	)
	for r, fill := range fillerCounts {
		// Globally-unique ordinary leaves so the harness's antispam dedup never
		// collapses two appends onto one sequence (which would desync leafCount).
		for j := 0; j < fill; j++ {
			var d [32]byte
			copy(d[:], []byte(fmt.Sprintf("mh-filler-r%d-%d", r, j)))
			if _, err := h.Embedded.AppendLeaf(ctx, d[:]); err != nil {
				t.Fatalf("round %d: AppendLeaf filler %d: %v", r, j, err)
			}
			leafCount++
		}

		// Commit the rotation through the production appender.
		payload := []byte(fmt.Sprintf("multi-horizon rotation payload r=%d", r))
		canonical, pos, proof, err := appender.AppendRotationEntry(ctx, payload)
		if err != nil {
			t.Fatalf("round %d: AppendRotationEntry: %v", r, err)
		}
		leafCount++ // the rotation entry is itself a leaf

		// The horizon is the head that covers this rotation. Nothing is appended
		// between the commit and this read, so it is exactly the head the
		// appender built the proof against, and its size is the running count.
		head, err := h.Embedded.Head()
		if err != nil {
			t.Fatalf("round %d: Head: %v", r, err)
		}
		if head.TreeSize != leafCount {
			t.Fatalf("round %d: horizon size = %d, want %d (running leaf count; antispam dedup?)",
				r, head.TreeSize, leafCount)
		}
		if isPowerOfTwo(head.TreeSize) {
			t.Fatalf("round %d: horizon %d is a power of two — choose a filler count that lands on an imperfect tree",
				r, head.TreeSize)
		}
		if pos.Sequence != leafCount-1 {
			t.Errorf("round %d: rotation pos = %d, want %d (last leaf)", r, pos.Sequence, leafCount-1)
		}

		// COMMIT-TIME sanity: the appender already self-verified in step 6;
		// re-affirm via the SDK consumer path at the live head.
		if err := witness.VerifyRotationInclusion(canonical, proof, head, pos); err != nil {
			t.Fatalf("round %d: commit-time VerifyRotationInclusion: %v", r, err)
		}

		records = append(records, rotationRecord{
			canonical:   canonical,
			pos:         pos,
			committed:   proof,
			horizonHead: head,
		})
	}

	if len(records) != len(fillerCounts) {
		t.Fatalf("recorded %d rotations, want %d", len(records), len(fillerCounts))
	}

	// Grow the tree past the last rotation so every rotation is interior.
	for j := 0; j < trailingFill; j++ {
		var d [32]byte
		copy(d[:], []byte(fmt.Sprintf("mh-trailing-%d", j)))
		if _, err := h.Embedded.AppendLeaf(ctx, d[:]); err != nil {
			t.Fatalf("trailing AppendLeaf %d: %v", j, err)
		}
		leafCount++
	}

	// Trailing appends integrate ASYNCHRONOUSLY (batched), so the published head
	// lags the last AppendLeaf by up to a batch. Poll until it catches up so the
	// live head is deterministic and every rotation sits at an interior position.
	var finalHead types.TreeHead
	deadline := time.Now().Add(10 * time.Second)
	for {
		finalHead, err = h.Embedded.Head()
		if err != nil {
			t.Fatalf("final Head: %v", err)
		}
		if finalHead.TreeSize >= leafCount {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("live head stuck at %d, want %d after trailing fill", finalHead.TreeSize, leafCount)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// MAIN ASSERTIONS — re-derive each historical proof AFTER the tree advanced.
	for i, rec := range records {
		if i > 0 && rec.pos.Sequence <= records[i-1].pos.Sequence {
			t.Errorf("rotation %d: pos %d not strictly after previous %d",
				i, rec.pos.Sequence, records[i-1].pos.Sequence)
		}

		// (a) RE-DERIVE the proof at its OWN horizon size, long after the live
		//     head moved on — the auditor's tree_size=horizon path. Re-derivation
		//     at a fixed horizon is deterministic, so the co-path must match the
		//     proof the appender committed, and it must reconstruct to the PAST
		//     root captured at commit time.
		ownProof, err := h.Adapter.TypedInclusionProof(rec.pos.Sequence, rec.horizonHead.TreeSize)
		if err != nil {
			t.Fatalf("rotation %d: re-derive proof at horizon %d: %v", i, rec.horizonHead.TreeSize, err)
		}
		ownProof.LeafHash = envelope.OnLogEntryLeafHash(rec.canonical)
		if !merkleProofSiblingsEqual(ownProof, rec.committed) {
			t.Errorf("rotation %d: re-derived co-path differs from the committed proof at horizon %d",
				i, rec.horizonHead.TreeSize)
		}
		if err := witness.VerifyRotationInclusion(rec.canonical, ownProof, rec.horizonHead, rec.pos); err != nil {
			t.Errorf("rotation %d: historical proof failed to reconstruct at its horizon %d: %v",
				i, rec.horizonHead.TreeSize, err)
		}

		// (b) The SAME leaf is provable at the LATER live head, where the
		//     trailing fill has pushed it to a deep interior position: the leaf
		//     is permanent, only the co-path grows.
		headProof, err := h.Adapter.TypedInclusionProof(rec.pos.Sequence, finalHead.TreeSize)
		if err != nil {
			t.Fatalf("rotation %d: proof at live head %d: %v", i, finalHead.TreeSize, err)
		}
		headProof.LeafHash = envelope.OnLogEntryLeafHash(rec.canonical)
		if err := witness.VerifyRotationInclusion(rec.canonical, headProof, finalHead, rec.pos); err != nil {
			t.Errorf("rotation %d: proof failed to reconstruct at the live head %d: %v",
				i, finalHead.TreeSize, err)
		}
		if len(headProof.Siblings) < 8 {
			t.Errorf("rotation %d: live-head co-path depth %d, want >=8 (deep interior position)",
				i, len(headProof.Siblings))
		}

		// (c) HORIZON-BOUND: the horizon proof must NOT reconstruct to a DIFFERENT
		//     horizon's root (same claimed size, foreign root) — it commits to a
		//     SPECIFIC cosigned horizon, not any root of that size.
		otherRoot := records[(i+1)%len(records)].horizonHead.RootHash
		if otherRoot != rec.horizonHead.RootHash {
			wrongHorizon := rec.horizonHead
			wrongHorizon.RootHash = otherRoot
			if err := witness.VerifyRotationInclusion(rec.canonical, ownProof, wrongHorizon, rec.pos); err == nil {
				t.Errorf("rotation %d: proof reconstructed to a foreign horizon root — not horizon-bound", i)
			}
		}
	}
}

// isPowerOfTwo reports whether n is a power of two (n >= 1). Used to assert the
// multi-rotation horizons land on IMPERFECT (non-2^k) tree sizes — the regime
// the RFC 6962 inclusion-proof bug lived in.
func isPowerOfTwo(n uint64) bool {
	return n != 0 && n&(n-1) == 0
}

// merkleProofSiblingsEqual reports whether two proofs carry the same co-path
// (leaf position, tree size, and sibling list). Used to assert that re-deriving
// an inclusion proof at a fixed horizon is deterministic and matches what the
// appender committed at that horizon.
func merkleProofSiblingsEqual(a, b *types.MerkleProof) bool {
	if a.LeafPosition != b.LeafPosition || a.TreeSize != b.TreeSize || len(a.Siblings) != len(b.Siblings) {
		return false
	}
	for i := range a.Siblings {
		if a.Siblings[i] != b.Siblings[i] {
			return false
		}
	}
	return true
}
