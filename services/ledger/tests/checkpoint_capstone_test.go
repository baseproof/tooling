/*
FILE PATH: tests/checkpoint_capstone_test.go

PR-1.5 — the real-real checkpoint capstone (#80): BOTH production halves
joined through one CheckpointOnce at one size, for the first time anywhere.

  - the REAL tessera Merkle pipeline: EmbeddedAppender assigns the leaf,
    integrates it into POSIX tiles, and the TesseraAdapter — the loop's
    PRODUCTION CheckpointRooter — derives RootAtSize/IntegratedSize from
    those tiles;
  - the REAL SMT pipeline: in-memory tree committed through the real
    cursor (smt_root_state), tiled by the real emitter onto POSIX;
  - the REAL validating witness: httptest cosign servers running the
    SDK's NewWitnessHandler, collected by the real HeadSync into the
    real tree_heads.

The three disciplines this test is built on (the #80 acceptance frame):

 1. COMPOSE PROVEN HALVES, INVENT NO WIRING. Every component above is
    exercised verbatim by an existing green test (the DB-free appender
    tests prove the tessera half; checkpoint_integrity proves the
    loop's SMT half; the Rung-B test proves the signer). Only the JOIN
    is new.
 2. NEVER PICK A SIZE — LET THE LOOP PICK IT. One entry stream feeds
    both pipelines through production calls (AppendLeaf assigns the
    sequence; the SMT commit records the same sequence); treeSize is
    derived only by the loop via store.TreeSizeForCommittedSeq, and
    every assertion is against the size THE LOOP CHOSE, re-derived
    through the same production primitives — never a hand-pinned +1.
 3. THE SIGNER'S ACCEPTANCE IS THE ALIGNMENT ASSERTION; HOLDS ARE THE
    TRIPWIRE. A real validating cosigner accepting the head proves both
    roots were genuinely populated at the same size. If the halves
    misalign, the loop's HOLD paths (merkle_not_durable, tiles-not-
    durable) freeze rather than publish and the named fault classes
    (cosign.ErrInvalidPayload) fail the test loudly — a mis-wiring
    surfaces as a clean hold-timeout or a named fault, never a false
    green.

This composition is also the executable spec for #76's
GenesisLogAppender: "first entry on an empty tree, needing a covering
cosigned head" — the loop holds over the empty log, integrates, then
publishes a head the appender's covering-wait can trust.
*/
package tests

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	opbuilder "github.com/baseproof/tooling/services/ledger/builder"
	opstore "github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

func TestCheckpoint_Capstone_RealMerkleRealSMTRealSigner(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Clean genesis for the loop's PG singletons.
	if _, err := pool.Exec(ctx, `UPDATE smt_root_state SET current_root=$1, committed_through_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset smt_root_state: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tile_frontier SET frontier_root=$1, frontier_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset tile_frontier: %v", err)
	}

	// PROVEN HALF 1 — the real tessera Merkle pipeline (EmbeddedAppender +
	// TesseraAdapter over POSIX tiles). The adapter IS the production
	// CheckpointRooter; nothing is faked on the Merkle side.
	th := newTesseraHarness(t, ctx, logger)

	// PROVEN HALF 2 — the real SMT pipeline: tree + commit cursor + tile
	// emitter, exactly as checkpoint_integrity wires them.
	leafStore := smt.NewInMemoryLeafStore()
	nodeStore := opstore.NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(leafStore, nodeStore)
	tree.SetRoot(smt.EmptyHash)
	rootStore := opstore.NewSMTRootStateStore(pool)
	tileStore := opstore.NewPosixSMTTileStore(t.TempDir())

	// PROVEN HALF 3 — the real validating signer (SDK NewWitnessHandler over
	// httptest) and the real collector persisting into tree_heads.
	fixture := newWitnessFixture(t, th.NetworkID, 1)
	headSync, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  fixture.URLs(),
		QuorumK:           1,
		PerWitnessTimeout: 2 * time.Second,
		NetworkID:         th.NetworkID,
		HTTPClient:        newTunedHTTPClient(2 * time.Second),
	}, opstore.NewTreeHeadStore(pool), logger)
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	recorder := &horizonRecorder{}

	// THE JOIN — the only new wiring in this test: the real adapter as the
	// loop's rooter, the real HeadSync as its cosigner.
	loop := opbuilder.NewCheckpointLoop(
		opstore.NewSMTCommitCursor(rootStore),
		opstore.NewPgTileFrontier(pool),
		opstore.NewBuildTilesEmitter(nodeStore, tileStore),
		th.Adapter, recorder, headSync, nil, 0, logger,
	)

	// ONE ENTRY STREAM through production code. The on-log convention: the
	// ledger feeds tessera the 32-byte entry identity; the Merkle leaf hash
	// is OnLogEntryLeafHash(canonical) = H(0x00 || identity).
	canonical := []byte("pr-1.5 capstone entry — one stream, two real pipelines")
	identity := sha256.Sum256(canonical)

	seq, err := th.Embedded.AppendLeaf(ctx, identity[:]) // REAL: tessera assigns the sequence
	if err != nil {
		t.Fatalf("AppendLeaf: %v", err)
	}

	// The SMT commit records THE SAME sequence tessera assigned — discipline
	// 2: no hand-derived size anywhere; the loop alone turns this into a
	// treeSize via store.TreeSizeForCommittedSeq.
	pos := types.LogPosition{LogDID: testLogDID, Sequence: seq}
	if err := tree.SetLeaves(ctx, []types.SMTLeaf{{Key: identity, OriginTip: pos, AuthorityTip: pos}}); err != nil {
		t.Fatalf("SetLeaves: %v", err)
	}
	committedRoot, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("tree.Root: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE smt_root_state SET current_root=$1, committed_through_seq=$2 WHERE id=1`,
		committedRoot[:], int64(seq),
	); err != nil {
		t.Fatalf("commit smt_root_state: %v", err)
	}

	// Drive the production loop until it publishes. While tessera has not yet
	// integrated the leaf, the loop HOLDS (merkle_not_durable) — discipline 3:
	// misalignment can only freeze, never publish, so the failure mode here is
	// a clean hold-timeout. Any non-nil cycle error is a named fault and fails
	// immediately.
	const budget = 15 * time.Second
	deadline := time.Now().Add(budget)
	for len(recorder.published()) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("hold-timeout: the loop never published within %s — the real halves did not align "+
				"(this is the tripwire, not a flake: inspect merkle_not_durable / tiles holds)", budget)
		}
		if err := loop.CheckpointOnce(ctx); err != nil {
			t.Fatalf("the production loop faulted (named class, fix the constructor): %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}

	published := recorder.published()
	if len(published) != 1 {
		t.Fatalf("published %d horizons, want exactly 1 (skip-if-unchanged keys on the commit position)", len(published))
	}
	head := published[0]

	// THE ALIGNMENT ASSERTIONS — every value re-derived through the SAME
	// production primitives at the size THE LOOP CHOSE:
	wantSize := opstore.TreeSizeForCommittedSeq(seq) // the rule's single home, referenced not re-derived
	if head.TreeSize != wantSize {
		t.Fatalf("loop published size %d, want TreeSizeForCommittedSeq(%d) = %d", head.TreeSize, seq, wantSize)
	}
	realRoot, err := th.Adapter.RootAtSize(ctx, head.TreeSize)
	if err != nil {
		t.Fatalf("RootAtSize(%d) after publish: %v", head.TreeSize, err)
	}
	if head.RootHash != realRoot {
		t.Fatalf("published RootHash %x != the real tiles' root %x at the loop's size", head.RootHash[:8], realRoot[:8])
	}
	if head.SMTRoot != committedRoot {
		t.Fatalf("published SMTRoot %x != the committed cursor root %x (dual-commitment)", head.SMTRoot[:8], committedRoot[:8])
	}
	if head.SMTRoot == ([32]byte{}) || head.RootHash == ([32]byte{}) {
		t.Fatal("a zero root reached the published head — the factory's postcondition is broken")
	}
	// Discipline 3's core: a REAL validating signer accepted this head — both
	// roots genuinely populated at one size.
	if len(head.Signatures) < 1 {
		t.Fatal("published head carries no witness signature — the signer never accepted it")
	}
	// And it is durably persisted where the appender's covering-wait reads.
	row, err := opstore.NewTreeHeadStore(pool).LatestCosigned(ctx, 1)
	if err != nil || row == nil {
		t.Fatalf("no cosigned head persisted (row=%v err=%v)", row, err)
	}
	if row.TreeSize != head.TreeSize {
		t.Fatalf("persisted covering head at size %d, published at %d", row.TreeSize, head.TreeSize)
	}

	// CLOSING PROOF — the published head really covers the appended entry: a
	// REAL inclusion proof from the REAL tiles, with the on-log leaf binding,
	// reconstructs to the published RootHash.
	proof, err := th.Adapter.TypedInclusionProof(seq, head.TreeSize)
	if err != nil {
		t.Fatalf("TypedInclusionProof(%d,%d): %v", seq, head.TreeSize, err)
	}
	proof.LeafHash = envelope.OnLogEntryLeafHash(canonical)
	if err := smt.VerifyMerkleInclusion(proof, head.RootHash); err != nil {
		t.Fatalf("real proof does not reconstruct to the published cosigned root: %v", err)
	}

	// The loop stays quiet afterwards (skip-if-unchanged): one more cycle
	// publishes nothing new.
	if err := loop.CheckpointOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("post-publish cycle: %v", err)
	}
	if got := len(recorder.published()); got != 1 {
		t.Fatalf("post-publish cycle re-published (total %d), want exactly 1", got)
	}
}
