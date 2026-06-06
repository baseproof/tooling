package builder

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// These tests validate the single-clock invariant the design note asserts:
// the published horizon's SMTRoot is ALWAYS a root the tile layer made durable,
// because the SAME loop tiles a root and then cosigns THAT root. They model the
// exact production failure (a proof anchored on the published root must resolve
// over the tile store) with in-memory fakes — no Postgres, no witnesses.

// ── fakes ────────────────────────────────────────────────────────────────────

// fakeCommit serves a scripted sequence of (seq, root) the commit cursor is at.
// Each ReadCommit returns the current head; advance() moves it (modeling the
// builder committing new batches between checkpoint ticks).
type fakeCommit struct {
	mu   sync.Mutex
	seq  uint64
	root [32]byte
}

func (f *fakeCommit) advance(seq uint64, root [32]byte) {
	f.mu.Lock()
	f.seq, f.root = seq, root
	f.mu.Unlock()
}
func (f *fakeCommit) ReadCommit(context.Context) (uint64, [32]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seq, f.root, nil
}

type fakeFrontier struct {
	seq      uint64
	root     [32]byte
	advances []struct {
		seq  uint64
		root [32]byte
	}
}

func (f *fakeFrontier) ReadFrontier(context.Context) (uint64, [32]byte, error) {
	return f.seq, f.root, nil
}
func (f *fakeFrontier) AdvanceFrontier(_ context.Context, seq uint64, root [32]byte) error {
	f.seq, f.root = seq, root
	f.advances = append(f.advances, struct {
		seq  uint64
		root [32]byte
	}{seq, root})
	return nil
}

// fakeTiles is the durable tile substrate AND the emitter: EmitDurable records
// the root as present, exactly as BuildTiles+PUT-ack would. present() is the
// proof-side check (TiledNodeStore.Get(root) resolves iff the root was emitted).
type fakeTiles struct {
	mu      sync.Mutex
	durable map[[32]byte]bool
	err     error // when non-nil, EmitDurable fails (blob-store outage)
	calls   [][32]byte
}

func newFakeTiles() *fakeTiles { return &fakeTiles{durable: map[[32]byte]bool{}} }
func (f *fakeTiles) EmitDurable(_ context.Context, _ [32]byte, committedRoot [32]byte, _ uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, committedRoot)
	if f.err != nil {
		return f.err // no PUT-ack ⇒ root NOT recorded durable
	}
	f.durable[committedRoot] = true
	return nil
}
func (f *fakeTiles) present(root [32]byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.durable[root]
}

// fakeRooter returns a deterministic Merkle root per size and reports a
// configurable integrated (durable) tree size. integrated == 0 models an empty
// log (genesis); a large value models "every committed size is durable". The loop
// gates on integrated both for Merkle-durability and as the genesis disambiguator.
type fakeRooter struct {
	err        error
	integrated uint64
}

func (f *fakeRooter) RootAtSize(_ context.Context, treeSize uint64) ([32]byte, error) {
	if f.err != nil {
		return [32]byte{}, f.err
	}
	var r [32]byte
	r[0], r[1] = 0xAA, byte(treeSize)
	return r, nil
}

func (f *fakeRooter) IntegratedSize(context.Context) (uint64, error) {
	return f.integrated, nil
}

// fakeWitness records the heads it cosigned and can be forced to fail (witness
// outage) or to return a zero head (no collector wired).
type fakeWitness struct {
	err     error
	noColl  bool
	cosigns []types.TreeHead
}

func (f *fakeWitness) RequestCosignatures(_ context.Context, head types.TreeHead) (types.CosignedTreeHead, error) {
	if f.err != nil {
		return types.CosignedTreeHead{}, f.err
	}
	f.cosigns = append(f.cosigns, head)
	if f.noColl {
		return types.CosignedTreeHead{}, nil // TreeSize == 0 sentinel
	}
	return types.CosignedTreeHead{TreeHead: head}, nil
}

// fakePublisher records the heads published as the horizon.
type fakePublisher struct{ published []types.CosignedTreeHead }

func (f *fakePublisher) PublishCosignedCheckpoint(_ context.Context, head types.CosignedTreeHead) error {
	f.published = append(f.published, head)
	return nil
}

type zeroReceipts struct{}

func (zeroReceipts) ReceiptRoot(context.Context, uint64, uint64) ([32]byte, error) {
	return [32]byte{}, nil
}

func rootN(n byte) [32]byte { var r [32]byte; r[0] = n; return r }

// fakeReceiptArchiver records the archive call and can be forced to fail (to prove
// archiving is best-effort — a write error must not fail the checkpoint).
type fakeReceiptArchiver struct {
	calls []struct{ coveringSize, fromSeq, toSeq uint64 }
	err   error
}

func (f *fakeReceiptArchiver) ArchiveReceiptCommits(_ context.Context, coveringSize, fromSeq, toSeq uint64) error {
	f.calls = append(f.calls, struct{ coveringSize, fromSeq, toSeq uint64 }{coveringSize, fromSeq, toSeq})
	return f.err
}

func newLoop(c *fakeCommit, f *fakeFrontier, t *fakeTiles, w *fakeWitness, p *fakePublisher) *CheckpointLoop {
	// integrated defaults to "every committed size is durable" so tests asserting a
	// publish are not gated by the Merkle-durability check. Tests exercising the
	// gate (genesis / merkle-lag) construct the rooter explicitly via newLoopR.
	return NewCheckpointLoop(c, f, t, &fakeRooter{integrated: ^uint64(0)}, p, w, zeroReceipts{}, 0, nil)
}

// newLoopR is newLoop with an explicit rooter, for tests that drive the
// Merkle-durability / genesis gate via the rooter's integrated size.
func newLoopR(c *fakeCommit, f *fakeFrontier, t *fakeTiles, w *fakeWitness, p *fakePublisher, r *fakeRooter) *CheckpointLoop {
	return NewCheckpointLoop(c, f, t, r, p, w, zeroReceipts{}, 0, nil)
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestCheckpoint_PublishesDurableRoot is the core invariant: the published head's
// SMTRoot is the root just made durable, the publish happens AFTER EmitDurable,
// and the frontier advances to that exact root.
func TestCheckpoint_PublishesDurableRoot(t *testing.T) {
	cRoot := rootN(0x11)
	commit := &fakeCommit{seq: 41, root: cRoot}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	tiles := newFakeTiles()
	witness := &fakeWitness{}
	pub := &fakePublisher{}
	loop := newLoop(commit, frontier, tiles, witness, pub)

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	if len(pub.published) != 1 {
		t.Fatalf("want 1 publish, got %d", len(pub.published))
	}
	got := pub.published[0]
	if got.SMTRoot != cRoot {
		t.Fatalf("published SMTRoot = %x, want committed root %x", got.SMTRoot[:4], cRoot[:4])
	}
	if got.TreeSize != 42 {
		t.Fatalf("published TreeSize = %d, want cSeq+1 = 42", got.TreeSize)
	}
	if !tiles.present(got.SMTRoot) {
		t.Fatal("published root is NOT in the durable tile set — the 500-bug invariant is violated")
	}
	if frontier.seq != 41 || frontier.root != cRoot {
		t.Fatalf("frontier = (%d,%x), want (41,%x)", frontier.seq, frontier.root[:4], cRoot[:4])
	}
	if len(witness.cosigns) != 1 || witness.cosigns[0].SMTRoot != cRoot {
		t.Fatal("witness was not asked to cosign the durable root")
	}
}

// TestCheckpoint_ArchivesReceiptCommits_BestEffort: after a successful publish the
// loop invokes the receipt archiver with (coveringSize=tree_size, fromSeq=prev
// published size, toSeq=cSeq), and an archiver error is SWALLOWED (best-effort) —
// the checkpoint still succeeds and the horizon still advances (cf. 1.1a).
func TestCheckpoint_ArchivesReceiptCommits_BestEffort(t *testing.T) {
	cRoot := rootN(0x11)
	commit := &fakeCommit{seq: 41, root: cRoot}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	tiles := newFakeTiles()
	witness := &fakeWitness{}
	pub := &fakePublisher{}
	loop := newLoop(commit, frontier, tiles, witness, pub)

	arch := &fakeReceiptArchiver{err: errors.New("object store down")}
	loop.SetReceiptArchiver(arch)

	// Best-effort: an archiver error must NOT fail the checkpoint.
	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce must succeed despite archive error: %v", err)
	}
	if len(pub.published) != 1 {
		t.Fatalf("publish must still happen, got %d", len(pub.published))
	}
	if len(arch.calls) != 1 {
		t.Fatalf("want 1 archive call, got %d", len(arch.calls))
	}
	if c := arch.calls[0]; c.coveringSize != 42 || c.fromSeq != 0 || c.toSeq != 41 {
		t.Fatalf("archive call = (cover=%d, from=%d, to=%d), want (42,0,41)", c.coveringSize, c.fromSeq, c.toSeq)
	}
}

// TestCheckpoint_PublishedRootAlwaysTilePresent is the headline property under
// the production failure shape: the commit cursor JUMPS over intermediate roots
// (the 1s-tick-vs-487/s skip). The legacy publisher could select a skipped root;
// the checkpoint loop publishes only the root it tiled. Every published root must
// be tile-present across the whole run.
func TestCheckpoint_PublishedRootAlwaysTilePresent(t *testing.T) {
	commit := &fakeCommit{}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	tiles := newFakeTiles()
	pub := &fakePublisher{}
	loop := newLoop(commit, frontier, tiles, &fakeWitness{}, pub)

	// 50 commits; the checkpoint loop runs only every 10th — modeling the cursor
	// jumping over 9 intermediate roots each tick (none of which get tiled).
	for i := uint64(1); i <= 50; i++ {
		commit.advance(i, rootN(byte(i)))
		if i%10 == 0 {
			if err := loop.CheckpointOnce(context.Background()); err != nil {
				t.Fatalf("CheckpointOnce at i=%d: %v", i, err)
			}
		}
	}
	if len(pub.published) == 0 {
		t.Fatal("nothing published")
	}
	for _, h := range pub.published {
		if !tiles.present(h.SMTRoot) {
			t.Fatalf("published a root %x with no durable tiles — proof would 500", h.SMTRoot[:4])
		}
	}
	// And the loop must never tile/publish a skipped intermediate (e.g. root 0x07).
	if tiles.present(rootN(7)) {
		t.Fatal("an intermediate (skipped) root was tiled — loop is not tiling only cRoot")
	}
}

// TestCheckpoint_HoldsOnEmitError: a blob-store outage HOLDS — no frontier
// advance, no cosign, no publish, and not an error (the commit cursor is free to
// keep advancing; the horizon simply freezes).
func TestCheckpoint_HoldsOnEmitError(t *testing.T) {
	commit := &fakeCommit{seq: 5, root: rootN(0x22)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	tiles := newFakeTiles()
	tiles.err = errors.New("blob store down")
	witness := &fakeWitness{}
	pub := &fakePublisher{}
	loop := newLoop(commit, frontier, tiles, witness, pub)

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("emit-outage should HOLD (nil), got %v", err)
	}
	if len(pub.published) != 0 {
		t.Fatal("published despite the tiles never being made durable")
	}
	if len(witness.cosigns) != 0 {
		t.Fatal("cosigned despite a blob outage")
	}
	if len(frontier.advances) != 0 {
		t.Fatal("advanced the frontier without a durable PUT-ack")
	}
}

// TestCheckpoint_HoldsOnWitnessError: a witness-quorum outage HOLDS the publish
// (tiles were made durable, frontier advanced, but the horizon does not move and
// it is not an error).
func TestCheckpoint_HoldsOnWitnessError(t *testing.T) {
	commit := &fakeCommit{seq: 7, root: rootN(0x33)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	tiles := newFakeTiles()
	witness := &fakeWitness{err: errors.New("no quorum")}
	pub := &fakePublisher{}
	loop := newLoop(commit, frontier, tiles, witness, pub)

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("witness-outage should HOLD (nil), got %v", err)
	}
	if !tiles.present(rootN(0x33)) {
		t.Fatal("tiles should have been made durable before the (failed) cosign")
	}
	if len(pub.published) != 0 {
		t.Fatal("published a head with no witness quorum")
	}
}

// TestCheckpoint_NoCollectorNoPublish: a zero-TreeSize cosign return (no witness
// collector wired — read-only/test ledger) must not publish.
func TestCheckpoint_NoCollectorNoPublish(t *testing.T) {
	commit := &fakeCommit{seq: 3, root: rootN(0x44)}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	pub := &fakePublisher{}
	loop := newLoop(commit, frontier, newFakeTiles(), &fakeWitness{noColl: true}, pub)
	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	if len(pub.published) != 0 {
		t.Fatal("published with no collector wired")
	}
}

// TestCheckpoint_SkipsUnchanged: a second cycle with no new commit re-emits
// nothing and re-publishes nothing (idle ticks are near-free).
func TestCheckpoint_SkipsUnchanged(t *testing.T) {
	commit := &fakeCommit{seq: 9, root: rootN(0x55)}
	tiles := newFakeTiles()
	pub := &fakePublisher{}
	loop := newLoop(commit, &fakeFrontier{root: smt.EmptyHash}, tiles, &fakeWitness{}, pub)

	_ = loop.CheckpointOnce(context.Background())
	_ = loop.CheckpointOnce(context.Background()) // unchanged cRoot
	if len(pub.published) != 1 {
		t.Fatalf("want exactly 1 publish across two unchanged cycles, got %d", len(pub.published))
	}
	if len(tiles.calls) != 1 {
		t.Fatalf("want exactly 1 emit across two unchanged cycles, got %d", len(tiles.calls))
	}
}

// TestCheckpoint_GenesisSkip: a genuinely empty log has nothing to publish. The
// commit cursor is at the 0-sentinel with the EmptyHash root AND the integrated
// size is 0 — the integrated size (not the root) is what proves the log is empty,
// because a single committed commentary entry has the SAME (0, EmptyHash) cursor.
func TestCheckpoint_GenesisSkip(t *testing.T) {
	commit := &fakeCommit{seq: 0, root: smt.EmptyHash}
	pub := &fakePublisher{}
	loop := newLoopR(commit, &fakeFrontier{root: smt.EmptyHash}, newFakeTiles(), &fakeWitness{}, pub, &fakeRooter{integrated: 0})
	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	if len(pub.published) != 0 {
		t.Fatal("published over an empty log (integrated size 0)")
	}
}

// TestCheckpoint_CommentarySeedPublishes is the e2e seed regression. The
// genesis-seed entry is COMMENTARY-class: it advances the log (one Merkle leaf ⇒
// integrated size 1) WITHOUT mutating the SMT root (still EmptyHash). The commit
// cursor is therefore (committed_through_seq=0, current_root=EmptyHash) — BYTE-
// IDENTICAL to a fresh log in smt_root_state. The loop must STILL cosign + publish
// a head at tree_size 1, because the integrated size (1, not 0) proves an entry
// committed. The old `cRoot == EmptyHash` guard skipped this, so the seed head was
// never cosigned and `seed()` timed out — the witnesses were never even asked.
func TestCheckpoint_CommentarySeedPublishes(t *testing.T) {
	commit := &fakeCommit{seq: 0, root: smt.EmptyHash}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	tiles := newFakeTiles()
	witness := &fakeWitness{}
	pub := &fakePublisher{}
	loop := newLoopR(commit, frontier, tiles, witness, pub, &fakeRooter{integrated: 1})

	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("CheckpointOnce: %v", err)
	}
	if len(pub.published) != 1 {
		t.Fatalf("commentary seed must publish exactly 1 horizon, got %d", len(pub.published))
	}
	got := pub.published[0]
	if got.TreeSize != 1 {
		t.Fatalf("published TreeSize = %d, want 1 (committed_through_seq 0 + 1)", got.TreeSize)
	}
	if got.SMTRoot != smt.EmptyHash {
		t.Fatalf("published SMTRoot = %x, want EmptyHash (commentary ⇒ no SMT mutation)", got.SMTRoot[:4])
	}
	if len(witness.cosigns) != 1 || witness.cosigns[0].TreeSize != 1 {
		t.Fatal("witness was not asked to cosign the seed head at tree_size 1")
	}
}

// TestCheckpoint_CommentaryRunAdvancesHorizon: across a run of commentary entries
// the SMT root NEVER changes (stays EmptyHash), but the log position advances
// (seq 0,1,2 ⇒ integrated 1,2,3). The horizon must re-publish at each new
// tree_size — proof that skip-if-unchanged keys on the POSITION, not the root, so
// a static SMT root does not freeze the horizon.
func TestCheckpoint_CommentaryRunAdvancesHorizon(t *testing.T) {
	commit := &fakeCommit{}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	pub := &fakePublisher{}
	rooter := &fakeRooter{integrated: 0}
	loop := newLoopR(commit, frontier, newFakeTiles(), &fakeWitness{}, pub, rooter)

	for seq := uint64(0); seq <= 2; seq++ {
		commit.advance(seq, smt.EmptyHash) // commentary ⇒ root never changes
		rooter.integrated = seq + 1        // each entry integrates one Merkle leaf
		if err := loop.CheckpointOnce(context.Background()); err != nil {
			t.Fatalf("CheckpointOnce seq=%d: %v", seq, err)
		}
	}
	if len(pub.published) != 3 {
		t.Fatalf("want 3 publishes across the commentary run, got %d", len(pub.published))
	}
	for i, h := range pub.published {
		if h.TreeSize != uint64(i+1) {
			t.Fatalf("publish %d TreeSize = %d, want %d", i, h.TreeSize, i+1)
		}
		if h.SMTRoot != smt.EmptyHash {
			t.Fatalf("publish %d SMTRoot = %x, want EmptyHash throughout", i, h.SMTRoot[:4])
		}
	}
}

// TestCheckpoint_HoldsWhenMerkleLagsCommit: the SMT commit cursor is ahead of the
// durable Merkle integration (the head's RootHash = RootAtSize(treeSize) is not
// yet derivable). The loop HOLDS before emitting/cosigning/publishing, and the
// gate short-circuits ahead of the SMT-tile emit.
func TestCheckpoint_HoldsWhenMerkleLagsCommit(t *testing.T) {
	commit := &fakeCommit{seq: 5, root: rootN(0x66)} // treeSize 6
	tiles := newFakeTiles()
	witness := &fakeWitness{}
	pub := &fakePublisher{}
	loop := newLoopR(commit, &fakeFrontier{root: smt.EmptyHash}, tiles, witness, pub, &fakeRooter{integrated: 4})
	if err := loop.CheckpointOnce(context.Background()); err != nil {
		t.Fatalf("merkle-lag should HOLD (nil), got %v", err)
	}
	if len(pub.published) != 0 {
		t.Fatal("published despite the Merkle tiles not covering the committed size")
	}
	if len(tiles.calls) != 0 {
		t.Fatal("emitted SMT tiles before the Merkle durability gate passed")
	}
	if len(witness.cosigns) != 0 {
		t.Fatal("cosigned despite the Merkle durability HOLD")
	}
}

// TestCheckpoint_WitnessQuorumFailureHook verifies the injected SRE hook fires
// exactly once per cycle the witness K-of-N cosign is unavailable, and never on
// a clean publish or on an upstream (pre-cosign) hold. This is the seam the
// composition root binds to gossipnet.IncWitnessQuorumFailure — the core loop
// itself stays free of any metrics/gossip dependency. (The nil-hook no-op path
// is exercised by every other test, which sets no hook.)
func TestCheckpoint_WitnessQuorumFailureHook(t *testing.T) {
	t.Run("fires on the witness-quorum hold", func(t *testing.T) {
		commit := &fakeCommit{seq: 7, root: rootN(0x33)}
		loop := newLoop(commit, &fakeFrontier{root: smt.EmptyHash}, newFakeTiles(),
			&fakeWitness{err: errors.New("no quorum")}, &fakePublisher{})
		fired := 0
		loop.OnWitnessQuorumFailure(func(context.Context) { fired++ })

		if err := loop.CheckpointOnce(context.Background()); err != nil {
			t.Fatalf("witness-outage should HOLD (nil), got %v", err)
		}
		if fired != 1 {
			t.Fatalf("hook fired %d times, want exactly 1 on the witness-quorum hold", fired)
		}
	})

	t.Run("does not fire on a clean publish", func(t *testing.T) {
		commit := &fakeCommit{seq: 41, root: rootN(0x11)}
		loop := newLoop(commit, &fakeFrontier{root: smt.EmptyHash}, newFakeTiles(),
			&fakeWitness{}, &fakePublisher{})
		fired := 0
		loop.OnWitnessQuorumFailure(func(context.Context) { fired++ })

		if err := loop.CheckpointOnce(context.Background()); err != nil {
			t.Fatalf("CheckpointOnce: %v", err)
		}
		if fired != 0 {
			t.Fatalf("hook fired %d times on a clean publish, want 0", fired)
		}
	})

	t.Run("does not fire on a pre-cosign hold", func(t *testing.T) {
		// A blob-store outage HOLDS at Step 1, before the cosign is ever reached.
		commit := &fakeCommit{seq: 5, root: rootN(0x22)}
		tiles := newFakeTiles()
		tiles.err = errors.New("blob store down")
		loop := newLoop(commit, &fakeFrontier{root: smt.EmptyHash}, tiles,
			&fakeWitness{}, &fakePublisher{})
		fired := 0
		loop.OnWitnessQuorumFailure(func(context.Context) { fired++ })

		if err := loop.CheckpointOnce(context.Background()); err != nil {
			t.Fatalf("emit-outage should HOLD (nil), got %v", err)
		}
		if fired != 0 {
			t.Fatalf("hook fired %d times on a pre-cosign (blob-store) hold, want 0", fired)
		}
	})
}

// recordingReceipts is a ReceiptRanger that records the [from,to] of every
// ReceiptRoot call (returning a deterministic non-zero root), so a test can assert
// the receipt delta's lower bound.
type recordingReceipts struct {
	calls []struct{ from, to uint64 }
}

func (r *recordingReceipts) ReceiptRoot(_ context.Context, from, to uint64) ([32]byte, error) {
	r.calls = append(r.calls, struct{ from, to uint64 }{from, to})
	var h [32]byte
	h[0], h[1] = byte(from), byte(to)
	return h, nil
}

// TestCheckpoint_ReceiptDeltaSurvivesCosignHold pins fix A2: the receipt delta keys
// off the last PUBLISHED tree_size, not the tile frontier — so a cosign HOLD (which
// advances the frontier at Step 5 but never publishes) cannot orphan the held
// delta's receipts. The checkpoint published AFTER the hold must commit a ReceiptRoot
// whose range starts at lastPublishedSize, SPANNING the entries committed during the
// hold (the range the receipt-proof handler reconstructs via CosignedSizeBelow).
func TestCheckpoint_ReceiptDeltaSurvivesCosignHold(t *testing.T) {
	commit := &fakeCommit{}
	frontier := &fakeFrontier{root: smt.EmptyHash}
	witness := &fakeWitness{}
	pub := &fakePublisher{}
	rec := &recordingReceipts{}
	loop := NewCheckpointLoop(commit, frontier, newFakeTiles(),
		&fakeRooter{integrated: ^uint64(0)}, pub, witness, rec, 0, nil)
	ctx := context.Background()

	// Cycle 1 — commit seq 99 (tree_size 100), cosign OK → publish. Genesis delta [0,99].
	commit.advance(99, rootN(0x01))
	if err := loop.CheckpointOnce(ctx); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}

	// Cycle 2 — commit seq 199 (tree_size 200), cosign HOLDS. The frontier advances
	// to 199 (Step 5, pre-cosign); the horizon stays at 100 (never published).
	commit.advance(199, rootN(0x02))
	witness.err = errors.New("witness quorum unavailable")
	if err := loop.CheckpointOnce(ctx); err != nil {
		t.Fatalf("cycle 2 (hold must return nil): %v", err)
	}

	// Cycle 3 — commit seq 299 (tree_size 300), cosign recovers → publish.
	commit.advance(299, rootN(0x03))
	witness.err = nil
	if err := loop.CheckpointOnce(ctx); err != nil {
		t.Fatalf("cycle 3: %v", err)
	}

	// Two publishes (100 and 300); the 200 checkpoint was held.
	if len(pub.published) != 2 {
		t.Fatalf("published %d heads, want 2 (the 200 checkpoint held)", len(pub.published))
	}
	if pub.published[0].TreeSize != 100 || pub.published[1].TreeSize != 300 {
		t.Fatalf("published sizes = [%d %d], want [100 300]", pub.published[0].TreeSize, pub.published[1].TreeSize)
	}

	// The post-hold (cSeq 299) receipt delta must start at the last PUBLISHED size 100,
	// covering the held region [100,199]. The pre-A2 frontier-keyed logic would yield
	// [200,299], orphaning [100,199] (the bug this fix closes).
	var got struct{ from, to uint64 }
	found := false
	for _, c := range rec.calls {
		if c.to == 299 {
			got, found = c, true
		}
	}
	if !found {
		t.Fatalf("no ReceiptRoot call for cSeq 299; calls=%v", rec.calls)
	}
	if got.from != 100 {
		t.Errorf("post-hold receipt delta = [%d,%d], want [100,299] (spans the held [100,199]); frontier-keyed would orphan it as [200,299]", got.from, got.to)
	}
}
