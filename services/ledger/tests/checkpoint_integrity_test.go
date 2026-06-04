package tests

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	opbuilder "github.com/baseproof/tooling/services/ledger/builder"
	opstore "github.com/baseproof/tooling/services/ledger/store"
)

// --- orthogonal fakes -------------------------------------------------------
// The 30K integrity failure was SMT-tile-side: the published horizon's SMTRoot
// had no tile. The Merkle RootHash and the witness signature are NOT what 500'd,
// so they are stubbed; everything on the SMT-tile path (tree, emitter, frontier,
// tile store, proof) is real.

type intgRooter struct{}

func (intgRooter) RootAtSize(context.Context, uint64) ([32]byte, error) {
	return [32]byte{0xCC}, nil
}

// IntegratedSize is stubbed "everything durable": this test exercises the SMT-tile
// resolution path (real emitter/frontier/tile store), not the Merkle-durability
// gate, so the gate must always pass for the real committed sizes.
func (intgRooter) IntegratedSize(context.Context) (uint64, error) {
	return ^uint64(0), nil
}

type intgWitness struct{}

func (intgWitness) RequestCosignatures(_ context.Context, h types.TreeHead) (types.CosignedTreeHead, error) {
	return types.CosignedTreeHead{TreeHead: h}, nil // non-zero TreeSize ⇒ publishes
}

type intgPublisher struct{ roots [][32]byte }

func (p *intgPublisher) PublishCosignedCheckpoint(_ context.Context, h types.CosignedTreeHead) error {
	p.roots = append(p.roots, h.SMTRoot)
	return nil
}

// TestCheckpoint_Integrity_ProofOverTilesResolves reproduces the 30K integrity
// requirement end-to-end against real Postgres:
//
//   - drive the REAL SMT tree forward in batches, with the commit cursor JUMPING
//     over intermediate roots between checkpoints (exactly the 487/s-vs-1s-tick
//     shape that produced the failure at 30K);
//   - run the REAL CheckpointLoop (real BuildTilesEmitter → POSIX tile store, real
//     PgTileFrontier, real SMTCommitCursor);
//   - assert that for EVERY published horizon root, an SMT membership proof served
//     from the REAL tile store RESOLVES — i.e. /v1/smt/proof over the tiles source
//     never returns ErrUnknownRoot (HTTP 500) on a published root.
//
// It also asserts the negative that makes the old design wrong: an intermediate
// committed root the loop skipped is NOT in the tile store, so publishing it (the
// legacy "select by tree_size" behaviour) WOULD have 500'd. The fix is that the
// loop only ever publishes a root it just tiled.
func TestCheckpoint_Integrity_ProofOverTilesResolves(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Clean genesis (drive the tree from empty; the in-memory leaf/node stores
	// start empty, so the persisted root must match).
	if _, err := pool.Exec(ctx, `UPDATE smt_root_state SET current_root=$1, committed_through_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset smt_root_state: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tile_frontier SET frontier_root=$1, frontier_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset tile_frontier: %v", err)
	}

	leafStore := smt.NewInMemoryLeafStore()
	nodeStore := opstore.NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(leafStore, nodeStore)
	tree.SetRoot(smt.EmptyHash)

	rootStore := opstore.NewSMTRootStateStore(pool)
	tileDir := t.TempDir()
	tileStore := opstore.NewPosixSMTTileStore(tileDir)

	pub := &intgPublisher{}
	loop := opbuilder.NewCheckpointLoop(
		opstore.NewSMTCommitCursor(rootStore),
		opstore.NewPgTileFrontier(pool),
		opstore.NewBuildTilesEmitter(nodeStore, tileStore),
		intgRooter{}, pub, intgWitness{}, nil, 0, logger,
	)

	const logDID = "did:web:integrity.test"
	keyFor := func(seq uint64) [32]byte {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], seq)
		return sha256.Sum256(append([]byte(logDID), b[:]...))
	}
	commitBatch := func(fromSeq, n uint64) [32]byte {
		leaves := make([]types.SMTLeaf, n)
		for i := uint64(0); i < n; i++ {
			s := fromSeq + i
			pos := types.LogPosition{LogDID: logDID, Sequence: s}
			leaves[i] = types.SMTLeaf{Key: keyFor(s), OriginTip: pos, AuthorityTip: pos}
		}
		if err := tree.SetLeaves(ctx, leaves); err != nil {
			t.Fatalf("SetLeaves [%d,%d): %v", fromSeq, fromSeq+n, err)
		}
		newRoot, err := tree.Root(ctx)
		if err != nil {
			t.Fatalf("tree.Root: %v", err)
		}
		// Persist the new committed root + cursor — the bleeding edge the builder's
		// atomic commit would have written to smt_root_state. The test is the sole
		// writer, so a direct UPDATE stands in for the builder's CAS.
		if _, err := pool.Exec(ctx,
			`UPDATE smt_root_state SET current_root=$1, committed_through_seq=$2 WHERE id=1`,
			newRoot[:], int64(fromSeq+n-1),
		); err != nil {
			t.Fatalf("set smt_root_state: %v", err)
		}
		return newRoot
	}

	// Drive: 50 entries/batch, checkpoint only every 4th batch → the cursor jumps
	// 200 roots between checkpoints, leaving 150 un-tiled intermediates each time.
	const batch = uint64(50)
	const rounds = 40
	var total uint64
	var intermediateRoot [32]byte // a root the loop will skip (never a checkpoint cRoot)
	for r := 0; r < rounds; r++ {
		root := commitBatch(total, batch)
		total += batch
		if r == 0 {
			intermediateRoot = root // committed at seq 49; first checkpoint is after r==3
		}
		if r%4 == 3 {
			if err := loop.CheckpointOnce(ctx); err != nil {
				t.Fatalf("CheckpointOnce r=%d: %v", r, err)
			}
		}
	}
	if err := loop.CheckpointOnce(ctx); err != nil { // publish the tip
		t.Fatalf("final CheckpointOnce: %v", err)
	}

	if len(pub.roots) == 0 {
		t.Fatal("checkpoint loop published no horizon")
	}
	t.Logf("published %d horizons over %d committed entries (cursor jumped 200/checkpoint)", len(pub.roots), total)

	// INTEGRITY: every published horizon root resolves over the REAL tile store.
	cache := smt.NewTileCache(2048)
	k0 := keyFor(0) // committed in the first batch ⇒ a member under every later root
	for i, root := range pub.roots {
		ts := smt.NewTiledNodeStore(ctx, tileStore, cache)
		proof, err := smt.GenerateProofAt(ts, root, k0)
		if err != nil {
			t.Fatalf("horizon[%d] root %x: proof over tiles failed (%v) — the 30K ErrUnknownRoot bug", i, root[:6], err)
		}
		if proof.TerminalKind != types.SMTTerminalLeaf || proof.TerminalLeaf == nil || proof.TerminalLeaf.Key != k0 {
			t.Fatalf("horizon[%d] root %x: proof for key0 is not a membership proof", i, root[:6])
		}
	}

	// NEGATIVE control: the skipped intermediate root is NOT tile-present, so the
	// legacy "publish the latest cosigned head by tree_size" — which could select
	// it — WOULD have 500'd. Publishing by root identity is what avoids that.
	if opstore.TilesCoverRoot(ctx, tileStore, cache, intermediateRoot) {
		t.Fatalf("intermediate root %x is tiled — loop is not tiling only the published cRoot", intermediateRoot[:6])
	}
	// And the published tip IS tile-present (the positive of the same oracle).
	tip := pub.roots[len(pub.roots)-1]
	if !opstore.TilesCoverRoot(ctx, tileStore, cache, tip) {
		t.Fatalf("published tip %x is NOT tile-present — published⇒durable invariant violated", tip[:6])
	}
}
