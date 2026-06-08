package store

// Regression for issue #189 — a crash mid-commit strands the published horizon
// permanently because two code paths trust `frontier_root == committed_root` as
// proof that the root's tiles are durable. They are not, after a crash that loses
// the un-tiled tail before the tiles were fsync'd.
//
// This test reconstructs the EXACT post-crash invariant the live forensics showed
// (frontier_root == committed_root, empty tail, empty tiles, durable smt_leaves)
// and proves the RED/GREEN boundary:
//
//   RED  — the watermark gate ("skip when committed == frontier", in both
//          cmd/ledger/boot/wire/wire.go::recoverTailOnBoot and
//          builder/checkpoint_loop.go::CheckpointOnce) leaves the published root
//          with NO servable proof: smt.GenerateProofAt returns ErrUnknownRoot
//          (the source of the live 500 {"anchored checkpoint root not present in
//          node store"}).
//
//   GREEN — gating on the TRUE durability signal, store.TilesCoverRoot (are the
//          tiles for this root actually present?), replays smt_leaves and
//          re-emits the tiles, after which the proof resolves.
//
// The scenario is backend-independent: it is the state any crash between a
// frontier advance and a durable tile write leaves behind, on posix OR S3.

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// buildCommittedTree189 returns a committed root + its leaf set (the durable
// smt_leaves) + the first leaf key — the authoritative state that survives a
// crash in Postgres.
func buildCommittedTree189(t *testing.T, ctx context.Context, n int) ([32]byte, []types.SMTLeaf, [32]byte) {
	t.Helper()
	src := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	leaves := make([]types.SMTLeaf, 0, n)
	var firstKey [32]byte
	for i := 1; i <= n; i++ {
		var k [32]byte
		k[0], k[1], k[31] = byte(i), byte(i>>8), byte(0xff-i)
		if i == 1 {
			firstKey = k
		}
		leaf := types.SMTLeaf{
			Key:          k,
			OriginTip:    types.LogPosition{LogDID: "did:test:189", Sequence: uint64(i)},
			AuthorityTip: types.LogPosition{LogDID: "did:test:189", Sequence: uint64(i)},
		}
		if err := src.SetLeaf(ctx, k, leaf); err != nil {
			t.Fatalf("SetLeaf %d: %v", i, err)
		}
		leaves = append(leaves, leaf)
	}
	root, err := src.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	return root, leaves, firstKey
}

// proofResolves189 reports whether a membership proof for key at root can be
// served from the tile store — exactly what api/proofs.go does for a horizon-
// anchored request (GenerateSMTProof with SMTProofSourceTiles).
func proofResolves189(ctx context.Context, tiles SMTTileStore, cache *smt.TileCache, root, key [32]byte) error {
	p, _, err := GenerateSMTProof(ctx, SMTProofSourceTiles, nil, tiles, cache, root, key)
	if err != nil {
		return err
	}
	if p.TerminalKind != types.SMTTerminalLeaf || p.TerminalLeaf == nil || p.TerminalLeaf.Key != key {
		return errors.New("proof resolved but is not the expected membership proof")
	}
	return nil
}

// TestIssue189_CrashStrandsPublishedRoot_GateMustNotTrustFrontier runs the same
// post-crash scenario through the buggy gate and the fixed gate and asserts
// opposite outcomes — the RED/GREEN proof.
func TestIssue189_CrashStrandsPublishedRoot_GateMustNotTrustFrontier(t *testing.T) {
	ctx := context.Background()
	cache := smt.NewTileCache(256)

	committedRoot, leaves, key0 := buildCommittedTree189(t, ctx, 24)

	// Post-crash invariant, reconstructed exactly:
	//   smt_root_state.current_root = committedRoot   (durable, PG)
	//   tile_frontier.frontier_root = committedRoot   (durable, PG) ← the LIE
	//   smt_leaves                  = leaves          (durable, PG)
	//   in-memory node tail         = EMPTY           (SIGKILL wiped it)
	//   tile store                  = EMPTY           (un-fsync'd Put → 0 files post-crash)
	frontierRoot := committedRoot
	emptyTiles := NewMemSMTTileStore()

	// Boot precondition: with an empty substrate the published root is unservable
	// right now (the 500 the operator sees).
	if err := proofResolves189(ctx, emptyTiles, cache, committedRoot, key0); err == nil {
		t.Fatal("precondition: proof must NOT resolve against an empty substrate")
	}

	// One recovery decision, applied to the same post-crash state.
	runScenario := func(shouldRecover bool) error {
		tn := NewTailedNodeStore(smt.NewInMemoryNodeStore())
		localTiles := NewMemSMTTileStore()
		if shouldRecover {
			if err := RecoverTail(ctx, leaves, tn, committedRoot); err != nil {
				return err
			}
			if err := NewBuildTilesEmitter(tn, localTiles).
				EmitDurable(ctx, smt.EmptyHash, committedRoot, uint64(len(leaves))); err != nil {
				return err
			}
		}
		return proofResolves189(ctx, localTiles, cache, committedRoot, key0)
	}

	// RED — buggy gate: skip recovery when committed == frontier.
	buggyShouldRecover := committedRoot != frontierRoot // == false
	if err := runScenario(buggyShouldRecover); err == nil {
		t.Fatal("BUG NOT REPRODUCED: buggy gate served the proof; expected a permanent ErrUnknownRoot")
	} else {
		t.Logf("RED reproduced — buggy gate strands the published root: %v", err)
	}

	// GREEN — fixed gate: recover when committed != frontier OR tiles are absent.
	tilesPresent := TilesCoverRoot(ctx, emptyTiles, cache, committedRoot) // false
	fixedShouldRecover := committedRoot != frontierRoot || !tilesPresent  // true
	if !fixedShouldRecover {
		t.Fatal("fixed gate should decide to recover when tiles are absent")
	}
	if err := runScenario(fixedShouldRecover); err != nil {
		t.Fatalf("GREEN failed — fixed gate did NOT heal the published root: %v", err)
	}
	t.Log("GREEN — fixed gate replays smt_leaves + re-emits tiles; the published root's proof resolves")
}

// TestIssue189_TilesCoverRoot_DetectsMissingSubstrate pins the detector the fix
// relies on: false for a root whose tiles are absent (post-crash), true once
// emitted — so the gate can stop trusting the watermark.
func TestIssue189_TilesCoverRoot_DetectsMissingSubstrate(t *testing.T) {
	ctx := context.Background()
	cache := smt.NewTileCache(256)
	committedRoot, leaves, _ := buildCommittedTree189(t, ctx, 16)

	tiles := NewMemSMTTileStore()
	if TilesCoverRoot(ctx, tiles, cache, committedRoot) {
		t.Fatal("TilesCoverRoot = true on an EMPTY store; the watermark-trusting bug lives here")
	}

	tn := NewTailedNodeStore(smt.NewInMemoryNodeStore())
	if err := RecoverTail(ctx, leaves, tn, committedRoot); err != nil {
		t.Fatalf("RecoverTail: %v", err)
	}
	if err := NewBuildTilesEmitter(tn, tiles).
		EmitDurable(ctx, smt.EmptyHash, committedRoot, uint64(len(leaves))); err != nil {
		t.Fatalf("EmitDurable: %v", err)
	}
	if !TilesCoverRoot(ctx, tiles, cache, committedRoot) {
		t.Fatal("TilesCoverRoot = false after emit; detector is broken")
	}
	if !TilesCoverRoot(ctx, tiles, cache, smt.EmptyHash) {
		t.Fatal("EmptyHash must be reported as covered")
	}
}
