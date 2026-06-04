/*
FILE PATH: store/tail_recovery.go

RecoverTail rebuilds the in-memory SMT node tail after a restart.

The de-polluted commit path hands a batch's dirty nodes to an in-memory tail
(NOT Postgres) and the reconciler tiles them. A crash loses the tail, so on boot
the un-tiled gap (tile_frontier → committed root) lives nowhere durable except
smt_leaves. Because root = f(smt_leaves), replaying the committed leaf set
re-derives exactly those nodes: SetLeaves reads already-tiled subtrees through to
durable tiles and writes the un-tiled remainder into the tail. The rebuilt root
is checked against the committed root — an integrity assertion before serving.

Call ONLY when the tiles do not already cover the committed root
(frontier_root != committed_root); the reconciler then tiles the tail and prunes
it back down. (A gap-only replay would need a seq-keyed leaf scan; today the
whole tree is rebuilt transiently — a later optimization.)
*/
package store

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/core/smt"
	sdktypes "github.com/baseproof/baseproof/types"
)

// RecoverTail replays leaves into tailed and verifies the rebuilt root equals
// committedRoot.
func RecoverTail(ctx context.Context, leaves []sdktypes.SMTLeaf, tailed *TailedNodeStore, committedRoot [32]byte) error {
	if committedRoot == smt.EmptyHash || len(leaves) == 0 {
		return nil // empty tree — nothing to rebuild
	}
	// In-memory leaf store: SetLeaves writes leaves there (discarded — smt_leaves
	// is already authoritative) and the derived nodes into `tailed` (the tail,
	// reading ≤frontier nodes through to durable tiles).
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), tailed)
	if err := tree.SetLeaves(ctx, leaves); err != nil {
		return fmt.Errorf("store/tail-recovery: replay %d leaves: %w", len(leaves), err)
	}
	got, err := tree.Root(ctx)
	if err != nil {
		return fmt.Errorf("store/tail-recovery: root: %w", err)
	}
	if got != committedRoot {
		return fmt.Errorf("store/tail-recovery: rebuilt root %x != committed root %x (leaf set inconsistent with smt_root_state)", got[:8], committedRoot[:8])
	}
	return nil
}
