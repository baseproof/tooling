package store

import (
	"testing"

	"github.com/baseproof/baseproof/core/smt"
)

// TestPruneOrphans proves the orphan-prune evicts CROSS-BATCH orphans (nodes
// superseded by a later batch, so unreachable from the latest committed root)
// while RETAINING everything reachable from that root — the un-tiled gap — even
// when nothing is durable in tiles. The retention half is the load-bearing one:
// the prune must never drop a node a committed root still needs. (br / fakeTiles
// are shared with tailed_node_store_audit_test.go.)
func TestPruneOrphans(t *testing.T) {
	leafA := br(200, smt.EmptyHash, smt.EmptyHash)
	leafB := br(201, smt.EmptyHash, smt.EmptyHash)
	hA, hB := smt.HashNode(leafA), smt.HashNode(leafB)
	committedRoot := br(1, hA, smt.EmptyHash)
	orphanRoot := br(2, hB, smt.EmptyHash)
	hC, hO := smt.HashNode(committedRoot), smt.HashNode(orphanRoot)

	present := func(s *TailedNodeStore, h [32]byte) bool { n, _ := s.Get(h); return n != nil }

	// Nothing durable in tiles, so retention can't be "rescued" by the read-through
	// — the tail alone must keep the live gap.
	s := NewTailedNodeStore(&fakeTiles{})
	// batch 1: orphanRoot is the committed root, leafB its child.
	s.PutBatchCommitted([]smt.Node{orphanRoot, leafB}, hO)
	// batch 2 supersedes it: committedRoot/leafA are the live state; batch 1's nodes
	// are now orphaned (unreachable from the new committed root, never tiled).
	s.PutBatchCommitted([]smt.Node{committedRoot, leafA}, hC)

	for _, h := range [][32]byte{hC, hA, hO, hB} {
		if !present(s, h) {
			t.Fatalf("pre-prune: %x missing", h[:4])
		}
	}

	dropped := s.PruneOrphans()
	if dropped != 2 {
		t.Errorf("dropped=%d, want 2 (orphanRoot + leafB)", dropped)
	}
	// RETENTION (load-bearing): the live gap — reachable from the committed root,
	// NOT durable — must remain servable.
	if !present(s, hC) || !present(s, hA) {
		t.Error("orphan-prune dropped a node reachable from the committed root — a data-serving gap")
	}
	// ORPHANS: the superseded version + its child are gone.
	if present(s, hO) || present(s, hB) {
		t.Error("orphan-prune did not evict the cross-batch orphans")
	}

	// Guard: a store with no committed root set never drops blindly.
	s2 := NewTailedNodeStore(&fakeTiles{})
	s2.PutBatch([]smt.Node{leafA, leafB})
	if d := s2.PruneOrphans(); d != 0 {
		t.Errorf("PruneOrphans with no committed root dropped %d, want 0", d)
	}
}
