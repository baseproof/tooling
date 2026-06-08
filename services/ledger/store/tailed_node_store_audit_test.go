package store

import (
	"testing"

	"github.com/baseproof/baseproof/core/smt"
)

// fakeTiles is a controllable durable read-through: Get returns a node iff its
// hash was marked durable (present in the map).
type fakeTiles struct{ durable map[[32]byte]smt.Node }

func (f *fakeTiles) Get(h [32]byte) (smt.Node, error) { return f.durable[h], nil }
func (f *fakeTiles) Put(smt.Node) ([32]byte, error)   { return [32]byte{}, nil }

// br builds a distinct BranchNode (distinct fields ⇒ distinct content hash).
func br(depth uint16, l, r [32]byte) *smt.BranchNode {
	var p [32]byte
	p[0] = byte(depth)
	return &smt.BranchNode{BranchDepth: depth, Prefix: p, LeftHash: l, RightHash: r}
}

// TestTailGCAudit proves the non-destructive audit flags exactly the unsafe case:
// a tail node reachable from a published root, NOT reachable from the committed
// root (so the orphan-prune would drop it), and NOT durable in tiles — dropping
// it would strand a published root. The safe cases (durable, or no published
// root) report zero violations.
func TestTailGCAudit(t *testing.T) {
	// Tail DAG:
	//   committedRoot → leafA
	//   pubRoot       → leafA (shared) + leafC
	// leafC is reachable from the published root but not from committed.
	leafA := br(200, smt.EmptyHash, smt.EmptyHash)
	leafC := br(201, smt.EmptyHash, smt.EmptyHash)
	hA := smt.HashNode(leafA)
	hC := smt.HashNode(leafC)
	committedRoot := br(1, hA, smt.EmptyHash)
	pubRoot := br(2, hA, hC)
	hCommitted := smt.HashNode(committedRoot)
	hPub := smt.HashNode(pubRoot)

	newStore := func(durable map[[32]byte]smt.Node) *TailedNodeStore {
		s := NewTailedNodeStore(&fakeTiles{durable: durable})
		s.PutBatch([]smt.Node{committedRoot, leafA, pubRoot, leafC})
		return s
	}

	// (1) VIOLATION: leafC reachable from pubRoot, not committed, and NOT durable.
	s := newStore(map[[32]byte]smt.Node{hPub: pubRoot}) // pubRoot durable; leafC is not
	cand, viol, sample := s.TailGCAudit(hCommitted, [][32]byte{hPub})
	if cand == 0 {
		t.Fatal("expected candidates: pubRoot/leafC are reachable-from-published but not committed")
	}
	if viol != 1 || sample != hC {
		t.Errorf("expected exactly 1 violation (leafC %x); got viol=%d sample=%x", hC[:4], viol, sample[:4])
	}

	// (2) SAFE: same shape, but leafC IS durable in tiles ⇒ servable after a drop.
	s = newStore(map[[32]byte]smt.Node{hPub: pubRoot, hC: leafC})
	if _, viol, _ := s.TailGCAudit(hCommitted, [][32]byte{hPub}); viol != 0 {
		t.Errorf("a durable candidate must not be a violation; got %d", viol)
	}

	// (3) No published roots ⇒ pure orphans, trivially safe (the prune drops them,
	// nothing references them) ⇒ zero candidates/violations.
	s = newStore(nil)
	if cand, viol, _ := s.TailGCAudit(hCommitted, nil); cand != 0 || viol != 0 {
		t.Errorf("no published roots ⇒ no candidates/violations; got cand=%d viol=%d", cand, viol)
	}
}
