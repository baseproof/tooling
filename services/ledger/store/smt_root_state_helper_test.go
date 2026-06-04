package store

import "testing"

// TestTreeSizeForCommittedSeq pins THE canonical seq↔tree_size boundary:
// tree_size (leaf count) = committed_through_seq (0-indexed) + 1. This is the
// single definition every consumer must route through; a regression here is the
// off-by-one that false-positived the integrity SMT detector.
func TestTreeSizeForCommittedSeq(t *testing.T) {
	cases := []struct {
		seq, wantTreeSize uint64
	}{
		{0, 1},   // first entry: seq 0 → tree_size 1
		{10, 11}, // the exact case from the captured divergence
		{9999, 10000},
	}
	for _, c := range cases {
		if got := TreeSizeForCommittedSeq(c.seq); got != c.wantTreeSize {
			t.Errorf("TreeSizeForCommittedSeq(%d) = %d, want %d", c.seq, got, c.wantTreeSize)
		}
		st := SMTRootState{CommittedThroughSeq: c.seq}
		if got := st.TreeSize(); got != c.wantTreeSize {
			t.Errorf("SMTRootState{seq=%d}.TreeSize() = %d, want %d", c.seq, got, c.wantTreeSize)
		}
	}
}
