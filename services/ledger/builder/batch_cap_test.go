package builder

import "testing"

// TestClampBatchSize pins the per-cycle dequeue cap: non-positive falls back to
// the default, in-range passes through, and anything above MaxBatchSize is
// capped — so a misconfigured LEDGER_BATCH_SIZE can never unbound the in-memory
// node tail, the commit critical section, or the per-commitment mutation set.
func TestClampBatchSize(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{-1, defaultBatchSize},
		{0, defaultBatchSize},
		{1, 1},
		{512, 512},
		{MaxBatchSize, MaxBatchSize},
		{MaxBatchSize + 1, MaxBatchSize},
		{100_000, MaxBatchSize},
	}
	for _, c := range cases {
		if got := clampBatchSize(c.in, nil); got != c.want {
			t.Errorf("clampBatchSize(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
