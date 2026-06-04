package builder

import "testing"

func TestTileLagExceeded(t *testing.T) {
	cases := []struct {
		name                        string
		committed, frontier, maxLag uint64
		want                        bool
	}{
		{"caught up", 100, 100, 50, false},
		{"within bound", 100, 60, 50, false}, // lag 40 ≤ 50
		{"at bound", 100, 50, 50, false},     // lag 50, not > 50
		{"exceeds bound", 100, 49, 50, true}, // lag 51 > 50
		{"disabled (maxLag 0)", 100, 0, 0, false},
		{"frontier ahead (impossible) → no backpressure", 100, 200, 50, false},
	}
	for _, c := range cases {
		if got := tileLagExceeded(c.committed, c.frontier, c.maxLag); got != c.want {
			t.Errorf("%s: tileLagExceeded(%d,%d,%d) = %v, want %v", c.name, c.committed, c.frontier, c.maxLag, got, c.want)
		}
	}
}
