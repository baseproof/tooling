package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSubmitConcurrentOrderPreserved asserts results[i] corresponds to items[i]
// regardless of which worker finishes first — the property the epoch's sequence
// discovery relies on to pair an SCT hash back to its built entity.
func TestSubmitConcurrentOrderPreserved(t *testing.T) {
	const nItems = 500
	items := make([]int, nItems)
	for i := range items {
		items[i] = i
	}
	got := submitConcurrent(8, items, func(v int) string {
		return fmt.Sprintf("h-%d", v)
	})
	if len(got) != nItems {
		t.Fatalf("len(got) = %d, want %d", len(got), nItems)
	}
	for i := range got {
		if want := fmt.Sprintf("h-%d", i); got[i] != want {
			t.Fatalf("got[%d] = %q, want %q (order not preserved)", i, got[i], want)
		}
	}
}

// TestSubmitConcurrentRunsAllExactlyOnce asserts every item is submitted exactly
// once (no dropped or duplicated work) across the pool.
func TestSubmitConcurrentRunsAllExactlyOnce(t *testing.T) {
	const nItems = 1000
	items := make([]int, nItems)
	for i := range items {
		items[i] = i
	}
	var calls int64
	var mu sync.Mutex
	seen := make(map[int]int, nItems)
	submitConcurrent(16, items, func(v int) string {
		atomic.AddInt64(&calls, 1)
		mu.Lock()
		seen[v]++
		mu.Unlock()
		return ""
	})
	if calls != nItems {
		t.Fatalf("submit called %d times, want %d", calls, nItems)
	}
	for i := 0; i < nItems; i++ {
		if seen[i] != 1 {
			t.Fatalf("item %d submitted %d times, want exactly 1", i, seen[i])
		}
	}
}

// TestSubmitConcurrentBoundsInFlight asserts no more than `workers` submissions
// are ever active at once — the bounded-in-flight guarantee.
func TestSubmitConcurrentBoundsInFlight(t *testing.T) {
	const (
		nItems  = 2000
		workers = 4
	)
	items := make([]int, nItems)
	var inFlight, maxInFlight int64
	submitConcurrent(workers, items, func(int) string {
		cur := atomic.AddInt64(&inFlight, 1)
		for {
			old := atomic.LoadInt64(&maxInFlight)
			if cur <= old || atomic.CompareAndSwapInt64(&maxInFlight, old, cur) {
				break
			}
		}
		// brief spin so overlap is observable
		for i := 0; i < 1000; i++ {
			_ = i
		}
		atomic.AddInt64(&inFlight, -1)
		return ""
	})
	if maxInFlight > workers {
		t.Fatalf("max in-flight = %d, exceeds workers = %d", maxInFlight, workers)
	}
	if maxInFlight < 1 {
		t.Fatalf("max in-flight = %d, expected work to run", maxInFlight)
	}
}

// TestSubmitConcurrentWorkersFloor asserts workers<1 is clamped to 1 (still runs
// all items) rather than deadlocking on a zero-worker pool.
func TestSubmitConcurrentWorkersFloor(t *testing.T) {
	items := []int{1, 2, 3}
	got := submitConcurrent(0, items, func(v int) string {
		return fmt.Sprintf("%d", v)
	})
	want := []string{"1", "2", "3"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestSubmitConcurrentEmpty asserts the empty-batch case returns an empty slice
// without spawning a stuck pool.
func TestSubmitConcurrentEmpty(t *testing.T) {
	got := submitConcurrent(4, []int{}, func(int) string { return "x" })
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
}
