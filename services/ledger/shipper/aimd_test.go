package shipper

import (
	"context"
	"testing"
	"time"
)

// Failures halve the limit (multiplicative decrease) to the floor; successes ramp
// it additively back to the ceiling.
func TestAIMD_BacksOffAndRamps(t *testing.T) {
	l := newAIMDLimiter(1, 8, 0.5) // optimistic start at max=8
	if got := l.currentLimit(); got != 8 {
		t.Fatalf("start limit = %v, want 8 (optimistic at the ceiling)", got)
	}
	for _, want := range []float64{4, 2, 1, 1} { // halve, floored at min=1
		l.release(false)
		if got := l.currentLimit(); got != want {
			t.Fatalf("after a failure: limit = %v, want %v", got, want)
		}
	}
	for i := 0; i < 40; i++ { // +0.5 each, capped at max=8
		l.release(true)
	}
	if got := l.currentLimit(); got != 8 {
		t.Fatalf("after many successes: limit = %v, want capped at 8", got)
	}
}

// acquire blocks once inflight reaches the current limit and wakes on a release.
func TestAIMD_AcquireBlocksAtLimitAndWakesOnRelease(t *testing.T) {
	l := newAIMDLimiter(1, 1, 0.5) // limit pinned at 1
	ctx := context.Background()
	if err := l.acquire(ctx); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	acquired := make(chan struct{})
	go func() {
		_ = l.acquire(ctx)
		close(acquired)
	}()
	select {
	case <-acquired:
		t.Fatal("second acquire returned while at the limit — it must block")
	case <-time.After(50 * time.Millisecond):
	}
	l.release(true) // frees the slot
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("acquire did not wake after release")
	}
}

// acquire returns the context error when cancelled while parked.
func TestAIMD_AcquireRespectsContext(t *testing.T) {
	l := newAIMDLimiter(1, 1, 0.5)
	_ = l.acquire(context.Background()) // take the only slot
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.acquire(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("acquire must return the ctx error on cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("acquire did not return on ctx cancel")
	}
}

// healthy() tracks "an upload succeeded within window" — the signal the failure
// path uses to tell an outage (relentless retry) from a poison entry (quarantine).
func TestAIMD_HealthSignal(t *testing.T) {
	l := newAIMDLimiter(1, 4, 0.5)
	if l.healthy(time.Second) {
		t.Fatal("no success yet ⇒ NOT healthy (relentless during a cold outage)")
	}
	l.release(true) // a success now
	if !l.healthy(time.Second) {
		t.Fatal("just succeeded ⇒ healthy")
	}
	if l.healthy(time.Nanosecond) {
		t.Fatal("success older than the window ⇒ not healthy")
	}
}
