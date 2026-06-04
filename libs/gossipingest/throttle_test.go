/*
FILE PATH: libs/gossipingest/throttle_test.go

Ladder 5 P9 (#21) — race-detector + boundary tests for the Throttler.

# WHAT THIS PINS

 1. Constructor validation: nil inner / nil logger / non-positive
    capacity all return ErrInvalidConfig-shape errors at construction,
    NOT at runtime.

 2. Bounded concurrency: with Capacity=N, at most N HandleSignedEvent
    calls run concurrently. The N+1st blocks until a slot frees.

 3. Saturation accessor truthfulness: InFlight() and Saturation()
    report the actual in-flight count across the lifecycle.

 4. Ctx cancellation during acquire: when at capacity and ctx is
    cancelled, the blocked call returns ctx.Err() WITHOUT entering
    the wrapped sink.

 5. Inner ctx propagation: ctx flows to the wrapped sink unchanged;
    the wrapped sink's response (success/error) flows back unchanged.

 6. Slot release on inner-sink error: a wrapped sink that returns
    an error still releases its slot — no leak across error paths.

 7. Race-cleanliness: N writers × M deliveries each runs cleanly
    under -race with no DATA RACE reports.
*/
package gossipingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baseproof/baseproof/gossip"
)

// fakeSink is a configurable SignedEventSink stand-in. Each call
// increments callCount, optionally blocks on the supplied gate
// channel, optionally returns a configured error.
type fakeSink struct {
	callCount atomic.Int64
	// inFlight tracks concurrent callers; the max observed is used to
	// verify the throttle's bound.
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
	// gate, if non-nil, blocks each call until its receive succeeds.
	// Useful for staging "hold N callers, then release" tests.
	gate chan struct{}
	// err, if non-nil, is returned by every call (slot still released).
	err error
}

func (f *fakeSink) HandleSignedEvent(ctx context.Context, ev gossip.SignedEvent) error {
	cur := f.inFlight.Add(1)
	// Track max observed concurrency (CAS-loop on the high-water mark).
	for {
		max := f.maxInFlight.Load()
		if cur <= max {
			break
		}
		if f.maxInFlight.CompareAndSwap(max, cur) {
			break
		}
	}
	defer f.inFlight.Add(-1)
	f.callCount.Add(1)

	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ─────────────────────────────────────────────────────────────────
// Constructor validation
// ─────────────────────────────────────────────────────────────────

func TestNewThrottler_RejectsNilInner(t *testing.T) {
	_, err := NewThrottler(nil, 4, discardLogger())
	if err == nil {
		t.Fatal("nil inner sink must error")
	}
	if !strings.Contains(err.Error(), "inner sink") {
		t.Errorf("error must name the missing field; got: %v", err)
	}
}

func TestNewThrottler_RejectsNilLogger(t *testing.T) {
	_, err := NewThrottler(&fakeSink{}, 4, nil)
	if err == nil {
		t.Fatal("nil logger must error")
	}
}

func TestNewThrottler_RejectsZeroCapacity(t *testing.T) {
	_, err := NewThrottler(&fakeSink{}, 0, discardLogger())
	if err == nil {
		t.Fatal("zero capacity must error")
	}
	if !strings.Contains(err.Error(), "capacity") {
		t.Errorf("error must name capacity; got: %v", err)
	}
}

func TestNewThrottler_RejectsNegativeCapacity(t *testing.T) {
	_, err := NewThrottler(&fakeSink{}, -1, discardLogger())
	if err == nil {
		t.Fatal("negative capacity must error")
	}
}

// ─────────────────────────────────────────────────────────────────
// Bounded concurrency
// ─────────────────────────────────────────────────────────────────

// TestThrottler_BoundsConcurrency pins the load-bearing invariant:
// with Capacity=N, the throttle NEVER lets more than N
// HandleSignedEvent calls run concurrently. The test launches
// 4 × Capacity goroutines all targeting the same throttle; each
// goroutine's wrapped-sink call blocks on a gate until the test
// releases it. The test asserts that the fakeSink's observed
// maxInFlight is exactly Capacity (not Capacity+1, not less).
func TestThrottler_BoundsConcurrency(t *testing.T) {
	const capacity = 3
	const workers = 12 // 4× capacity

	sink := &fakeSink{gate: make(chan struct{})}
	thr, err := NewThrottler(sink, capacity, discardLogger())
	if err != nil {
		t.Fatalf("NewThrottler: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_ = thr.HandleSignedEvent(context.Background(), gossip.SignedEvent{})
		}()
	}

	// Wait until exactly capacity callers are blocked at the gate.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sink.inFlight.Load() == capacity {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := sink.inFlight.Load(); got != capacity {
		t.Fatalf("expected exactly %d in-flight at the gate; got %d", capacity, got)
	}

	// Throttler's InFlight() must agree (single source of truth).
	if got := thr.InFlight(); got != capacity {
		t.Errorf("Throttler.InFlight() = %d, want %d", got, capacity)
	}
	if got := thr.Saturation(); got != 1.0 {
		t.Errorf("Throttler.Saturation() at full capacity = %v, want 1.0", got)
	}

	// Release all gates in succession; all workers eventually exit.
	for i := 0; i < workers; i++ {
		sink.gate <- struct{}{}
	}
	wg.Wait()

	// Across the full run, max observed concurrency MUST be exactly
	// capacity — never higher (throttle bound), never lower (test
	// saturated the gate).
	if got := sink.maxInFlight.Load(); got != int64(capacity) {
		t.Errorf("max observed in-flight = %d, want %d (throttle bound violated)",
			got, capacity)
	}
	if got := sink.callCount.Load(); got != int64(workers) {
		t.Errorf("call count = %d, want %d", got, workers)
	}
}

// ─────────────────────────────────────────────────────────────────
// Saturation accessor
// ─────────────────────────────────────────────────────────────────

func TestThrottler_SaturationLifecycle(t *testing.T) {
	const capacity = 4
	sink := &fakeSink{gate: make(chan struct{})}
	thr, err := NewThrottler(sink, capacity, discardLogger())
	if err != nil {
		t.Fatalf("NewThrottler: %v", err)
	}

	// Empty: 0 / capacity = 0.0.
	if got := thr.Saturation(); got != 0.0 {
		t.Errorf("empty Saturation = %v, want 0.0", got)
	}

	// 2-of-4 in-flight: 0.5.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = thr.HandleSignedEvent(context.Background(), gossip.SignedEvent{})
		}()
	}
	// Wait until both have arrived at the gate.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if sink.inFlight.Load() == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := thr.InFlight(); got != 2 {
		t.Errorf("InFlight = %d, want 2", got)
	}
	if got := thr.Saturation(); got != 0.5 {
		t.Errorf("half-capacity Saturation = %v, want 0.5", got)
	}
	if got := thr.Capacity(); got != capacity {
		t.Errorf("Capacity = %d, want %d", got, capacity)
	}

	// Release and let them exit; saturation returns to 0.
	sink.gate <- struct{}{}
	sink.gate <- struct{}{}
	wg.Wait()
	// Give the deferred release of the throttle slot a moment to land.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if thr.InFlight() == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := thr.InFlight(); got != 0 {
		t.Errorf("post-release InFlight = %d, want 0", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// Ctx cancellation during acquire
// ─────────────────────────────────────────────────────────────────

// TestThrottler_CtxCancelDuringAcquire pins the structural invariant:
// when at capacity and ctx is cancelled, the blocked call returns
// ctx.Err() WITHOUT entering the wrapped sink. This matters because
// a flood of cancelled-during-acquire requests must not increment
// the wrapped sink's invocation count (e.g., spurious DB writes).
func TestThrottler_CtxCancelDuringAcquire(t *testing.T) {
	const capacity = 1
	sink := &fakeSink{gate: make(chan struct{})}
	thr, err := NewThrottler(sink, capacity, discardLogger())
	if err != nil {
		t.Fatalf("NewThrottler: %v", err)
	}

	// Saturate the throttle: one in-flight caller holds the only slot.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = thr.HandleSignedEvent(context.Background(), gossip.SignedEvent{})
	}()
	// Wait until the holder is at the gate.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if sink.inFlight.Load() == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Issue a second call with a cancellable ctx; cancel before any
	// slot frees. It MUST return ctx.Err and MUST NOT increment the
	// sink's call count.
	cancellable, cancel := context.WithCancel(context.Background())
	secondErr := make(chan error, 1)
	go func() { secondErr <- thr.HandleSignedEvent(cancellable, gossip.SignedEvent{}) }()
	// Give the second call a moment to enter its Acquire select.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-secondErr:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ctx-cancelled acquire must return context.Canceled; got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled acquire did not return within 1s")
	}

	// Verify the wrapped sink was NOT entered by the cancelled call.
	// Only the first (holder) call should have incremented callCount.
	if got := sink.callCount.Load(); got != 1 {
		t.Errorf("wrapped sink invocations = %d, want 1 (cancelled acquire must skip sink)", got)
	}

	// Release the holder for clean shutdown.
	sink.gate <- struct{}{}
	wg.Wait()
}

// ─────────────────────────────────────────────────────────────────
// Inner sink error propagation + slot release
// ─────────────────────────────────────────────────────────────────

// TestThrottler_InnerErrorReleasesSlot pins the no-leak invariant:
// when the wrapped sink returns an error, the throttle's slot still
// releases. A future-throttler implementation that conditioned the
// release on success would leak slots on every verify failure,
// silently degrading to capacity-0 over time.
func TestThrottler_InnerErrorReleasesSlot(t *testing.T) {
	const capacity = 2
	wantErr := errors.New("inner sink failed")
	sink := &fakeSink{err: wantErr}
	thr, err := NewThrottler(sink, capacity, discardLogger())
	if err != nil {
		t.Fatalf("NewThrottler: %v", err)
	}

	// Run 8 sequential calls, every one returning the inner error.
	// After all complete, the slot count MUST be back to 0.
	for i := 0; i < 8; i++ {
		got := thr.HandleSignedEvent(context.Background(), gossip.SignedEvent{})
		if !errors.Is(got, wantErr) {
			t.Errorf("call %d: got err %v, want %v", i, got, wantErr)
		}
	}
	if got := thr.InFlight(); got != 0 {
		t.Errorf("post-error InFlight = %d, want 0 (slot leak)", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// Race-detector workload
// ─────────────────────────────────────────────────────────────────

// TestThrottler_ConcurrentDeliveries_RaceClean pins the goroutine-
// safety invariant: N writers × M deliveries each runs cleanly with
// no DATA RACE reports under -race. Verifies that the channel-based
// semaphore + InFlight accessor are safe for concurrent readers.
//
// Sized small enough to run fast (16 × 64 = 1024 deliveries) but
// thick enough that a missing-fence would surface as a race report.
func TestThrottler_ConcurrentDeliveries_RaceClean(t *testing.T) {
	const writers = 16
	const perWriter = 64
	const capacity = 8

	sink := &fakeSink{} // no gate; deliveries return immediately
	thr, err := NewThrottler(sink, capacity, discardLogger())
	if err != nil {
		t.Fatalf("NewThrottler: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				_ = thr.HandleSignedEvent(context.Background(), gossip.SignedEvent{})
				// Concurrent read of accessors — a missing fence around
				// the channel-len would surface here.
				_ = thr.InFlight()
				_ = thr.Saturation()
				_ = thr.Capacity()
			}
		}()
	}
	wg.Wait()

	wantCalls := int64(writers * perWriter)
	if got := sink.callCount.Load(); got != wantCalls {
		t.Errorf("call count = %d, want %d", got, wantCalls)
	}
	if got := thr.InFlight(); got != 0 {
		t.Errorf("post-run InFlight = %d, want 0", got)
	}
}

// ─────────────────────────────────────────────────────────────────
// Quiet-log assertion (regression guard)
// ─────────────────────────────────────────────────────────────────

// TestThrottler_LogsNothingOnHappyPath pins a posture choice: the
// happy-path Throttler is silent. A future contributor adding
// per-call info logging at 1K+ TPS would flood the operator's log;
// this test fails if any log line is emitted by a normal delivery.
//
// The Throttler MAY log saturation-threshold crossings or other
// rare events in the future; those would warrant explicit tests
// against a configured logger buffer. For now the no-log baseline
// is the safe default.
func TestThrottler_LogsNothingOnHappyPath(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	thr, err := NewThrottler(&fakeSink{}, 4, logger)
	if err != nil {
		t.Fatalf("NewThrottler: %v", err)
	}
	for i := 0; i < 10; i++ {
		if err := thr.HandleSignedEvent(context.Background(), gossip.SignedEvent{}); err != nil {
			t.Fatalf("delivery: %v", err)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("happy-path delivery must not log; got: %s",
			fmt.Sprintf("%q", buf.String()))
	}
}
