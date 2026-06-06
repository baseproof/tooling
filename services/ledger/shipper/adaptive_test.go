package shipper

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/tooling/services/ledger/wal"
)

// burstBytestore returns a 500-like error whenever the number of CONCURRENT
// WriteEntry calls exceeds maxConcurrent — a store that throttles under burst
// (the seaweedfs/S3 failure mode). It records the peak concurrency it saw and how
// many requests it rejected, so a test can prove the limiter actually backed off.
type burstBytestore struct {
	mu            sync.Mutex
	inflight      int
	peak          int
	maxConcurrent int
	rejected      int
	stored        map[uint64]struct{}
}

func newBurstBytestore(maxConcurrent int) *burstBytestore {
	return &burstBytestore{maxConcurrent: maxConcurrent, stored: map[uint64]struct{}{}}
}

func (b *burstBytestore) WriteEntry(_ context.Context, seq uint64, _ [32]byte, _ []byte) error {
	b.mu.Lock()
	b.inflight++
	if b.inflight > b.peak {
		b.peak = b.inflight
	}
	over := b.inflight > b.maxConcurrent
	b.mu.Unlock()

	time.Sleep(2 * time.Millisecond) // hold the slot so concurrency is observable

	b.mu.Lock()
	defer b.mu.Unlock()
	b.inflight--
	if over {
		b.rejected++
		return errors.New("S3 500 InternalError: rate limit token exceeded (simulated)")
	}
	b.stored[seq] = struct{}{}
	return nil
}

func (b *burstBytestore) snapshot() (peak, rejected, stored int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peak, b.rejected, len(b.stored)
}

// TestShipper_AdaptiveBurst_CatchesUp: a store that 500s above maxConcurrent
// concurrent writes. The AIMD limiter backs off below that threshold, the writes
// start succeeding, and the WAL drains to completion — the head CATCHES UP instead
// of wedging. A fixed MaxInFlight above the threshold (the old behavior) would 500
// forever; here MaxInFlight is the CEILING and the limiter floats below it.
func TestShipper_AdaptiveBurst_CatchesUp(t *testing.T) {
	const n = 40
	const storeCeiling = 3 // the store 500s above 3 concurrent

	w := newFakeWAL()
	for seq := uint64(1); seq <= n; seq++ { // seqs 1..n (the WAL absorbs seq 0 at HWM=0)
		w.seed(seq, hashFor(seq), wireFor(seq))
	}
	bs := newBurstBytestore(storeCeiling)

	cfg := fastConfig()
	cfg.MaxInFlight = 12     // AIMD ceiling — well above the store's 3
	cfg.MaxAttempts = 100000 // relentless: never quarantine under the outage
	cfg.HealthyWindow = time.Second
	s := NewShipper(w, bs, cfg)

	// The head catches up: HWM reaches n and every entry is durably stored — the
	// WAL fully drains despite the store throttling under burst (no wedge).
	runUntilCondition(t, s, 10*time.Second, func() bool {
		hwm, _ := w.HWM(context.Background())
		_, _, stored := bs.snapshot()
		return hwm == n && stored == n
	})

	peak, rejected, stored := bs.snapshot()
	// The burst genuinely happened (so the test isn't trivially under the ceiling)…
	if peak <= storeCeiling {
		t.Fatalf("peak concurrency %d never exceeded the store ceiling %d — no burst exercised", peak, storeCeiling)
	}
	if rejected == 0 {
		t.Fatal("store never rejected a write — no burst exercised")
	}
	// …and the limiter backed OFF from the ceiling rather than wedging…
	if lim := s.limiter.currentLimit(); lim >= float64(cfg.MaxInFlight) {
		t.Errorf("AIMD limit stayed at the ceiling %v — it must back off under the store's 500s", lim)
	}
	// …and everything still shipped (caught up, no wedge, no give-up).
	if stored != n {
		t.Fatalf("only %d/%d entries durably stored — the head did not catch up", stored, n)
	}
}

// TestShipper_Relentless_NoManualDuringOutage: while the store is unhealthy (no
// recent success), an entry that exhausts MaxAttempts is RETRIED, never marked
// StateManual — so a transient outage lets the head lag and catch up, not wedge.
func TestShipper_Relentless_NoManualDuringOutage(t *testing.T) {
	w := newFakeWAL()
	w.seed(0, hashFor(0), wireFor(0))
	cfg := fastConfig()
	cfg.MaxAttempts = 2
	s := NewShipper(w, newFakeBytestore(), cfg) // fresh limiter ⇒ lastSuccess zero ⇒ unhealthy

	ctx := context.Background()
	e := wal.SequencedEntry{Seq: 0, Hash: hashFor(0)}
	for i := 0; i < 6; i++ { // well past MaxAttempts
		s.recordFailure(ctx, e)
	}
	meta, _ := w.MetaState(ctx, hashFor(0))
	if meta.State == wal.StateManual {
		t.Fatal("entry quarantined during a store outage — it must retry relentlessly (no recent success)")
	}
	if meta.Attempts < cfg.MaxAttempts {
		t.Fatalf("attempts did not accrue: got %d", meta.Attempts)
	}
}

// TestShipper_Poison_QuarantinedWhenStoreHealthy: the safety valve still fires — a
// store that's HEALTHY (recent success) with ONE entry that keeps failing
// quarantines that entry after MaxAttempts so it cannot stall the HWM forever.
func TestShipper_Poison_QuarantinedWhenStoreHealthy(t *testing.T) {
	w := newFakeWAL()
	w.seed(0, hashFor(0), wireFor(0))
	cfg := fastConfig()
	cfg.MaxAttempts = 2
	cfg.HealthyWindow = time.Minute
	s := NewShipper(w, newFakeBytestore(), cfg)
	s.limiter.release(true) // a recent success ⇒ the store is healthy

	ctx := context.Background()
	e := wal.SequencedEntry{Seq: 0, Hash: hashFor(0)}
	for i := 0; i < 3; i++ {
		s.recordFailure(ctx, e)
	}
	meta, _ := w.MetaState(ctx, hashFor(0))
	if meta.State != wal.StateManual {
		t.Fatalf("a poison entry on a HEALTHY store must be quarantined, got state=%v", meta.State)
	}
}
