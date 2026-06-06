package shipper

import (
	"context"
	"math"
	"sync"
	"time"
)

/*
aimdLimiter is additive-increase / multiplicative-decrease concurrency control —
TCP-style congestion control for the shipper's uploads to the byte store.

WHY. The store (S3 / SeaweedFS / GCS) has a request-rate ceiling. A FIXED
MaxInFlight is either too slow normally or overwhelms the store under a burst —
and once the store starts returning 500/503 the AWS SDK's own client-side retry
budget collapses (the "retry quota exceeded, 0 available" wedge). Instead, the
limiter DISCOVERS the store's sustainable concurrency at runtime: every success
nudges the limit up (additive); every failure halves it (multiplicative). It
floats in [min, max]; max is the worker-pool ceiling. The result is that the
durable head LAGS the store's real rate under load and CATCHES UP when the burst
eases — it never wedges, and it needs no magic constant.

HEALTH SIGNAL. The limiter also tracks whether an upload has SUCCEEDED recently,
which the failure path uses to tell a transient store OUTAGE (no recent success ⇒
retry relentlessly, never quarantine) apart from a POISON entry (store demonstrably
healthy, yet one entry keeps failing ⇒ quarantine it so it cannot stall the HWM /
grow the advancer's hold set unbounded).
*/
type aimdLimiter struct {
	mu  sync.Mutex
	gen chan struct{} // closed on each release to wake acquire() waiters

	limit    float64 // current concurrency limit (float for smooth additive increase)
	inflight int
	min, max float64
	step     float64 // additive increase per success

	lastSuccess time.Time
}

// newAIMDLimiter starts OPTIMISTIC at max and backs off under failure. min is
// floored at 1 so the limiter always probes for the store's recovery. step is the
// additive increase per success (defaults to 0.5 — a gentle ramp that resists
// oscillation).
func newAIMDLimiter(min, max int, step float64) *aimdLimiter {
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	if step <= 0 {
		step = 0.5
	}
	return &aimdLimiter{
		gen:   make(chan struct{}),
		limit: float64(max),
		min:   float64(min),
		max:   float64(max),
		step:  step,
	}
}

// acquire blocks until an upload slot is free under the CURRENT limit, or ctx is
// cancelled. Workers park here when the limiter has backed off; backpressure then
// propagates up through the work channel to the scanner (which pauses), so nothing
// is dropped — entries simply wait their turn in the durable WAL.
func (l *aimdLimiter) acquire(ctx context.Context) error {
	for {
		l.mu.Lock()
		if float64(l.inflight) < l.limit {
			l.inflight++
			l.mu.Unlock()
			return nil
		}
		wait := l.gen // capture under lock; a release closes exactly this generation
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait:
			// a release happened — re-check the (possibly lower) limit.
		}
	}
}

// release returns a slot and ADAPTS the limit: success → additive increase (and
// marks the store healthy at now); failure → multiplicative decrease (halve,
// floored at min). It wakes parked acquirers so they re-evaluate the new limit.
func (l *aimdLimiter) release(success bool) {
	l.mu.Lock()
	if l.inflight > 0 {
		l.inflight--
	}
	if success {
		l.limit = math.Min(l.max, l.limit+l.step)
		l.lastSuccess = time.Now()
	} else {
		l.limit = math.Max(l.min, l.limit/2)
	}
	close(l.gen) // wake all waiters
	l.gen = make(chan struct{})
	l.mu.Unlock()
}

// healthy reports whether an upload SUCCEEDED within window — i.e. the store is
// actually working. The failure path quarantines a poison entry only when the
// store is healthy; during an outage (no recent success) every failure is a retry,
// so the head lags and catches up rather than wedging.
func (l *aimdLimiter) healthy(window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.lastSuccess.IsZero() && time.Since(l.lastSuccess) < window
}

// currentLimit exposes the live limit for metrics + tests.
func (l *aimdLimiter) currentLimit() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}
