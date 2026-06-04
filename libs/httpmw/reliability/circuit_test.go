/*
FILE PATH: libs/httpmw/reliability/circuit_test.go

DESCRIPTION:

	Pins the three-state circuit breaker:
	  Closed → consecutive failures → Open
	  Open   → fast-fail with ErrCircuitOpen until cooldown elapses
	  Open   → cooldown elapsed → next call is HalfOpen
	  HalfOpen → ProbeWindow successes → Closed
	  HalfOpen → first failure → Open
*/
package reliability

import (
	"errors"
	"testing"
	"time"
)

var errProbe = errors.New("probe failure")

func TestBreaker_DefaultsApplied(t *testing.T) {
	b := NewBreaker(CircuitConfig{})
	if b.State() != "closed" {
		t.Errorf("initial state = %s, want closed", b.State())
	}
	if b.cfg.FailureThreshold != 5 {
		t.Errorf("FailureThreshold default drifted: %d", b.cfg.FailureThreshold)
	}
	if b.cfg.ProbeWindow != 3 {
		t.Errorf("ProbeWindow default drifted: %d", b.cfg.ProbeWindow)
	}
	if b.cfg.Cooldown != 30*time.Second {
		t.Errorf("Cooldown default drifted: %v", b.cfg.Cooldown)
	}
}

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	b := NewBreaker(CircuitConfig{FailureThreshold: 3})
	for i := 0; i < 3; i++ {
		if err := b.Call(func() error { return errProbe }); err != errProbe {
			t.Errorf("call %d: got %v, want errProbe", i, err)
		}
	}
	if b.State() != "open" {
		t.Errorf("state after 3 failures = %s, want open", b.State())
	}
	// Subsequent call fast-fails with ErrCircuitOpen.
	err := b.Call(func() error { return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("open state: got %v, want ErrCircuitOpen", err)
	}
}

func TestBreaker_SuccessResetsFailureCount(t *testing.T) {
	b := NewBreaker(CircuitConfig{FailureThreshold: 3})
	_ = b.Call(func() error { return errProbe })
	_ = b.Call(func() error { return errProbe })
	// Successful call resets the failure counter.
	_ = b.Call(func() error { return nil })
	// Two more failures alone don't trip the breaker now.
	_ = b.Call(func() error { return errProbe })
	_ = b.Call(func() error { return errProbe })
	if b.State() != "closed" {
		t.Errorf("after success-reset, state = %s, want closed", b.State())
	}
}

func TestBreaker_HalfOpen_ClosesOnProbeWindow(t *testing.T) {
	b := NewBreaker(CircuitConfig{
		FailureThreshold: 1, ProbeWindow: 2, Cooldown: 10 * time.Millisecond,
	})
	// Trip the breaker.
	_ = b.Call(func() error { return errProbe })
	if b.State() != "open" {
		t.Fatalf("state = %s, want open", b.State())
	}

	// Override the breaker's clock — bypass the real-time wait.
	b.nowFn = func() time.Time { return time.Now().Add(time.Hour) }

	// First call after cooldown → half-open + this call is the
	// first probe. ProbeWindow=2, so we need one more.
	if err := b.Call(func() error { return nil }); err != nil {
		t.Fatalf("first probe: %v", err)
	}
	if b.State() != "half_open" {
		t.Errorf("state after 1 probe = %s, want half_open", b.State())
	}
	// Second probe success closes the breaker.
	if err := b.Call(func() error { return nil }); err != nil {
		t.Fatalf("second probe: %v", err)
	}
	if b.State() != "closed" {
		t.Errorf("state after 2 probes = %s, want closed", b.State())
	}
}

func TestBreaker_HalfOpen_FailureReopens(t *testing.T) {
	b := NewBreaker(CircuitConfig{
		FailureThreshold: 1, ProbeWindow: 3, Cooldown: 10 * time.Millisecond,
	})
	_ = b.Call(func() error { return errProbe })
	b.nowFn = func() time.Time { return time.Now().Add(time.Hour) }

	// First probe fails → re-open.
	_ = b.Call(func() error { return errProbe })
	if b.State() != "open" {
		t.Errorf("after half-open failure, state = %s, want open", b.State())
	}
}

func TestBreaker_StateString_Stable(t *testing.T) {
	cases := []struct {
		s    circuitState
		want string
	}{
		{stateClosed, "closed"},
		{stateOpen, "open"},
		{stateHalfOpen, "half_open"},
	}
	for _, c := range cases {
		b := &Breaker{state: c.s}
		if got := b.State(); got != c.want {
			t.Errorf("State(%d) = %q, want %q", c.s, got, c.want)
		}
	}
}
