/*
FILE PATH: libs/httpmw/reliability/circuit.go

DESCRIPTION:

	Minimal three-state circuit breaker for outbound HTTP calls
	(ledger submit, artifact-store push, etc.). Pattern is the
	standard circuit-breaker:

	  Closed    — calls pass through, failures counted.
	  Open      — failures exceeded threshold; calls fast-fail with
	              ErrCircuitOpen until cooldown elapses.
	  HalfOpen  — cooldown elapsed; limited probe traffic allowed.
	              ProbeWindow successes → Closed; first failure → Open.

	The implementation is intentionally tiny — gobreaker is
	well-tested but pulls a transitive that the JN binary doesn't
	otherwise need; the failure-counting + state machine here are
	~80 LoC and unit-testable in isolation.

	Defaults are conservative for the JN→ledger path: 5 failures
	in a row → open; 30s cooldown; 3 consecutive probe successes →
	close. Override per call site.
*/
package reliability

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned by Call when the breaker is open
// (fast-fail). Callers errors.Is this to distinguish breaker
// rejection from upstream failure.
var ErrCircuitOpen = errors.New("circuit breaker open")

// State of the breaker.
type circuitState int

const (
	stateClosed circuitState = iota
	stateOpen
	stateHalfOpen
)

// CircuitConfig configures the breaker. Zero values fall back
// to documented defaults.
type CircuitConfig struct {
	// FailureThreshold is the number of consecutive failures
	// required to open the breaker. Default 5.
	FailureThreshold int

	// ProbeWindow is the number of consecutive probe successes
	// required to close from half-open. Default 3.
	ProbeWindow int

	// Cooldown is the wall-clock duration the breaker stays open
	// before transitioning to half-open. Default 30s.
	Cooldown time.Duration
}

// DefaultCircuitConfig returns the production-tuned defaults.
func DefaultCircuitConfig() CircuitConfig {
	return CircuitConfig{
		FailureThreshold: 5,
		ProbeWindow:      3,
		Cooldown:         30 * time.Second,
	}
}

// Breaker is a goroutine-safe circuit breaker.
type Breaker struct {
	cfg CircuitConfig

	mu              sync.Mutex
	state           circuitState
	consecFailures  int
	consecSuccesses int
	openedAt        time.Time

	// nowFn is overridable in tests so cooldown doesn't depend on
	// real wall-clock time. Production paths leave it nil; the
	// breaker uses time.Now.
	nowFn func() time.Time
}

// NewBreaker constructs a breaker with cfg's defaults filled in.
func NewBreaker(cfg CircuitConfig) *Breaker {
	d := DefaultCircuitConfig()
	if cfg.FailureThreshold > 0 {
		d.FailureThreshold = cfg.FailureThreshold
	}
	if cfg.ProbeWindow > 0 {
		d.ProbeWindow = cfg.ProbeWindow
	}
	if cfg.Cooldown > 0 {
		d.Cooldown = cfg.Cooldown
	}
	return &Breaker{cfg: d, state: stateClosed}
}

func (b *Breaker) now() time.Time {
	if b.nowFn != nil {
		return b.nowFn()
	}
	return time.Now()
}

// Call invokes fn through the breaker. Returns ErrCircuitOpen when
// fast-failing; otherwise propagates fn's error. Successful calls
// either keep the breaker closed or count toward closing it from
// half-open.
func (b *Breaker) Call(fn func() error) error {
	b.mu.Lock()
	if b.state == stateOpen {
		if b.now().Sub(b.openedAt) < b.cfg.Cooldown {
			b.mu.Unlock()
			return ErrCircuitOpen
		}
		// Cooldown elapsed — transition to half-open. Subsequent
		// calls run as probes.
		b.state = stateHalfOpen
		b.consecSuccesses = 0
	}
	b.mu.Unlock()

	err := fn()

	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.recordFailure()
		return err
	}
	b.recordSuccess()
	return nil
}

func (b *Breaker) recordFailure() {
	b.consecFailures++
	b.consecSuccesses = 0
	if b.state == stateHalfOpen {
		b.openCircuit()
		return
	}
	if b.state == stateClosed && b.consecFailures >= b.cfg.FailureThreshold {
		b.openCircuit()
	}
}

func (b *Breaker) recordSuccess() {
	b.consecSuccesses++
	b.consecFailures = 0
	if b.state == stateHalfOpen && b.consecSuccesses >= b.cfg.ProbeWindow {
		b.state = stateClosed
		b.consecSuccesses = 0
	}
}

func (b *Breaker) openCircuit() {
	b.state = stateOpen
	b.openedAt = b.now()
	b.consecFailures = 0
}

// State returns the current state as a stable string. Useful for
// metrics + observability without exposing the int
// constants externally.
func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case stateClosed:
		return "closed"
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half_open"
	}
	return "unknown"
}
