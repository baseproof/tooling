package shipper

import "testing"

// AIMDLimit exposes the limiter's live concurrency limit, and reflects backoff.
func TestShipper_AIMDLimit(t *testing.T) {
	s := NewShipper(newFakeWAL(), newFakeBytestore(), fastConfig())

	init := s.AIMDLimit()
	if init <= 0 {
		t.Fatalf("initial AIMD limit = %v, want > 0 (starts at the ceiling)", init)
	}
	// A failure halves the limit (multiplicative decrease).
	s.limiter.release(false)
	if got := s.AIMDLimit(); got >= init {
		t.Fatalf("after a failure AIMD limit = %v, want < %v", got, init)
	}

	// nil-safe.
	var nilShip *Shipper
	if got := nilShip.AIMDLimit(); got != 0 {
		t.Fatalf("nil shipper AIMD limit = %v, want 0", got)
	}
}
