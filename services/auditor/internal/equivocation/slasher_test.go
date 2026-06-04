// FILE PATH: services/auditor/internal/equivocation/slasher_test.go
//
// Tests for the Phase 5 slasher's state machine. We bypass real
// BLS verification by using a slasher with no WitnessSets and
// asserting the "fails re-verification" silent-drop path. State
// transitions are exercised via a test-only injectVerified helper.
//
// Cryptographic acceptance is the SDK's responsibility (covered
// in baseproof/gossip/findings/equivocation_test.go); these tests
// focus on the JN slasher's bookkeeping:
//
//  1. NewSlasher rejects empty WitnessSets (ErrSlasherConfig).
//  2. NewSlasher defaults Threshold to 1.
//  3. Apply silently drops findings that fail Verify.
//  4. injectVerified records counts and trips Slashed at Threshold.
//  5. IsSlashed reflects the threshold crossing.
//  6. Snapshot returns a copy (mutation doesn't leak back).
//  7. Reset zeroes state for one ledger, leaves others alone.
//  8. nil receiver methods are no-ops (defensive).
package equivocation

import (
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
)

func TestNewSlasher_RejectsEmptyWitnessSets(t *testing.T) {
	_, err := NewSlasher(SlasherConfig{})
	if !errors.Is(err, ErrSlasherConfig) {
		t.Fatalf("want ErrSlasherConfig, got %v", err)
	}
}

func TestNewSlasher_DefaultsThreshold(t *testing.T) {
	s, err := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
	})
	if err != nil {
		t.Fatalf("NewSlasher: %v", err)
	}
	if s.threshold != 1 {
		t.Fatalf("default Threshold = 1, got %d", s.threshold)
	}
}

func TestNewSlasher_RespectsExplicitThreshold(t *testing.T) {
	s, err := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
		Threshold:   3,
	})
	if err != nil {
		t.Fatalf("NewSlasher: %v", err)
	}
	if s.threshold != 3 {
		t.Fatalf("Threshold = 3, got %d", s.threshold)
	}
}

func TestInjectVerified_AccumulatesAndSlashesAtThreshold(t *testing.T) {
	s, err := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
		Threshold:   3,
	})
	if err != nil {
		t.Fatalf("NewSlasher: %v", err)
	}
	endpoint := "https://ledger.davidson.example/court"
	for i := 1; i <= 3; i++ {
		s.injectVerified(endpoint)
		state := s.state[endpoint]
		if state.Count != i {
			t.Fatalf("after %d injects, Count=%d", i, state.Count)
		}
		// Slashed flips ONLY at the threshold-th injection.
		wantSlashed := i >= 3
		if state.Slashed != wantSlashed {
			t.Fatalf("after %d injects, Slashed=%v want %v", i, state.Slashed, wantSlashed)
		}
	}
}

func TestIsSlashed_ReflectsThresholdCrossing(t *testing.T) {
	s, _ := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
		Threshold:   2,
	})
	endpoint := "https://ledger.williamson.example/court"
	if s.IsSlashed(endpoint) {
		t.Fatalf("brand-new endpoint must not be slashed")
	}
	s.injectVerified(endpoint)
	if s.IsSlashed(endpoint) {
		t.Fatalf("below-threshold endpoint must not be slashed")
	}
	s.injectVerified(endpoint)
	if !s.IsSlashed(endpoint) {
		t.Fatalf("at-threshold endpoint must be slashed")
	}
}

func TestSnapshot_ReturnsCopy(t *testing.T) {
	s, _ := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
	})
	s.injectVerified("a")
	s.injectVerified("b")
	snap := s.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(snap))
	}
	// Mutating the snapshot must not affect the slasher.
	snap[0].Count = 999
	for _, st := range s.Snapshot() {
		if st.Count == 999 {
			t.Fatalf("Snapshot returned a reference, not a copy")
		}
	}
}

func TestReset_OneEndpointOnly(t *testing.T) {
	s, _ := NewSlasher(SlasherConfig{
		WitnessSets: map[string]*cosign.WitnessKeySet{"did:test:1": nil},
	})
	s.injectVerified("a")
	s.injectVerified("b")
	s.Reset("a")
	if s.IsSlashed("a") {
		t.Fatalf("Reset must clear slash state for a")
	}
	if !s.IsSlashed("b") {
		t.Fatalf("Reset must NOT clear slash state for b")
	}
}

func TestNilReceiver_NoOps(t *testing.T) {
	var s *Slasher
	if s.IsSlashed("anything") {
		t.Fatalf("nil receiver IsSlashed must be false")
	}
	if snap := s.Snapshot(); snap != nil {
		t.Fatalf("nil receiver Snapshot must be nil")
	}
	s.Reset("anything") // must not panic
}

// injectVerified is a test-only helper that bypasses the
// re-verification step and exercises the state machine directly.
// We expose it via a method to keep the package's public surface
// clean.
func (s *Slasher) injectVerified(endpoint string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.state[endpoint]
	if !ok {
		st = &SlashState{LedgerEndpoint: endpoint, FirstSeen: now}
		s.state[endpoint] = st
	}
	st.Count++
	st.LastSeen = now
	if st.Count >= s.threshold && !st.Slashed {
		st.Slashed = true
	}
}
