/*
FILE PATH: cmd/ledger/pool_sizing_test.go

Tests defaultPgMaxConns + validatePgPoolSizing — boot-time guards on
the Postgres pool. The pool is sized to the read/admission path and a
handful of background loops; it is DECOUPLED from SequencerMaxInFlight
because the sequencer's parallel stage-1 workers hold no PG connection
(the singleton committer is the sole sequencer-side PG writer). These
tests pin that decoupling so a future tweak can't silently re-introduce
the mif×4 / mif+headroom coupling that capped throughput at
MaxInFlight / Tessera-BatchMaxAge.
*/
package main

import (
	"strings"
	"testing"
)

func TestDefaultPgMaxConns_FixedAndDecoupledFromMaxInFlight(t *testing.T) {
	// The default is a single fixed value, independent of any
	// sequencer setting — raising MaxInFlight must NOT inflate the
	// pool (stage-1 holds no connection).
	got := defaultPgMaxConns()
	if got != defaultPgPoolSize {
		t.Errorf("defaultPgMaxConns() = %d, want %d", got, defaultPgPoolSize)
	}
	if got < minPgPoolConns {
		t.Errorf("default pool %d below floor %d", got, minPgPoolConns)
	}
}

func TestValidatePgPoolSizing_RejectsBelowFloor(t *testing.T) {
	cases := []struct {
		maxConns int32
		wantErr  bool
	}{
		{maxConns: 1, wantErr: true},
		{maxConns: minPgPoolConns - 1, wantErr: true},
		{maxConns: minPgPoolConns, wantErr: false},
		{maxConns: defaultPgPoolSize, wantErr: false},
		// A large pool paired with a large in-flight degree must still
		// pass — the validator does not consult MaxInFlight at all.
		{maxConns: 32, wantErr: false},
		{maxConns: 256, wantErr: false},
	}
	for _, tc := range cases {
		err := validatePgPoolSizing(tc.maxConns)
		if (err != nil) != tc.wantErr {
			t.Errorf("validatePgPoolSizing(maxConns=%d): err=%v, wantErr=%v",
				tc.maxConns, err, tc.wantErr)
		}
	}
}

func TestValidatePgPoolSizing_ErrorMessageActionable(t *testing.T) {
	err := validatePgPoolSizing(1)
	if err == nil {
		t.Fatal("expected error")
	}
	// The error must point at the env var to set so an operator
	// reading the boot log can fix the misconfig without spelunking.
	// It must NOT advise lowering MaxInFlight — that lever is no longer
	// coupled to pool sizing.
	if !strings.Contains(err.Error(), "LEDGER_PG_MAX_CONNS") {
		t.Errorf("error missing LEDGER_PG_MAX_CONNS: %v", err)
	}
	if strings.Contains(err.Error(), "LEDGER_SEQUENCER_MAX_INFLIGHT") {
		t.Errorf("error should NOT couple pool sizing to MaxInFlight: %v", err)
	}
}

// The default must always satisfy validation — the ledger never
// refuses to start when no LEDGER_PG_MAX_CONNS override is set.
func TestDefaultPgMaxConns_AlwaysPassesValidation(t *testing.T) {
	if err := validatePgPoolSizing(defaultPgMaxConns()); err != nil {
		t.Errorf("default pool fails validation: %v", err)
	}
}

// minPgPoolConns is the load-bearing safety floor: committer (1) +
// builder (1) + lag/cursor + concurrent read/admission handlers. Pin
// it so accidental tightening (which would create false-negative
// startup failures) is caught.
func TestMinPgPoolConns_Invariants(t *testing.T) {
	if minPgPoolConns <= 0 {
		t.Errorf("minPgPoolConns must be positive, got %d", minPgPoolConns)
	}
	if defaultPgPoolSize < minPgPoolConns {
		t.Errorf("defaultPgPoolSize=%d must be >= minPgPoolConns=%d",
			defaultPgPoolSize, minPgPoolConns)
	}
}
