package credit

import (
	"context"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
)

func TestOracleForPolicy(t *testing.T) {
	ctx := context.Background()

	// Uncharged → NoCostOracle (CostUncharged).
	if got, err := OracleForPolicy(authz.AdmissionPolicy{CostMode: authz.CostModeUncharged}, nil).Cost(ctx, nil); err != nil || got != CostUncharged {
		t.Errorf("uncharged: %d / %v", got, err)
	}

	// Flat → FlatCostOracle{FlatUnits}.
	if got, err := OracleForPolicy(authz.AdmissionPolicy{CostMode: authz.CostModeFlat, FlatUnits: 5}, nil).Cost(ctx, nil); err != nil || got != 5 {
		t.Errorf("flat: %d / %v", got, err)
	}

	// Unknown mode → safe NoCostOracle fallback.
	if got, err := OracleForPolicy(authz.AdmissionPolicy{CostMode: "weird"}, nil).Cost(ctx, nil); err != nil || got != CostUncharged {
		t.Errorf("unknown mode fallback: %d / %v", got, err)
	}

	// Unit-rate → a UnitRateCostOracle wired to the supplied schedule source
	// (type-assert rather than call Cost, which would need a real signed entry).
	rate := func(context.Context, *envelope.Entry) ([]authz.UnitRateTier, error) {
		return []authz.UnitRateTier{{MinUnits: 0, RatePerUnit: 1}}, nil
	}
	o := OracleForPolicy(authz.AdmissionPolicy{CostMode: authz.CostModeUnitRate}, rate)
	ur, ok := o.(UnitRateCostOracle)
	if !ok {
		t.Fatalf("unit_rate mode = %T, want UnitRateCostOracle", o)
	}
	if ur.RawUnits == nil || ur.Schedule == nil {
		t.Error("unit_rate oracle must be wired with RawUnits + Schedule")
	}
	// Confirm the wired schedule is the one we passed.
	if sched, err := ur.Schedule(ctx, nil); err != nil || len(sched) != 1 || sched[0].RatePerUnit != 1 {
		t.Errorf("schedule not wired through: %v / %v", sched, err)
	}
}
