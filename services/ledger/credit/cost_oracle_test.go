package credit

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
)

func TestNoCostOracle_AndConsumedUnits(t *testing.T) {
	ctx := context.Background()
	// Init default: uncharged sentinel, recorded transparently.
	if got, err := (NoCostOracle{}).Cost(ctx, nil); err != nil || got != CostUncharged {
		t.Errorf("no-cost: %d / %v (want %d)", got, err, CostUncharged)
	}
	// ConsumedUnits: uncharged(-1) and free(0) consume 0; priced consumes itself.
	for _, c := range []struct{ cost, want int64 }{
		{CostUncharged, 0}, {-5, 0}, {0, 0}, {1, 1}, {7, 7},
	} {
		if got := ConsumedUnits(c.cost); got != c.want {
			t.Errorf("ConsumedUnits(%d) = %d, want %d", c.cost, got, c.want)
		}
	}
}

func TestFlatCostOracle(t *testing.T) {
	ctx := context.Background()
	if got, err := (FlatCostOracle{Units: 1}).Cost(ctx, nil); err != nil || got != 1 {
		t.Errorf("flat 1: %d / %v", got, err)
	}
	if got, err := (FlatCostOracle{Units: 5}).Cost(ctx, nil); err != nil || got != 5 {
		t.Errorf("flat 5: %d / %v", got, err)
	}
	if _, err := (FlatCostOracle{Units: 0}).Cost(ctx, nil); err == nil {
		t.Error("zero units must error")
	}
}

func TestUnitRateCostOracle(t *testing.T) {
	ctx := context.Background()
	tiers := []authz.UnitRateTier{{MinUnits: 0, RatePerUnit: 1}, {MinUnits: 1000, RatePerUnit: 3}}

	o := UnitRateCostOracle{
		RawUnits: func(*envelope.Entry) (int64, error) { return 10, nil },
		Schedule: func(context.Context, *envelope.Entry) ([]authz.UnitRateTier, error) { return tiers, nil },
	}
	if got, err := o.Cost(ctx, nil); err != nil || got != 10 { // 10 × 1
		t.Errorf("small: %d / %v", got, err)
	}

	large := UnitRateCostOracle{
		RawUnits: func(*envelope.Entry) (int64, error) { return 2000, nil },
		Schedule: func(context.Context, *envelope.Entry) ([]authz.UnitRateTier, error) { return tiers, nil },
	}
	if got, err := large.Cost(ctx, nil); err != nil || got != 6000 { // 2000 × 3
		t.Errorf("large: %d / %v", got, err)
	}

	// No schedule → fail-closed.
	noRate := UnitRateCostOracle{
		RawUnits: func(*envelope.Entry) (int64, error) { return 5, nil },
		Schedule: func(context.Context, *envelope.Entry) ([]authz.UnitRateTier, error) { return nil, nil },
	}
	if _, err := noRate.Cost(ctx, nil); !errors.Is(err, ErrNoRateSchedule) {
		t.Errorf("no schedule: %v", err)
	}

	// RawUnits error propagates.
	boom := errors.New("raw fail")
	rawErr := UnitRateCostOracle{
		RawUnits: func(*envelope.Entry) (int64, error) { return 0, boom },
		Schedule: func(context.Context, *envelope.Entry) ([]authz.UnitRateTier, error) { return tiers, nil },
	}
	if _, err := rawErr.Cost(ctx, nil); !errors.Is(err, boom) {
		t.Errorf("raw error: %v", err)
	}
	// Schedule error propagates.
	schedErr := UnitRateCostOracle{
		RawUnits: func(*envelope.Entry) (int64, error) { return 5, nil },
		Schedule: func(context.Context, *envelope.Entry) ([]authz.UnitRateTier, error) { return nil, boom },
	}
	if _, err := schedErr.Cost(ctx, nil); !errors.Is(err, boom) {
		t.Errorf("schedule error: %v", err)
	}
}

func TestLenRawUnits(t *testing.T) {
	// An unsigned hand-built entry: Serialize fails-closed (no signatures),
	// so LenRawUnits surfaces the error rather than a bogus length.
	if _, err := LenRawUnits(&envelope.Entry{}); err == nil {
		t.Error("LenRawUnits on an unserializable entry must error, not return a length")
	}
}
