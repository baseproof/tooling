/*
FILE PATH: credit/cost_oracle.go

DESCRIPTION:

	The PAYMENT axis's pricing seam: how many abstract UNITS a submission costs.
	Distinct from the GATING axis (admission gate 5 — "is this valid?"); this
	answers "what does admitting this cost?" in units (never currency).

	CostOracle is deterministic and replayable so the credit balance projection
	(balance = Σ on-log grants − Σ cost) is rebuildable from the log alone:

	  - FlatCostOracle: every entry costs a fixed number of units (today's
	    1-credit-per-write behaviour; the default).
	  - UnitRateCostOracle: cost = rawUnits(entry) × on-log BP-ENTRY-CREDIT-UNIT-RATE-V1
	    schedule resolved AS-OF (baseproof/authz). Large artifacts price
	    differently via tiers; the artifact store supplies rawUnits later.

	The artifact store drops in behind UnitRateCostOracle WITHOUT changing the
	credit/balance model — pricing always reduces to a scalar unit cost.
*/
package credit

import (
	"context"
	"errors"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
)

// ErrNoRateSchedule is returned by UnitRateCostOracle when no on-log rate
// schedule is in effect — fail-closed (the caller rejects rather than pricing
// a submission at zero).
var ErrNoRateSchedule = errors.New("credit: no unit-rate schedule in effect")

// CostUncharged is the TRANSPARENT sentinel for a submission admitted with no
// pricing in effect (the init / "no cost for now" default). It is recorded
// explicitly — never a silent skip — so the projection and any auditor can see
// the entry was *uncharged*, distinct from *free by policy* (cost 0). The
// consumption projection counts ConsumedUnits(cost) = max(0, cost), so an
// uncharged (-1) or free (0) entry contributes 0 units, while a priced entry
// contributes its value. Negative-but-not-uncharged costs are invalid.
const CostUncharged int64 = -1

// ConsumedUnits maps a recorded cost to the units it consumes from a balance:
// CostUncharged (-1) and free (0) consume 0; a positive cost consumes itself.
// This is the single rule the balance projection uses, so "uncharged" can be
// recorded transparently without ever crediting the balance.
func ConsumedUnits(cost int64) int64 {
	if cost <= 0 {
		return 0
	}
	return cost
}

// CostOracle prices a submission in abstract units. Deterministic: the same
// entry + the same on-log inputs always yield the same cost (replay-safe).
type CostOracle interface {
	Cost(ctx context.Context, entry *envelope.Entry) (int64, error)
}

// NoCostOracle is the init / "no cost for now" default: every entry is admitted
// UNCHARGED (CostUncharged), recorded transparently so audits see the entry was
// not priced. Swapped for FlatCostOracle or UnitRateCostOracle when pricing is
// enabled — itself an on-log, published admission-policy change.
type NoCostOracle struct{}

// Cost returns the transparent uncharged sentinel.
func (NoCostOracle) Cost(context.Context, *envelope.Entry) (int64, error) {
	return CostUncharged, nil
}

// FlatCostOracle charges a fixed unit cost per entry. Units must be > 0.
// FlatCostOracle{Units: 1} reproduces the legacy one-credit-per-write rule.
type FlatCostOracle struct{ Units int64 }

// Cost returns the flat unit cost.
func (f FlatCostOracle) Cost(context.Context, *envelope.Entry) (int64, error) {
	if f.Units <= 0 {
		return 0, errors.New("credit: FlatCostOracle.Units must be positive")
	}
	return f.Units, nil
}

// RawUnitsFunc maps an entry to its raw size-units (e.g. artifact-store unit
// count). The default LenRawUnits uses the canonical byte length; the artifact
// store provides a richer mapping later. Must return a non-negative count.
type RawUnitsFunc func(entry *envelope.Entry) (int64, error)

// LenRawUnits is the default RawUnitsFunc: the entry's canonical byte length.
func LenRawUnits(entry *envelope.Entry) (int64, error) {
	b, err := envelope.Serialize(entry)
	if err != nil {
		return 0, err
	}
	return int64(len(b)), nil
}

// RateScheduleFunc returns the BP-ENTRY-CREDIT-UNIT-RATE-V1 tier schedule in effect for an
// entry (typically resolved AS-OF the entry's anchor from on-log rate entries).
// Returns nil when no schedule is in effect.
type RateScheduleFunc func(ctx context.Context, entry *envelope.Entry) ([]authz.UnitRateTier, error)

// UnitRateCostOracle prices cost = rawUnits(entry) × rate(schedule), both
// deterministic from on-log data, so the balance projection stays replayable.
type UnitRateCostOracle struct {
	RawUnits RawUnitsFunc
	Schedule RateScheduleFunc
}

// Cost computes the deterministic unit cost. Fail-closed: a nil/empty schedule
// returns ErrNoRateSchedule (never silently free).
func (o UnitRateCostOracle) Cost(ctx context.Context, entry *envelope.Entry) (int64, error) {
	raw, err := o.RawUnits(entry)
	if err != nil {
		return 0, err
	}
	sched, err := o.Schedule(ctx, entry)
	if err != nil {
		return 0, err
	}
	if len(sched) == 0 {
		return 0, ErrNoRateSchedule
	}
	return authz.CostForUnits(sched, raw), nil
}
