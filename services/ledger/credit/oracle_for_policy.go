package credit

import "github.com/baseproof/baseproof/authz"

// OracleForPolicy selects the CostOracle implied by an admission policy's cost
// mode — the policy-driven cost selection that completes the v1.20.0 two-axis
// runtime story:
//
//   - CostModeUncharged → NoCostOracle (CostUncharged, recorded transparently)
//   - CostModeFlat      → FlatCostOracle{Units: policy.FlatUnits}
//   - CostModeUnitRate  → UnitRateCostOracle{RawUnits: LenRawUnits, Schedule: rate}
//
// rate is the as-of BP-ENTRY-CREDIT-UNIT-RATE-V1 schedule source (nil ⇒ unit_rate mode prices
// fail-closed via ErrNoRateSchedule). A policy is validated upstream, so an
// unrecognised mode falls back to the safe NoCostOracle.
func OracleForPolicy(policy authz.AdmissionPolicy, rate RateScheduleFunc) CostOracle {
	switch policy.CostMode {
	case authz.CostModeFlat:
		return FlatCostOracle{Units: policy.FlatUnits}
	case authz.CostModeUnitRate:
		return UnitRateCostOracle{RawUnits: LenRawUnits, Schedule: rate}
	case authz.CostModeUncharged:
		return NoCostOracle{}
	default:
		return NoCostOracle{}
	}
}
