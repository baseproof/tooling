/*
FILE PATH: libs/monitoring/algorithm_policy_compliance.go — platform.algorithm_policy_compliance.

Independent re-derivation of the network ALGORITHM POLICY (the synthesized
genesis baseline + on-log BP-ENTRY-NETWORK-ALGORITHM-POLICY-V1 amendments) and
verification that the ledger admitted no entry signed with a forbidden/unknown
algorithm and published no illegal lifecycle ROLLBACK.

The crypto-agility lifecycle is monotone per algorithm: active → deprecated →
forbidden, never backward. The SDK walker authz.ResolveAlgorithmPolicyAt ENFORCES
that monotonicity as it walks and returns an error naming the offending
EffectivePos + algorithm when an amendment rolls a lifecycle backward. The
monitor surfaces that error as Critical — it means the ledger admitted an
amendment it should have rejected.

WHAT IT CHECKS:
  - chain integrity / monotonicity: ResolveAlgorithmPolicyAt at the audited
    as-of; a resolve error (rollback, unsorted, none-in-effect) is Critical and
    independently attributes the offending position from the wrapped error.
  - per entry: every signature's AlgoID PermitsVerification (active or
    deprecated — NOT forbidden, NOT absent) under the policy in effect at the
    entry's position.

KEY DEPENDENCIES: baseproof/authz (the algorithm-policy walker), baseproof/monitoring,
tooling/libs/crosslog.
*/
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

const MonitorAlgorithmPolicyCompliance monitoring.MonitorID = "platform.algorithm_policy_compliance"

// AlgorithmPolicyComplianceConfig configures the algorithm-policy monitor.
type AlgorithmPolicyComplianceConfig struct {
	// Records is the genesis-seeded, EffectivePos-sorted algorithm-policy chain.
	// Empty ⇒ unwired, no-op.
	Records authz.AlgorithmPolicyByPosition

	// Entries are the admitted business entries to check. May be empty.
	Entries []crosslog.EntryAtPosition

	// AsOf is the audited log position used for the chain-integrity /
	// monotonicity resolution.
	AsOf types.LogPosition
}

// CheckAlgorithmPolicyCompliance resolves the algorithm-policy chain (surfacing
// any lifecycle-rollback the SDK walker rejects) and flags any admitted entry
// signed with an algorithm the policy at its position does not permit.
func CheckAlgorithmPolicyCompliance(
	_ context.Context,
	cfg AlgorithmPolicyComplianceConfig,
	now time.Time,
) ([]monitoring.Alert, error) {
	if len(cfg.Records) == 0 {
		return nil, nil
	}

	// Chain integrity + monotonicity. ResolveAlgorithmPolicyAt walks genesis→asOf
	// enforcing the active→deprecated→forbidden monotonicity; a rollback (or an
	// unsorted chain) returns an error whose text names the offending
	// EffectivePos. That is the headline algorithm-policy finding.
	asOfPolicy, err := authz.ResolveAlgorithmPolicyAt(cfg.Records, cfg.AsOf)
	if err != nil {
		return []monitoring.Alert{algoPolicyAlert(monitoring.Critical,
			"algorithm-policy chain invalid (illegal lifecycle rollback or unsorted records)",
			map[string]any{"as_of": cfg.AsOf.String(), "records": len(cfg.Records), "error": err.Error()},
			now)}, nil
	}
	_ = asOfPolicy // resolved cleanly; per-entry checks resolve at each position below

	var alerts []monitoring.Alert
	for _, e := range cfg.Entries {
		if e.Entry == nil {
			continue
		}
		pol, perr := authz.ResolveAlgorithmPolicyAt(cfg.Records, e.Position)
		if perr != nil {
			alerts = append(alerts, algoPolicyAlert(monitoring.Warning,
				"cannot resolve algorithm policy at entry position",
				map[string]any{"entry_pos": e.Position.String(), "error": perr.Error()}, now))
			continue
		}
		for _, sig := range e.Entry.Signatures {
			if !pol.PermitsVerification(sig.AlgoID) {
				rec, known := pol.Lookup(sig.AlgoID)
				state := "absent"
				if known {
					state = string(rec.LifecycleState)
				}
				alerts = append(alerts, algoPolicyAlert(monitoring.Critical,
					fmt.Sprintf("admitted entry signed with algorithm 0x%04X not permitted (lifecycle: %s)", sig.AlgoID, state),
					map[string]any{
						"entry_pos": e.Position.String(),
						"signer":    e.Entry.Header.SignerDID,
						"algo_id":   fmt.Sprintf("0x%04X", sig.AlgoID),
						"lifecycle": state,
					}, now))
			}
		}
	}
	return alerts, nil
}

func algoPolicyAlert(sev monitoring.Severity, msg string, details map[string]any, now time.Time) monitoring.Alert {
	return monitoring.Alert{
		Monitor:     MonitorAlgorithmPolicyCompliance,
		Severity:    sev,
		Destination: monitoring.Both,
		Message:     msg,
		Details:     details,
		EmittedAt:   now,
	}
}
