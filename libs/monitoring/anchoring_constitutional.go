/*
FILE PATH: libs/monitoring/anchoring_constitutional.go

The CONSTITUTIONAL anchoring monitor — the verified-evidence path (PR-4b).

anchor_freshness.go (above) is the legacy SELF-REPORT check: it scans the
child's own log for its own anchor entries — useful liveness, but a captured
child can fabricate it. THIS check consumes externally collected, parent-
provenanced evidence (libs/anchorfeed → verifier.AnchorEvidence) and classifies
it with the SDK's constitutional ladder (verifier.CheckAnchoringEvidence →
network.CheckAnchoring): lineage-bound, self/fork-excluded, target-attributed,
min(AnchoredAt, VerifiedAt)-floored.

TWO DISTINCT FAILURE REASONS — never folded together:

 1. The SDK ladder (the finding's Reason): absent under require → Critical;
    stale → Warning; under the distinct-target quota → Critical. These mean
    "the commitment is NOT satisfied by the evidence that exists".
 2. CANNOT-CORROBORATE: a parent that was unreachable / 404 / unreadable.
    That is a COLLECTION failure — we don't know what evidence exists. It
    surfaces as its own Warning alert + counter and NEVER synthesizes
    evidence; with nothing collected, reason 1 independently degrades toward
    Critical (fail-closed), which is the correct compound outcome.

PER-TARGET AGES ARE COUNTERS, NEVER PAGES: they ride in Alert.Details and the
scan result (for gauges/dashboards); a target's age alone never raises
severity — only the SDK ladder does.

PARENT SET SELECTION IS THE WIRING'S RULE: constitutional Targets when the
policy declares them (each parent carries its target NetworkID); else the
auditor's trust-root config (legacy, pre-targets networks). The check itself
is pure over whatever parents it is given.
*/
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/verifier"
)

// MonitorConstitutionalAnchoring identifies this check's alerts.
const MonitorConstitutionalAnchoring sdkmonitoring.MonitorID = "network.constitutional_anchoring"

// AnchoringParent is one corroborator the monitor collects evidence from.
type AnchoringParent struct {
	// LogDID names the parent log (diagnostics + the cannot-corroborate
	// alert's vocabulary).
	LogDID string
	// Collect returns the parent-provenanced evidence (the libs/anchorfeed
	// composition: by-source page → MultiLog read → AnchorEvidence) plus
	// per-item read errors. A transport-level failure is returned as an
	// error from Collect itself.
	Collect func(ctx context.Context) ([]verifier.AnchorEvidence, []error)
}

// ConstitutionalAnchoringConfig wires CheckConstitutionalAnchoring.
type ConstitutionalAnchoringConfig struct {
	// Policy is the network's constitutional commitment (nil ⇒ none — the
	// check is informational and emits nothing).
	Policy *network.GenesisAnchoringPolicy
	// Pin is THIS network's NetworkID (self/fork exclusion + lineage domain).
	Pin [32]byte
	// CurrentSet is the rotation-replayed CURRENT witness set (nil fails
	// closed: no set, no corroboration, Critical under require).
	CurrentSet *cosign.WitnessKeySet
	// Parents is the corroborator set: constitutional Targets when the
	// policy declares them, else the legacy trust-root config.
	Parents []AnchoringParent
}

// AnchoringScanResult is the full posture for gauges/dashboards — richer
// than the alerts, which carry only lapses.
type AnchoringScanResult struct {
	// Finding is the SDK ladder's verdict over the collected evidence.
	Finding network.AnchoringFinding
	// CannotCorroborate counts parents whose collection FAILED (reason 2).
	CannotCorroborate int
	// EvidenceCount is how many evidence items were collected.
	EvidenceCount int
	// PerTargetAge maps each listed target's NetworkID hex to its freshest
	// effective-anchor age (counters that never page; absent = never
	// corroborated). Nil for a no-targets policy.
	PerTargetAge map[string]time.Duration
}

// CheckConstitutionalAnchoring collects evidence from every parent, runs the
// ONE SDK reduction + classification, and emits alerts for lapses:
//
//	finding not OK            → one alert at the finding's severity, the
//	                            finding's Reason verbatim (the SDK ladder)
//	collection failures > 0   → one Warning "cannot corroborate" alert
//	                            naming the unreachable parents (reason 2,
//	                            always distinct from reason 1)
//
// A fully healthy scan emits no alerts; the scan result carries the posture.
func CheckConstitutionalAnchoring(
	ctx context.Context,
	cfg ConstitutionalAnchoringConfig,
	now time.Time,
) (AnchoringScanResult, []sdkmonitoring.Alert) {
	var res AnchoringScanResult
	if cfg.Policy == nil {
		res.Finding = network.CheckAnchoring(nil, network.AnchorObservation{}, now)
		return res, nil
	}

	var evidence []verifier.AnchorEvidence
	var unreachable []string
	for _, p := range cfg.Parents {
		items, errs := p.Collect(ctx)
		evidence = append(evidence, items...)
		if len(items) == 0 && len(errs) > 0 {
			// Nothing collected AND something failed: this parent cannot
			// corroborate right now. (Partial reads with some items still
			// count the items; omission of the rest fails toward the
			// ladder, which is the safe direction.)
			unreachable = append(unreachable, p.LogDID)
		}
	}
	res.EvidenceCount = len(evidence)
	res.CannotCorroborate = len(unreachable)

	obs := verifier.LatestAnchorObservation(cfg.Policy, cfg.Pin, cfg.CurrentSet, evidence)
	res.Finding = network.CheckAnchoring(cfg.Policy, obs, now)
	if obs.PerTarget != nil {
		res.PerTargetAge = make(map[string]time.Duration, len(obs.PerTarget))
		for id, t := range obs.PerTarget {
			res.PerTargetAge[id] = now.Sub(t)
		}
	}

	var alerts []sdkmonitoring.Alert
	if !res.Finding.OK {
		details := map[string]any{
			"distinct_fresh_targets": res.Finding.DistinctFreshTargets,
			"evidence_count":         res.EvidenceCount,
			"max_age_seconds":        res.Finding.MaxAge.Seconds(),
		}
		for id, age := range res.PerTargetAge {
			details["target_age_s_"+id[:8]] = age.Seconds()
		}
		alerts = append(alerts, sdkmonitoring.Alert{
			Monitor:     MonitorConstitutionalAnchoring,
			Severity:    res.Finding.Severity,
			Destination: sdkmonitoring.Both,
			Message:     res.Finding.Reason, // the SDK ladder, verbatim
			Details:     details,
			EmittedAt:   now,
		})
	}
	if len(unreachable) > 0 {
		alerts = append(alerts, sdkmonitoring.Alert{
			Monitor:     MonitorConstitutionalAnchoring,
			Severity:    sdkmonitoring.Warning,
			Destination: sdkmonitoring.Ops,
			Message: fmt.Sprintf("cannot corroborate: %d parent(s) unreachable/unreadable (%v) — no evidence judgment implied",
				len(unreachable), unreachable),
			Details:   map[string]any{"unreachable_parents": unreachable},
			EmittedAt: now,
		})
	}
	return res, alerts
}
