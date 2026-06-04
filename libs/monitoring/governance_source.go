/*
FILE PATH: libs/monitoring/governance_source.go

The shared input snapshot + source closure for the three network-governance
compliance monitors. The daemon scans the log once, materializes the governance
chains (crosslog.MaterializeGovernance) + collects the entries/heads to check,
and exposes them as one GovernanceSnapshot; the three jobs each read the same
snapshot and run their dimension's Check. This mirrors url_drift_audit's
MaterializedSource closure pattern — the check stays pure over its inputs, the
daemon owns the scan.

KEY DEPENDENCIES: baseproof/types, tooling/libs/crosslog.
*/
package monitoring

import (
	"context"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

// GovernanceSnapshot is the materialized governance state plus the admitted
// entries / cosigned heads to check against it, all resolved at AsOf. Every
// field is optional: a genesis-only snapshot (empty Entries/Heads) resolves
// cleanly and raises nothing — the "wired and ready" state before a live on-log
// scan populates the amendments/subjects.
type GovernanceSnapshot struct {
	Governance crosslog.MaterializedGovernance
	Entries    []crosslog.EntryAtPosition
	Heads      []CosignedHeadObservation
	AsOf       types.LogPosition
}

// GovernanceSource returns the latest GovernanceSnapshot. Typically a closure
// over a freshly-walked (or cached) log scan. A non-nil error aborts the cycle
// (the scheduler records the run as failed).
type GovernanceSource func(ctx context.Context) (GovernanceSnapshot, error)
