package app

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/tooling/libs/monitoring"
)

func genesisOnlyGovernanceSource(_ context.Context) (monitoring.GovernanceSnapshot, error) {
	return monitoring.GovernanceSnapshot{}, nil
}

// All three governance-compliance jobs register when a source + positive
// interval are set (#41: registered + running).
func TestBuild_GovernanceJobsRegisteredWhenSourceAndIntervalSet(t *testing.T) {
	d := minimalDeps(t)
	d.GovernanceSource = genesisOnlyGovernanceSource
	d.GovernanceInterval = 10 * time.Minute

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler == nil {
		t.Fatal("governance registration must create a scheduler when no other jobs would")
	}
	for _, want := range []string{
		"signature_policy_compliance",
		"algorithm_policy_compliance",
		"protocol_version_compliance",
	} {
		if !contains(pipe.Scheduler.JobNames(), want) {
			t.Errorf("scheduler jobs = %v; want to include %s", pipe.Scheduler.JobNames(), want)
		}
	}
}

func TestBuild_GovernanceNotRegisteredWhenSourceNil(t *testing.T) {
	d := minimalDeps(t)
	// Deliberately omit GovernanceSource.
	d.GovernanceInterval = 10 * time.Minute

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "signature_policy_compliance") {
		t.Error("governance jobs must not register when GovernanceSource is nil")
	}
}

// Default AUDITOR_GOVERNANCE_INTERVAL is 0 (disabled); a regression that treated
// 0 as "register with a default" would silently start the audits operators
// didn't ask for.
func TestBuild_GovernanceNotRegisteredWhenIntervalZero(t *testing.T) {
	d := minimalDeps(t)
	d.GovernanceSource = genesisOnlyGovernanceSource
	d.GovernanceInterval = 0

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "signature_policy_compliance") {
		t.Error("governance jobs must not register when GovernanceInterval is 0")
	}
}
