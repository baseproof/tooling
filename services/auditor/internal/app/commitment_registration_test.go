package app

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/tooling/libs/monitoring"
)

func emptyCommitmentSource(_ context.Context) (monitoring.DerivationCommitmentComplianceConfig, error) {
	return monitoring.DerivationCommitmentComplianceConfig{}, nil
}

func TestBuild_CommitmentJobRegisteredWhenSourceAndIntervalSet(t *testing.T) {
	d := minimalDeps(t)
	d.DerivationCommitmentSource = emptyCommitmentSource
	d.DerivationCommitmentInterval = 10 * time.Minute

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler == nil {
		t.Fatal("commitment registration must create a scheduler when no other jobs would")
	}
	if !contains(pipe.Scheduler.JobNames(), "derivation_commitment_compliance") {
		t.Errorf("scheduler jobs = %v; want to include derivation_commitment_compliance",
			pipe.Scheduler.JobNames())
	}
}

func TestBuild_CommitmentNotRegisteredWhenSourceNil(t *testing.T) {
	d := minimalDeps(t)
	d.DerivationCommitmentInterval = 10 * time.Minute // source omitted

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "derivation_commitment_compliance") {
		t.Error("commitment job must not register when DerivationCommitmentSource is nil")
	}
}

func TestBuild_CommitmentNotRegisteredWhenIntervalZero(t *testing.T) {
	d := minimalDeps(t)
	d.DerivationCommitmentSource = emptyCommitmentSource
	d.DerivationCommitmentInterval = 0

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "derivation_commitment_compliance") {
		t.Error("commitment job must not register when DerivationCommitmentInterval is 0")
	}
}
