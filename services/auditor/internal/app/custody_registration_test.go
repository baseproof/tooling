package app

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/tooling/libs/monitoring"
)

func emptyCustodySource(_ context.Context) (monitoring.CustodyChainComplianceConfig, error) {
	return monitoring.CustodyChainComplianceConfig{}, nil
}

func TestBuild_CustodyJobRegisteredWhenSourceAndIntervalSet(t *testing.T) {
	d := minimalDeps(t)
	d.CustodyChainSource = emptyCustodySource
	d.CustodyChainInterval = 10 * time.Minute

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler == nil {
		t.Fatal("custody registration must create a scheduler when no other jobs would")
	}
	if !contains(pipe.Scheduler.JobNames(), "custody_chain_compliance") {
		t.Errorf("scheduler jobs = %v; want to include custody_chain_compliance",
			pipe.Scheduler.JobNames())
	}
}

func TestBuild_CustodyNotRegisteredWhenSourceNil(t *testing.T) {
	d := minimalDeps(t)
	d.CustodyChainInterval = 10 * time.Minute // source omitted

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "custody_chain_compliance") {
		t.Error("custody job must not register when CustodyChainSource is nil")
	}
}

func TestBuild_CustodyNotRegisteredWhenIntervalZero(t *testing.T) {
	d := minimalDeps(t)
	d.CustodyChainSource = emptyCustodySource
	d.CustodyChainInterval = 0

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "custody_chain_compliance") {
		t.Error("custody job must not register when CustodyChainInterval is 0")
	}
}
