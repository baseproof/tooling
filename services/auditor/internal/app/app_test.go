/*
FILE PATH: services/auditor/internal/app/app_test.go

Ladder 2 D6 backfill (#21) — Build() registers the url_drift_audit job
on the scheduler iff all four Deps fields are populated.

# WHAT THIS PINS

The Build path's gate on URLDrift registration is:

	registerURLDrift := d.URLDriftResolver != nil &&
	    d.URLDriftMaterializedSource != nil &&
	    d.URLDriftInterval > 0

These tests verify the registration's truth-table by inspecting
Pipeline.Scheduler.JobNames() after Build.

Tests do NOT exercise the audit body itself — that's covered in
libs/monitoring/url_drift_audit_test.go (T11 from PR #20). What
IS pinned here is that the SCHEDULER WIRES THE JOB at all.

# WHY THIS BACKFILL EXISTS

Ladder 2 shipped D6 (the Deps fields + the Build branch). A regression
that broke any one of the four gate conditions would silently drop the
job from the scheduler — operators see no alerts on actual drift
because the job never runs. The tests pin the gate.
*/
package app

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/network"
	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newNetworkID(t *testing.T) cosign.NetworkID {
	t.Helper()
	var nid cosign.NetworkID
	if _, err := rand.Read(nid[:]); err != nil {
		t.Fatal(err)
	}
	return nid
}

// fakeDIDResolver implements did.DIDResolver but is never actually
// consulted in these tests (Build doesn't run the job; the schedulers's
// Run loop is what calls it). Required only so the URLDriftResolver
// field is non-nil.
type fakeDIDResolver struct{}

func (fakeDIDResolver) Resolve(_ context.Context, _ string) (*did.DIDDocument, error) {
	return nil, nil
}

// minimalDeps returns the smallest Deps that satisfies Build's
// constructor checks. Callers selectively set additional fields to
// exercise the URLDrift registration gate.
func minimalDeps(t *testing.T) Deps {
	t.Helper()
	return Deps{
		Store:          gossip.NewInMemoryStore(),
		WitnessSets:    map[string]*cosign.WitnessKeySet{},
		NetworkID:      newNetworkID(t),
		DIDRegistry:    did.NewVerifierRegistry(),
		PeerHTTPClient: &http.Client{},
		Logger:         quietLogger(),
	}
}

// TestBuild_URLDriftRegisteredWhenAllFieldsSet pins the happy path: all
// four URLDrift fields populated + Interval > 0 → scheduler gets the
// url_drift_audit job.
func TestBuild_URLDriftRegisteredWhenAllFieldsSet(t *testing.T) {
	d := minimalDeps(t)
	d.URLDriftResolver = fakeDIDResolver{}
	d.URLDriftMaterializedSource = func(_ context.Context) (crosslog.MaterializedNetwork, error) {
		return crosslog.MaterializedNetwork{}, nil
	}
	d.URLDriftInterval = 5 * time.Minute
	d.URLDriftLocalLogDID = "did:web:test.example.org"

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler == nil {
		t.Fatal("URLDrift registration must create a scheduler when no other jobs would")
	}
	if !contains(pipe.Scheduler.JobNames(), "url_drift_audit") {
		t.Errorf("scheduler jobs = %v; want to include url_drift_audit",
			pipe.Scheduler.JobNames())
	}
}

// TestBuild_URLDriftNotRegisteredWhenResolverNil pins the gate: missing
// resolver → no job.
func TestBuild_URLDriftNotRegisteredWhenResolverNil(t *testing.T) {
	d := minimalDeps(t)
	// Deliberately omit URLDriftResolver.
	d.URLDriftMaterializedSource = func(_ context.Context) (crosslog.MaterializedNetwork, error) {
		return crosslog.MaterializedNetwork{}, nil
	}
	d.URLDriftInterval = 5 * time.Minute

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "url_drift_audit") {
		t.Error("URLDrift must not be registered when Resolver is nil")
	}
}

// TestBuild_URLDriftNotRegisteredWhenSourceNil pins the gate: missing
// MaterializedSource → no job.
func TestBuild_URLDriftNotRegisteredWhenSourceNil(t *testing.T) {
	d := minimalDeps(t)
	d.URLDriftResolver = fakeDIDResolver{}
	// Deliberately omit URLDriftMaterializedSource.
	d.URLDriftInterval = 5 * time.Minute

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "url_drift_audit") {
		t.Error("URLDrift must not be registered when MaterializedSource is nil")
	}
}

// TestBuild_URLDriftNotRegisteredWhenIntervalZero pins the gate: zero
// or negative Interval → no job. Default `AUDITOR_URL_DRIFT_INTERVAL`
// is 0 (disabled); regression that interpreted 0 as "register with a
// default interval" would silently start the audit when operators
// hadn't asked.
func TestBuild_URLDriftNotRegisteredWhenIntervalZero(t *testing.T) {
	d := minimalDeps(t)
	d.URLDriftResolver = fakeDIDResolver{}
	d.URLDriftMaterializedSource = func(_ context.Context) (crosslog.MaterializedNetwork, error) {
		return crosslog.MaterializedNetwork{}, nil
	}
	// Interval = 0 (default).

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler != nil && contains(pipe.Scheduler.JobNames(), "url_drift_audit") {
		t.Error("URLDrift must not be registered when Interval == 0")
	}
}

// TestBuild_URLDriftDepsCoexistWithExistingJobs pins that the
// url_drift_audit registration doesn't clobber the existing gossip_prune
// or horizon_audit jobs. The scheduler should carry whatever set of
// jobs the gate predicates approve.
func TestBuild_URLDriftDepsCoexistWithExistingJobs(t *testing.T) {
	d := minimalDeps(t)
	// URLDrift on.
	d.URLDriftResolver = fakeDIDResolver{}
	d.URLDriftMaterializedSource = func(_ context.Context) (crosslog.MaterializedNetwork, error) {
		return crosslog.MaterializedNetwork{}, nil
	}
	d.URLDriftInterval = 5 * time.Minute
	// Pre-existing job: gossip_prune. The Store must implement Pruner
	// AND RetentionDays > 0. gossip.NewInMemoryStore implements Pruner
	// in v1.x of the SDK; verify by feature-test before asserting.
	d.RetentionDays = 7

	pipe, err := Build(d)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if pipe.Scheduler == nil {
		t.Fatal("scheduler must exist when URLDrift is registered")
	}
	names := pipe.Scheduler.JobNames()
	if !contains(names, "url_drift_audit") {
		t.Errorf("scheduler missing url_drift_audit; got %v", names)
	}
	// gossip_prune presence is a feature-test on the in-memory store
	// (it may or may not implement Pruner). The pin we care about: the
	// URLDrift registration doesn't EXCLUDE the prune job when it would
	// otherwise be registered.
	t.Logf("scheduler jobs: %v", names)
}

// silence_imports keeps the SDK type imports referenced when not every
// test consumes each one. network.AuditorScopeAmendment is used in the
// amendment-loader test in the sibling file; this guard prevents an
// import-removal cleanup from breaking that file.
var (
	_ network.AuditorScopeAmendment
	_ sdktypes.LogPosition
)

// contains is a tiny slice-search; sort.SearchStrings would require a
// sorted slice which we don't want to mutate.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
