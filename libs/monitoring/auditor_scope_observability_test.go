/*
FILE PATH: libs/monitoring/auditor_scope_observability_test.go

Ladder 1 B2 backfill (#21) — pin that the auditor-scope reject counter
emits one Add per reject path with the expected label set.

# WHAT THIS PINS

Boots a Reconciler with a configured AuditorRegistry, dispatches the
authorized-for check against four imposter-or-mis-scoped originators
covering the four reject paths, then collects via an OTel ManualReader
and asserts:

  - one counter named baseproof.auditor_scope.reject is registered
  - each (reason, kind) label tuple sees exactly one Add
  - the four reasons covered are: not_registered, retired, no_registry,
    scope_mismatch
  - a fifth path (unsorted) is exercised separately via a hand-rolled
    unsorted slice

# WHY THIS BACKFILL EXISTS

Ladder 1 shipped B2 (the counter + emission sites) but lacked a test
that the OTel pipeline actually sees the increments. At 1K+ TPS × 15
networks, the operator's PromQL alerts depend on this counter being
correctly wired — a silent dead-end (instrument created but never
recorded against) would surface only after a real incident.
*/
package monitoring

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// installManualReader replaces the OTel global MeterProvider with a
// SDK-backed provider that exports through a ManualReader. Returns the
// reader (caller collects when ready) + a teardown that restores the
// previous global.
func installManualReader(t *testing.T) (*metric.ManualReader, func()) {
	t.Helper()
	prev := otel.GetMeterProvider()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	otel.SetMeterProvider(provider)
	// Reset the lazy-global counter so the next recordAuditorScopeReject
	// call re-binds against this MeterProvider. Without this, an earlier
	// test that already initialized the counter against a no-op provider
	// would leak that no-op into this test.
	auditorScopeRejectOnce = onceReset()
	auditorScopeRejectCounter = nil
	return reader, func() {
		_ = provider.Shutdown(context.Background())
		otel.SetMeterProvider(prev)
	}
}

// onceReset returns a fresh sync.Once-like value via reassignment. We
// can't sync.Once.Reset() (no such method), so we replace the field
// with a fresh sync.Once. Test-only seam.
func onceReset() (zeroOnce sync.Once) {
	return
}

// collectRejectCounts returns the per-(reason,kind) Add counts seen by
// the ManualReader since the last collection.
func collectRejectCounts(t *testing.T, reader *metric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "baseproof.auditor_scope.reject" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("unexpected aggregation type: %T", m.Data)
			}
			for _, dp := range sum.DataPoints {
				reason, _ := dp.Attributes.Value("reason")
				kind, _ := dp.Attributes.Value("kind")
				key := reason.AsString() + "|" + kind.AsString()
				out[key] += dp.Value
			}
		}
	}
	return out
}

// rejectTestReconciler builds a reconciler with a configured registry
// containing exactly one auditor at Scope=Equivocation, retired at
// sequence 50. The fixture covers four of the five reject paths:
//
//   - "did:web:imposter.example.org"   → not_registered
//   - "did:web:retired.example.org"    → retired (asOf > 50)
//   - "did:web:registered.example.org" + KindHistoryRewrite → scope_mismatch
//   - empty registry → no_registry (built separately)
func rejectTestReconciler(t *testing.T) *Reconciler {
	t.Helper()
	reg := validAuditorRegistration(t, "did:web:registered.example.org", network.ScopeEquivocation)
	retiredReg := validAuditorRegistration(t, "did:web:retired.example.org", network.ScopeEquivocation)
	retired := uint64(50)
	retiredReg.RetiredAt = &retired

	registry := recordsForScope(reg, retiredReg)
	asOf := func(_ context.Context) types.LogPosition {
		return types.LogPosition{Sequence: 100}
	}
	r, err := NewReconciler(ReconcilerConfig{
		Verifier:         &fakeVerifier{},
		Heads:            NewTrustedHeadStore(slog.New(slog.NewTextHandler(io.Discard, nil))),
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuditorRegistry:  registry,
		AuditorScopeAsOf: asOf,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return r
}

// TestAuditorScopeReject_EmitsCounterPerRejectPath pins that the four
// per-path Reasons each emit exactly one count on the OTel counter,
// labeled with the correct Kind.
func TestAuditorScopeReject_EmitsCounterPerRejectPath(t *testing.T) {
	reader, teardown := installManualReader(t)
	defer teardown()

	r := rejectTestReconciler(t)
	ctx := context.Background()

	// 1. not_registered
	if r.authorizedForKind(ctx, "did:web:imposter.example.org", gossip.KindEquivocationFinding) {
		t.Fatal("imposter must be rejected")
	}
	// 2. retired
	if r.authorizedForKind(ctx, "did:web:retired.example.org", gossip.KindEquivocationFinding) {
		t.Fatal("retired must be rejected")
	}
	// 3. scope_mismatch — registered for Equivocation only; History is wrong scope.
	if r.authorizedForKind(ctx, "did:web:registered.example.org", gossip.KindHistoryRewriteFinding) {
		t.Fatal("scope-mismatched event must be rejected")
	}

	counts := collectRejectCounts(t, reader)
	wantPairs := map[string]int64{
		"not_registered|BP-GOSSIP-LEDGER-EQUIVOCATION-V1":    1,
		"retired|BP-GOSSIP-LEDGER-EQUIVOCATION-V1":           1,
		"scope_mismatch|BP-GOSSIP-LEDGER-HISTORY-REWRITE-V1": 1,
	}
	for key, want := range wantPairs {
		if got := counts[key]; got != want {
			t.Errorf("counter[%s] = %d, want %d (all observed: %v)",
				key, got, want, counts)
		}
	}
}

// TestAuditorScopeReject_NoRegistryReason pins the no_registry path
// (registry is non-nil but empty).
func TestAuditorScopeReject_NoRegistryReason(t *testing.T) {
	reader, teardown := installManualReader(t)
	defer teardown()

	r, err := NewReconciler(ReconcilerConfig{
		Verifier:        &fakeVerifier{},
		Heads:           NewTrustedHeadStore(slog.New(slog.NewTextHandler(io.Discard, nil))),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuditorRegistry: network.AuditorRegistrationByPosition{},
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	if r.authorizedForKind(context.Background(),
		"did:web:any.example.org", gossip.KindEquivocationFinding) {
		t.Fatal("empty registry must reject")
	}
	counts := collectRejectCounts(t, reader)
	if counts["no_registry|BP-GOSSIP-LEDGER-EQUIVOCATION-V1"] != 1 {
		t.Errorf("no_registry counter = %d, want 1 (all observed: %v)",
			counts["no_registry|BP-GOSSIP-LEDGER-EQUIVOCATION-V1"], counts)
	}
}

// TestAuditorScopeReject_UnsortedReason pins the unsorted path (Ladder
// 1 B1's defensive arm at the gate site).
func TestAuditorScopeReject_UnsortedReason(t *testing.T) {
	reader, teardown := installManualReader(t)
	defer teardown()

	reg := validAuditorRegistration(t, "did:web:registered.example.org", network.ScopeEquivocation)
	// Hand-roll an unsorted slice (BuildAuditorRegistryFromConfig
	// sorts; this bypasses that and exercises the SDK's
	// ErrAuditorRecordsUnsorted path).
	unsorted := network.AuditorRegistrationByPosition{
		{EffectivePos: types.LogPosition{Sequence: 10}, Payload: reg},
		{EffectivePos: types.LogPosition{Sequence: 5}, Payload: reg},
	}
	r, err := NewReconciler(ReconcilerConfig{
		Verifier:        &fakeVerifier{},
		Heads:           NewTrustedHeadStore(slog.New(slog.NewTextHandler(io.Discard, nil))),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuditorRegistry: unsorted,
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	if r.authorizedForKind(context.Background(),
		"did:web:registered.example.org", gossip.KindEquivocationFinding) {
		t.Fatal("unsorted registry must reject")
	}
	counts := collectRejectCounts(t, reader)
	if counts["unsorted|BP-GOSSIP-LEDGER-EQUIVOCATION-V1"] != 1 {
		t.Errorf("unsorted counter = %d, want 1 (all observed: %v)",
			counts["unsorted|BP-GOSSIP-LEDGER-EQUIVOCATION-V1"], counts)
	}
}
