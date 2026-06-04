/*
FILE PATH: gossipnet/instruments_test.go

Unit coverage for the D4 witness-quorum + equivocation OTel counters
(gossipnet/instruments.go), asserted against a REAL in-memory MeterProvider
from the baseproof SDK (log.NewInMemoryMeterProvider — the sanctioned test
provider, default views). Pins the behaviour the boot wiring and the
checkpoint loop's SRE signal depend on:

  - Install*Counter(nil) is a no-op (witness-free / metric-free deployments).
  - Install*Counter is idempotent (a second install returns false).
  - IncWitnessQuorumFailure records on baseproof_witness_quorum_failures_total
    with the network_id label, once per call.
  - IncEquivocationDetected records on baseproof_equivocation_detected_total
    with the (kind, originator) labels.
  - An Inc issued BEFORE install is a silent no-op (no panic, no record) — the
    "safe to call before Install" contract the loop relies on.

The counters are package-level singletons; each test owns one counter's state
and resets it on cleanup so the suite is -count=N safe.
*/
package gossipnet

import (
	"context"
	"testing"

	baseprooflog "github.com/baseproof/baseproof/log"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// counterValue sums the int64 data points of a counter metric by name and
// returns the total plus the value of labelKey seen on a data point. Returns
// (-1, "") when the metric is absent from the collection.
func counterValue(t *testing.T, reader *sdkmetric.ManualReader, name, labelKey string) (int64, string) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("ManualReader.Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric %q: data %T, want Sum[int64]", name, m.Data)
			}
			var total int64
			var label string
			for _, dp := range sum.DataPoints {
				total += dp.Value
				if v, ok := dp.Attributes.Value(attribute.Key(labelKey)); ok {
					label = v.AsString()
				}
			}
			return total, label
		}
	}
	return -1, ""
}

// TestWitnessQuorumFailureCounter pins the witness-quorum counter end to end on
// a real OTel pipeline: nil-meter install is a no-op, Inc records under the
// network_id label, an Inc before install records nothing, and install is
// idempotent.
func TestWitnessQuorumFailureCounter(t *testing.T) {
	t.Cleanup(func() {
		quorumFailureState.mu.Lock()
		quorumFailureState.counter = nil
		quorumFailureState.mu.Unlock()
	})
	ctx := context.Background()

	// nil meter ⇒ no-op (a witness-free deployment installs nothing).
	if InstallWitnessQuorumFailureCounter(nil) {
		t.Fatal("InstallWitnessQuorumFailureCounter(nil) = true, want false")
	}
	// Inc before install must be a silent no-op (no panic, no record). The
	// sentinel label makes a leak visible in the count assertion below.
	IncWitnessQuorumFailure(ctx, "ffffffffffffffff")

	provider, reader := baseprooflog.NewInMemoryMeterProvider()
	if !InstallWitnessQuorumFailureCounter(provider.Meter("test")) {
		t.Fatal("first install on a real meter = false, want true")
	}
	if InstallWitnessQuorumFailureCounter(provider.Meter("test")) {
		t.Fatal("second install = true, want false (must be idempotent)")
	}

	const nid = "a1b2c3d4e5f60718"
	IncWitnessQuorumFailure(ctx, nid)
	IncWitnessQuorumFailure(ctx, nid)
	IncWitnessQuorumFailure(ctx, nid)

	got, label := counterValue(t, reader, "baseproof_witness_quorum_failures_total", "network_id")
	if got != 3 {
		t.Errorf("counter = %d, want 3 (the pre-install Inc must NOT have recorded)", got)
	}
	if label != nid {
		t.Errorf("network_id label = %q, want %q", label, nid)
	}
}

// TestEquivocationDetectedCounter pins the equivocation counter records under
// the (kind, originator) labels — the bounded-cardinality contract operators
// alert on.
func TestEquivocationDetectedCounter(t *testing.T) {
	t.Cleanup(func() {
		equivocationDetectedState.mu.Lock()
		equivocationDetectedState.counter = nil
		equivocationDetectedState.mu.Unlock()
	})
	ctx := context.Background()

	if InstallEquivocationDetectedCounter(nil) {
		t.Fatal("InstallEquivocationDetectedCounter(nil) = true, want false")
	}

	provider, reader := baseprooflog.NewInMemoryMeterProvider()
	if !InstallEquivocationDetectedCounter(provider.Meter("test")) {
		t.Fatal("install on a real meter = false, want true")
	}

	const kind = "equivocation_finding"
	const originator = "did:web:peer.example.org"
	IncEquivocationDetected(ctx, kind, originator)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "baseproof_equivocation_detected_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric data %T, want Sum[int64]", m.Data)
			}
			for _, dp := range sum.DataPoints {
				k, _ := dp.Attributes.Value(attribute.Key("kind"))
				o, _ := dp.Attributes.Value(attribute.Key("originator"))
				if k.AsString() == kind && o.AsString() == originator {
					found = true
					if dp.Value != 1 {
						t.Errorf("count = %d, want 1", dp.Value)
					}
				}
			}
		}
	}
	if !found {
		t.Fatalf("baseproof_equivocation_detected_total{kind=%q,originator=%q} was not recorded", kind, originator)
	}
}
