package observability

/*
gauges_test.go — the gauge-registration contract.

RegisterFloat64Gauge / RegisterInt64Gauge return a bool that is normally
ignored at the call site (the source works without the metric — never fatal),
which is exactly why the false path needs a test: a regression that started
swallowing real registrations would be invisible. Pin the nil-guards (no meter,
no provider → false, no panic) and the success path (a working meter → true).
T0; an OTel no-op meter, no exporter.
*/

import (
	"testing"

	"go.opentelemetry.io/otel/metric/noop"
)

func TestRegisterFloat64Gauge_Contract(t *testing.T) {
	m := noop.NewMeterProvider().Meter("test")
	provider := func() float64 { return 1.5 }

	if RegisterFloat64Gauge(nil, "x", "d", provider) {
		t.Error("nil meter must return false (registration cannot succeed)")
	}
	if RegisterFloat64Gauge(m, "x", "d", nil) {
		t.Error("nil provider must return false")
	}
	if !RegisterFloat64Gauge(m, "wal_backlog", "backlog depth", provider) {
		t.Error("a working meter + provider must register and return true")
	}
}

func TestRegisterInt64Gauge_Contract(t *testing.T) {
	m := noop.NewMeterProvider().Meter("test")
	provider := func() int64 { return 7 }

	if RegisterInt64Gauge(nil, "x", "d", provider) {
		t.Error("nil meter must return false")
	}
	if RegisterInt64Gauge(m, "x", "d", nil) {
		t.Error("nil provider must return false")
	}
	if !RegisterInt64Gauge(m, "horizon_lag", "lag", provider) {
		t.Error("a working meter + provider must register and return true")
	}
}
