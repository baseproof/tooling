// Read-on-scrape observable gauges (Phase 2 durability surface).
//
// FILE PATH:
//
//	observability/gauges.go
//
// DESCRIPTION:
//
//	Generic helpers to register a single-value OTel ObservableGauge whose
//	provider is invoked on each metric collection. Used for the Phase-2
//	"sustained/durability" gauges the operator watches at 30K:
//
//	  - baseproof_shipper_aimd_limit   (float) the AIMD congestion-control limit
//	  - baseproof_wal_backlog_total    (int)   sequenced-but-not-shipped entries
//	  - baseproof_horizon_lag_total    (int)   committed head size minus published
//	                                           (witness-cosigned) horizon size
//
//	Each is no-label (the ledger is a singleton) and no-op when the meter or
//	provider is nil, so callers can register unconditionally.
package observability

import (
	"context"

	"go.opentelemetry.io/otel/metric"
)

// RegisterFloat64Gauge registers a read-on-scrape Float64ObservableGauge that
// calls provider on each collection. Returns true on success; false when the
// meter/provider is nil or registration fails (the source still works without
// the metric — never fatal).
func RegisterFloat64Gauge(meter metric.Meter, name, desc string, provider func() float64) bool {
	if meter == nil || provider == nil {
		return false
	}
	// Deliberately NO WithUnit: these are bare-named counts/levels (backlog, horizon
	// lag, AIMD limit). UCUM unit "1" makes the OTel→Prometheus exporter append a
	// "_ratio" suffix (baseproof_wal_backlog_total_ratio …), which breaks bare-name
	// scrapers (the e2e durability check) and mislabels a count as a ratio.
	g, err := meter.Float64ObservableGauge(
		name,
		metric.WithDescription(desc),
	)
	if err != nil {
		return false
	}
	_, err = meter.RegisterCallback(func(_ context.Context, obs metric.Observer) error {
		obs.ObserveFloat64(g, provider())
		return nil
	}, g)
	return err == nil
}

// RegisterInt64Gauge is RegisterFloat64Gauge for an int64-valued provider.
func RegisterInt64Gauge(meter metric.Meter, name, desc string, provider func() int64) bool {
	if meter == nil || provider == nil {
		return false
	}
	// Deliberately NO WithUnit — see RegisterFloat64Gauge: unit "1" appends a
	// "_ratio" suffix that breaks bare-name scrapers and mislabels a count as a ratio.
	g, err := meter.Int64ObservableGauge(
		name,
		metric.WithDescription(desc),
	)
	if err != nil {
		return false
	}
	_, err = meter.RegisterCallback(func(_ context.Context, obs metric.Observer) error {
		obs.ObserveInt64(g, provider())
		return nil
	}, g)
	return err == nil
}
