// FILE PATH: libs/httpmw/observability/monitoring_metrics.go
//
// DESCRIPTION:
//
//	OTel instruments for the continuous-monitoring scheduler. The
//	scheduler computes each audit on a ticker and Records the outcome
//	here; Prometheus reads the last value at /metrics for free. This is
//	the "cached health served over HTTP" surface — the loops never
//	perform external alerting I/O (no Slack / PagerDuty); routing is left
//	to the scrape-side Grafana / Alertmanager stack.
//
//	Implements the monitoring scheduler's Sink with primitive arguments,
//	so this low-level package never imports the monitoring package.
package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// MonitoringMetrics publishes per-job scheduler health.
type MonitoringMetrics struct {
	runs     metric.Int64Counter     // jn_monitor_runs_total{job,outcome}
	duration metric.Float64Histogram // jn_monitor_run_duration_seconds{job}
	up       metric.Int64Gauge       // jn_monitor_up{job}
	lastRun  metric.Int64Gauge       // jn_monitor_last_run_unixtime{job}
	alerts   metric.Int64Gauge       // jn_monitor_alerts{job,severity}
}

// NewMonitoringMetrics constructs the instruments against the registry's
// meter provider. Panics on instrument-creation failure (boot-time
// programmer error), matching the other metric bundles in this package.
func NewMonitoringMetrics(r *MetricsRegistry) *MonitoringMetrics {
	meter := r.provider.Meter(
		"github.com/baseproof/tooling/libs/httpmw/observability/monitoring",
	)
	runs, err := meter.Int64Counter("jn_monitor_runs",
		metric.WithDescription("Scheduled monitor runs, labelled by job + outcome (ok/error)."))
	if err != nil {
		panic(fmt.Sprintf("observability: monitor runs counter: %v", err))
	}
	duration, err := meter.Float64Histogram("jn_monitor_run_duration_seconds",
		metric.WithDescription("Scheduled monitor run duration."), metric.WithUnit("s"))
	if err != nil {
		panic(fmt.Sprintf("observability: monitor duration histogram: %v", err))
	}
	up, err := meter.Int64Gauge("jn_monitor_up",
		metric.WithDescription("1 if the job's last run completed without error, else 0."))
	if err != nil {
		panic(fmt.Sprintf("observability: monitor up gauge: %v", err))
	}
	lastRun, err := meter.Int64Gauge("jn_monitor_last_run_unixtime",
		metric.WithDescription("Unix timestamp of the job's last run."))
	if err != nil {
		panic(fmt.Sprintf("observability: monitor last-run gauge: %v", err))
	}
	alerts, err := meter.Int64Gauge("jn_monitor_alerts",
		metric.WithDescription("Alerts from the job's last run, labelled by severity."))
	if err != nil {
		panic(fmt.Sprintf("observability: monitor alerts gauge: %v", err))
	}
	return &MonitoringMetrics{runs: runs, duration: duration, up: up, lastRun: lastRun, alerts: alerts}
}

// RecordRun implements the scheduler's Sink contract.
func (m *MonitoringMetrics) RecordRun(job string, ok bool, dur time.Duration, alertsBySeverity map[string]int) {
	ctx := context.Background()
	jobAttr := attribute.String("job", job)

	outcome := "ok"
	var upVal int64 = 1
	if !ok {
		outcome = "error"
		upVal = 0
	}
	m.runs.Add(ctx, 1, metric.WithAttributes(jobAttr, attribute.String("outcome", outcome)))
	m.duration.Record(ctx, dur.Seconds(), metric.WithAttributes(jobAttr))
	m.up.Record(ctx, upVal, metric.WithAttributes(jobAttr))
	m.lastRun.Record(ctx, time.Now().Unix(), metric.WithAttributes(jobAttr))

	// Emit every severity each run so a cleared alert resets its gauge to 0.
	for _, sev := range []string{"info", "warning", "critical"} {
		m.alerts.Record(ctx, int64(alertsBySeverity[sev]),
			metric.WithAttributes(jobAttr, attribute.String("severity", sev)))
	}
}
