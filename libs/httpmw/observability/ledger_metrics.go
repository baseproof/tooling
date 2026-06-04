/*
FILE PATH: libs/httpmw/observability/ledger_metrics.go

DESCRIPTION:

	OTel instruments specific to the JN→ledger submit path.
	Distinct from the inbound HTTP RED metrics in metrics.go: these
	measure the OUTBOUND latency of the ledger submit, plus the
	circuit-breaker state, so dashboards can attribute tail-latency
	outliers + 503s to the ledger side rather than the JN side.

	Three instruments (registered on the same MeterProvider as the
	inbound RED metrics, so they all surface on /metrics):

	  jn_ledger_submit_total{result}
	    Counter. result ∈ {ok, error, circuit_open}.

	  jn_ledger_submit_duration_seconds
	    Histogram of submit duration. Same buckets as the inbound
	    latency histogram so dashboards can plot p99 ledger
	    latency next to p99 inbound latency.

	  jn_ledger_submit_breaker_state{state}
	    UpDownCounter. Set to 1 when the breaker is in the labelled
	    state, 0 otherwise. Three label values: closed / open /
	    half_open.

	LedgerSubmitMetrics consumes the supplied *MetricsRegistry's
	OTel Meter so the Prometheus exporter wires the instruments to
	the same /metrics handler.
*/
package observability

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// LedgerSubmitMetrics bundles the ledger-submit instruments.
// One instance per process; share via MetricsRegistry.
//
// breakerCurrent tracks the previously-emitted state so Observe()
// can implement Prometheus gauge semantics (exactly one label
// value = 1, all others = 0) on top of OTel's add-only
// UpDownCounter. Mutated under mu.
type LedgerSubmitMetrics struct {
	requests metric.Int64Counter
	duration metric.Float64Histogram
	breaker  metric.Int64UpDownCounter

	mu             sync.Mutex
	breakerCurrent string
}

// NewLedgerSubmitMetrics registers + returns the ledger-submit
// instruments using the supplied MetricsRegistry's underlying
// OTel MeterProvider.
//
// Panics on instrument-creation failure. The OTel SDK only fails
// instrument creation on missing required arguments (we supply
// all of them) or unknown views (we register none). The panic
// surfaces a programmer error at boot rather than as silent
// metric loss in production.
func NewLedgerSubmitMetrics(r *MetricsRegistry) *LedgerSubmitMetrics {
	meter := r.provider.Meter(
		"github.com/baseproof/tooling/libs/httpmw/observability/ledger_submit",
	)

	requests, err := meter.Int64Counter(
		// OTel-native name; the Prometheus exporter appends "_total"
		// in wire output, producing "jn_ledger_submit_total".
		"jn_ledger_submit",
		metric.WithDescription(
			"Total ledger submit attempts, labelled by outcome (ok / error / circuit_open)."),
	)
	if err != nil {
		panic(fmt.Sprintf("observability: ledger submit counter: %v", err))
	}

	duration, err := meter.Float64Histogram(
		"jn_ledger_submit_duration_seconds",
		metric.WithDescription("Ledger submit duration including SDK retry-after handling."),
		metric.WithUnit("s"),
	)
	if err != nil {
		panic(fmt.Sprintf("observability: ledger submit histogram: %v", err))
	}

	breaker, err := meter.Int64UpDownCounter(
		"jn_ledger_submit_breaker_state",
		metric.WithDescription(
			"Circuit breaker state for the ledger submit path "+
				"(per-state value: 1 = current state, 0 = not)."),
	)
	if err != nil {
		panic(fmt.Sprintf("observability: ledger submit breaker gauge: %v", err))
	}

	m := &LedgerSubmitMetrics{
		requests:       requests,
		duration:       duration,
		breaker:        breaker,
		breakerCurrent: "closed",
	}
	// Initialise breaker to closed = 1. Other states emit zero
	// implicitly (UpDownCounter starts at zero per label set).
	m.breaker.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("state", "closed")))
	return m
}

// Observe records one ledger-submit outcome. Pass:
//
//	durationSeconds  end-to-end submit latency
//	result           "ok" / "error" / "circuit_open"
//	breakerState     "closed" / "open" / "half_open" — emitted by
//	                 reliability.Breaker.State(); call sites pass it
//	                 in directly so this package doesn't depend on
//	                 reliability.
func (m *LedgerSubmitMetrics) Observe(durationSeconds float64, result, breakerState string) {
	ctx := context.Background()
	m.requests.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
	m.duration.Record(ctx, durationSeconds)
	// Breaker gauge semantics on top of UpDownCounter: subtract 1
	// from the previous state's series, add 1 to the new state's.
	// No-op when breakerState == breakerCurrent, so dashboards
	// don't see spurious blips.
	m.mu.Lock()
	defer m.mu.Unlock()
	if breakerState == m.breakerCurrent {
		return
	}
	m.breaker.Add(ctx, -1, metric.WithAttributes(attribute.String("state", m.breakerCurrent)))
	m.breaker.Add(ctx, 1, metric.WithAttributes(attribute.String("state", breakerState)))
	m.breakerCurrent = breakerState
}
