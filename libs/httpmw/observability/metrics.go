/*
FILE PATH: libs/httpmw/observability/metrics.go

DESCRIPTION:

	Prometheus metrics middleware. Emits the RED triad (Rate /
	Errors / Duration) plus an in-flight gauge per route. Labels
	are kept minimal + bounded:

	  route   — the matched mux pattern (low-cardinality; dozens)
	  method  — HTTP verb (small fixed set)
	  status  — class bucket "2xx" / "4xx" / "5xx" / etc.
	            Using the class instead of the raw code keeps
	            cardinality bounded against a handler that returns
	            arbitrary status codes.

	Caller DID is deliberately NOT a label — that would explode
	cardinality at 10M/day across thousands of distinct callers.
	Per-caller telemetry belongs in structured logs (logger.go).

	/metrics is mounted by the composer outside the auth + rate-
	limit + body-size wrappers so Prometheus scrapers can always
	reach it (the same rationale as /healthz).
*/
package observability

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	sdklog "github.com/baseproof/baseproof/log"
)

// MetricsRegistryConfig configures the JN MetricsRegistry's
// underlying OTel MeterProvider. Production callers populate every
// field from build/deploy info; tests use NewMetricsRegistry() which
// substitutes safe defaults.
type MetricsRegistryConfig struct {
	// ServiceName identifies the binary in resource attributes.
	// Defaults to "jn" if empty.
	ServiceName string

	// ServiceVersion is the binary's git tag or build hash.
	// Defaults to "dev" if empty.
	ServiceVersion string

	// Environment identifies the deployment context. Defaults to
	// "production" if empty. Convention: "production", "staging",
	// "dev", "test".
	Environment string
}

// MetricsRegistry bundles the OTel HTTP-metric instruments. One
// instance per process; created at boot (via NewMetricsRegistry)
// and shared across every middleware wrapper.
//
// The internal MeterProvider is isolated per registry — tests
// instantiate one per test for parallel safety; production uses a
// single process-wide instance. The Prometheus handler returned by
// Handler() pulls from the same provider; no global registry is
// touched.
type MetricsRegistry struct {
	provider *sdkmetric.MeterProvider
	handler  http.Handler
	shutdown func(context.Context) error

	requests metric.Int64Counter
	duration metric.Float64Histogram
	inFlight metric.Int64UpDownCounter
}

// NewMetricsRegistry constructs a MetricsRegistry with default
// configuration ("jn" / "dev" / "production"). Tests use this
// parameterless form; production uses NewMetricsRegistryWithConfig
// for explicit service-identity wiring.
func NewMetricsRegistry() *MetricsRegistry {
	return NewMetricsRegistryWithConfig(MetricsRegistryConfig{})
}

// NewMetricsRegistryWithConfig is the production constructor. Empty
// fields fall back to the defaults documented on MetricsRegistryConfig.
//
// Panics on instrument-creation failure. The OTel SDK only fails
// instrument creation on missing required arguments (we supply all
// of them) or unknown views (we register none here), so this branch
// is unreachable for valid inputs. The panic surfaces a programmer
// error at boot rather than as silent metric loss in production.
func NewMetricsRegistryWithConfig(cfg MetricsRegistryConfig) *MetricsRegistry {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "jn"
	}
	if cfg.ServiceVersion == "" {
		cfg.ServiceVersion = "dev"
	}
	if cfg.Environment == "" {
		cfg.Environment = "production"
	}

	res, err := sdklog.NewMeterProvider(sdklog.MeterProviderConfig{
		ServiceName:    cfg.ServiceName,
		ServiceVersion: cfg.ServiceVersion,
		Environment:    cfg.Environment,
	})
	if err != nil {
		// Unreachable for valid config; we just defaulted every
		// required field. Treat as boot-time programmer error.
		panic(fmt.Sprintf("observability: NewMetricsRegistry: %v", err))
	}

	meter := res.Provider.Meter(
		"github.com/baseproof/tooling/libs/httpmw/observability",
	)

	requests, err := meter.Int64Counter(
		// OTel-native name; the Prometheus exporter appends "_total"
		// in wire output, producing "jn_http_requests_total".
		"jn_http_requests",
		metric.WithDescription(
			"Total HTTP requests handled, labelled by route + method + status class."),
	)
	if err != nil {
		panic(fmt.Sprintf("observability: counter: %v", err))
	}

	duration, err := meter.Float64Histogram(
		"jn_http_request_duration_seconds",
		metric.WithDescription("HTTP request duration, labelled by route + method."),
		metric.WithUnit("s"),
	)
	if err != nil {
		panic(fmt.Sprintf("observability: histogram: %v", err))
	}

	inFlight, err := meter.Int64UpDownCounter(
		"jn_http_in_flight_requests",
		metric.WithDescription("Currently in-flight HTTP requests, labelled by route."),
	)
	if err != nil {
		panic(fmt.Sprintf("observability: gauge: %v", err))
	}

	return &MetricsRegistry{
		provider: res.Provider,
		handler:  res.PrometheusHandler,
		shutdown: res.Shutdown,
		requests: requests,
		duration: duration,
		inFlight: inFlight,
	}
}

// Handler returns the /metrics scraper handler. Mount on the
// composer outside auth + rate-limit so Prometheus can always
// reach it.
func (r *MetricsRegistry) Handler() http.Handler {
	return r.handler
}

// Shutdown flushes pending exports and closes the underlying
// MeterProvider. For the Prometheus exporter (pull-based), this is
// effectively a no-op; for any future OTLP exporter the SDK adds,
// it flushes the pending batch. Safe to call twice.
func (r *MetricsRegistry) Shutdown(ctx context.Context) error {
	return r.shutdown(ctx)
}

// Wrap returns middleware that records the RED triad + in-flight
// gauge for every request through next. The route label is read
// from the supplied routeFn — typically a closure that returns
// the static route this handler is mounted at (e.g. "/v1/judicial").
// Using a closure rather than r.URL.Path keeps cardinality bounded
// (request paths with sequence numbers / DIDs would otherwise
// explode the label space).
func (r *MetricsRegistry) Wrap(routeFn func() string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		route := routeFn()

		routeAttr := attribute.String("route", route)
		methodAttr := attribute.String("method", req.Method)

		r.inFlight.Add(ctx, 1, metric.WithAttributes(routeAttr))
		defer r.inFlight.Add(ctx, -1, metric.WithAttributes(routeAttr))

		rec := newStatusRecorder(w)
		start := time.Now()
		next.ServeHTTP(rec, req)
		elapsed := time.Since(start).Seconds()

		statusAttr := attribute.String("status", classifyStatus(rec.status))
		r.requests.Add(ctx, 1, metric.WithAttributes(routeAttr, methodAttr, statusAttr))
		r.duration.Record(ctx, elapsed, metric.WithAttributes(routeAttr, methodAttr))
	})
}

// statusRecorder wraps http.ResponseWriter to capture the status
// code for the metrics label without buffering the body. Default
// to 200 because Go's stdlib treats an unwritten WriteHeader as
// 200 OK.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func newStatusRecorder(w http.ResponseWriter) *statusRecorder {
	return &statusRecorder{ResponseWriter: w, status: http.StatusOK}
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// classifyStatus collapses raw codes into the class bucket
// ("2xx" / "4xx" / "5xx") to keep label cardinality bounded.
// 1xx and 3xx are uncommon enough to share their own buckets.
func classifyStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	}
	return strconv.Itoa(code)
}
