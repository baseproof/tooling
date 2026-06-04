/*
FILE PATH: internal/obs/metrics.go

Prometheus instrumentation for the witness daemon. Metrics are
registered on a dedicated registry (not the global default) so the
daemon owns exactly what it exposes and tests can build throwaway
instances without global-state collisions.

Exposed series:

	witness_cosign_requests_total{route,code}  counter
	witness_cosign_request_seconds{route}      histogram (latency)
	witness_build_info{version}                gauge (always 1)

The /metrics endpoint is mounted by main.go via Handler(); the
cosign endpoint is wrapped via Instrument() so every response —
200 sign, 409 misfire, 403 purpose/network, 5xx — is counted by its
HTTP status.
*/
package obs

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the daemon's Prometheus collectors on a private
// registry.
type Metrics struct {
	reg      *prometheus.Registry
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewMetrics builds + registers the collectors and stamps build_info
// with version. version "" is recorded as "dev".
func NewMetrics(version string) *Metrics {
	if version == "" {
		version = "dev"
	}
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "witness_cosign_requests_total",
			Help: "Cosign HTTP requests by route and response code.",
		}, []string{"route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "witness_cosign_request_seconds",
			Help:    "Cosign HTTP request latency by route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "witness_build_info",
		Help: "Build metadata; value is always 1.",
	}, []string{"version"})
	buildInfo.WithLabelValues(version).Set(1)

	reg.MustRegister(m.requests, m.duration, buildInfo)
	// Standard process + Go runtime collectors for SRE baseline.
	reg.MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)
	return m
}

// Handler returns the /metrics scrape handler over this registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Instrument wraps next, recording request count (by status code)
// and latency under the given route label.
func (m *Metrics) Instrument(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.duration.WithLabelValues(route).Observe(time.Since(start).Seconds())
		m.requests.WithLabelValues(route, strconv.Itoa(rec.status)).Inc()
	})
}

// statusRecorder captures the response status code for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true // implicit 200
	}
	return s.ResponseWriter.Write(b)
}
