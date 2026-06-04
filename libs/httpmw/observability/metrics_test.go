/*
FILE PATH: libs/httpmw/observability/metrics_test.go

DESCRIPTION:

	Pins the Prometheus metrics middleware:
	  1. A 200 response increments jn_http_requests_total{...,status="2xx"}.
	  2. A 500 response increments {...,status="5xx"}.
	  3. Duration histogram observes a sample per request.
	  4. In-flight gauge increments on entry and decrements on exit.
	  5. Handler() serves the registry as text/plain in
	     OpenMetrics format.
*/
package observability

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// scrape executes /metrics through the registry's handler and
// returns the response body. Failure here is a fixture/setup bug,
// not a runtime path.
func scrape(t *testing.T, r *MetricsRegistry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape /metrics: status=%d, want 200; body=%s",
			rec.Code, rec.Body.String())
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("scrape: read body: %v", err)
	}
	return string(body)
}

// findSeriesValue parses a Prometheus scrape line of the form
// "metric_name{label1=\"v1\",label2=\"v2\"} 42.0" and returns the
// numeric value. Reports false when the (name, labels) tuple is
// absent. Used to assert exact counter / gauge / histogram-suffix
// values against scrape output.
//
// labels is the inside of the {} braces, e.g. `route="/test",method="GET"`.
// The label substring is matched literally — Prometheus exposition
// uses a stable label-emission order for OTel, which we lock by
// instrument-attribute order in the producer.
func findSeriesValue(body, name, labels string) (float64, bool) {
	prefix := name
	if labels != "" {
		prefix = name + "{" + labels + "}"
	} else {
		prefix = name + " "
	}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		// "metric{labels} value [timestamp]"
		// We split on the LAST space to get the value column.
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(parts[len(parts)-1], 64)
		if err != nil {
			continue
		}
		return v, true
	}
	return 0, false
}

// findLabeledSeriesValue is a variant that doesn't require an
// exact label-string match — it lets the caller pass a regex-
// shaped label substring (escaped where needed). Used when label
// emission order is uncertain across OTel versions.
func findLabeledSeriesValue(body, name string, labelPattern *regexp.Regexp) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+"{") && !strings.HasPrefix(line, name+" ") {
			continue
		}
		if labelPattern != nil && !labelPattern.MatchString(line) {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(parts[len(parts)-1], 64)
		if err != nil {
			continue
		}
		return v, true
	}
	return 0, false
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func errHandler(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "x", code)
	})
}

// staticRoute returns a routeFn that always reports the same label.
func staticRoute(s string) func() string { return func() string { return s } }

// ─────────────────────────────────────────────────────────────────────
// jn_http_requests_total — counter wire format
// ─────────────────────────────────────────────────────────────────────

func TestMetrics_2xx_IncrementsCounter(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	h := r.Wrap(staticRoute("/test"), okHandler())
	for i := 0; i < 3; i++ {
		h.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/test", nil))
	}

	body := scrape(t, r)

	// The OTel→Prom convention: counters surface with the "_total"
	// suffix even when the instrument was registered as
	// "jn_http_requests" (no suffix). Pinning the wire form here
	// catches any regression in that translation.
	pattern := regexp.MustCompile(`route="/test"`)
	v, ok := findLabeledSeriesValue(body, "jn_http_requests_total", pattern)
	if !ok {
		t.Fatalf("jn_http_requests_total{route=\"/test\",...} absent from scrape:\n%s", body)
	}
	if v != 3 {
		t.Errorf("counter value = %v, want 3", v)
	}

	// TYPE descriptor must declare the metric as "counter" — the
	// OTel-Prom exporter converts the Int64Counter to this type.
	if !strings.Contains(body, "# TYPE jn_http_requests_total counter") {
		t.Errorf("scrape missing # TYPE jn_http_requests_total counter:\n%s", body)
	}
}

func TestMetrics_5xx_StatusClassBucket(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	h := r.Wrap(staticRoute("/oops"), errHandler(http.StatusInternalServerError))
	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/oops", nil))

	body := scrape(t, r)
	pattern := regexp.MustCompile(`route="/oops".*status="5xx"|status="5xx".*route="/oops"`)
	v, ok := findLabeledSeriesValue(body, "jn_http_requests_total", pattern)
	if !ok {
		t.Fatalf("jn_http_requests_total{...status=\"5xx\"} absent:\n%s", body)
	}
	if v != 1 {
		t.Errorf("5xx counter = %v, want 1", v)
	}
}

func TestMetrics_4xx_StatusClassBucket(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	h := r.Wrap(staticRoute("/bad"), errHandler(http.StatusBadRequest))
	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/bad", nil))

	body := scrape(t, r)
	pattern := regexp.MustCompile(`status="4xx"`)
	v, ok := findLabeledSeriesValue(body, "jn_http_requests_total", pattern)
	if !ok {
		t.Fatalf("jn_http_requests_total{...status=\"4xx\"} absent:\n%s", body)
	}
	if v != 1 {
		t.Errorf("4xx counter = %v, want 1", v)
	}
}

// ─────────────────────────────────────────────────────────────────────
// jn_http_request_duration_seconds — histogram wire format
// ─────────────────────────────────────────────────────────────────────

func TestMetrics_DurationHistogram_HasCountSumAndBuckets(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	h := r.Wrap(staticRoute("/t"), okHandler())
	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/t", nil))

	body := scrape(t, r)

	// Histograms surface as <name>_count, <name>_sum, and
	// <name>_bucket{le="..."} series. All three MUST appear.
	required := []string{
		"jn_http_request_duration_seconds_count",
		"jn_http_request_duration_seconds_sum",
		"jn_http_request_duration_seconds_bucket",
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q:\n%s", want, body)
		}
	}

	// _count after one observation is exactly 1.
	pattern := regexp.MustCompile(`route="/t"`)
	count, ok := findLabeledSeriesValue(body,
		"jn_http_request_duration_seconds_count", pattern)
	if !ok {
		t.Fatalf("histogram _count absent:\n%s", body)
	}
	if count != 1 {
		t.Errorf("_count = %v, want 1", count)
	}

	// TYPE must be histogram.
	if !strings.Contains(body, "# TYPE jn_http_request_duration_seconds_seconds histogram") &&
		!strings.Contains(body, "# TYPE jn_http_request_duration_seconds histogram") {
		t.Errorf("scrape missing # TYPE histogram for duration:\n%s", body)
	}
}

// ─────────────────────────────────────────────────────────────────────
// jn_http_in_flight_requests — gauge wire format
// ─────────────────────────────────────────────────────────────────────

func TestMetrics_InFlightGauge_IncDecBalanced(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	// Mid-handler scrape: read /metrics WHILE a request is in
	// flight to confirm the gauge sits at 1.
	midScrape := make(chan string, 1)
	h := r.Wrap(staticRoute("/t"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		midScrape <- scrape(t, r)
		w.WriteHeader(http.StatusOK)
	}))

	go h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/t", nil))

	body := <-midScrape
	pattern := regexp.MustCompile(`route="/t"`)
	v, ok := findLabeledSeriesValue(body, "jn_http_in_flight_requests", pattern)
	if !ok {
		t.Fatalf("jn_http_in_flight_requests absent during handler:\n%s", body)
	}
	if v != 1 {
		t.Errorf("in-flight during handler = %v, want 1", v)
	}

	// After the handler completes, scrape again and confirm the
	// gauge dropped back to 0 — Inc must be balanced by Dec.
	body = scrape(t, r)
	v, ok = findLabeledSeriesValue(body, "jn_http_in_flight_requests", pattern)
	if !ok {
		t.Fatalf("jn_http_in_flight_requests absent after handler:\n%s", body)
	}
	if v != 0 {
		t.Errorf("in-flight after handler = %v, want 0", v)
	}
}

// ─────────────────────────────────────────────────────────────────────
// /metrics endpoint shape + SDK wire-compat invariants
// ─────────────────────────────────────────────────────────────────────

func TestMetrics_Handler_ServesScrape(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	// Generate at least one sample so the registry has something
	// to render.
	r.Wrap(staticRoute("/t"), okHandler()).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/t", nil),
	)

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "jn_http_requests_total") {
		t.Errorf("metrics output missing jn_http_requests_total:\n%s", body)
	}
}

// TestMetrics_WireFormat_NoTargetInfo locks the wire-format-compat
// invariant inherited from the SDK primitive: no target_info, no
// otel_scope_info synthetic metrics. Existing Prometheus scrapers
// don't expect them; the SDK's exporter is configured to suppress
// them, and the JN registry MUST inherit that.
func TestMetrics_WireFormat_NoTargetInfo(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	r.Wrap(staticRoute("/t"), okHandler()).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/t", nil),
	)

	body := scrape(t, r)
	if strings.Contains(body, "target_info") {
		t.Errorf("scrape contains target_info; SDK invariant requires it suppressed:\n%s", body)
	}
	if strings.Contains(body, "otel_scope_info") {
		t.Errorf("scrape contains otel_scope_info; SDK invariant requires it suppressed:\n%s", body)
	}
}

// TestMetrics_WireFormat_HelpAndType pins the # HELP / # TYPE
// descriptors. Promethues clients use these to render dashboards
// and infer aggregation behavior; missing or drifted descriptors
// silently break dashboards.
func TestMetrics_WireFormat_HelpAndType(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	r.Wrap(staticRoute("/t"), okHandler()).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/t", nil),
	)

	body := scrape(t, r)

	requirements := []struct {
		desc, line string
	}{
		{
			"counter HELP",
			"# HELP jn_http_requests_total Total HTTP requests handled, labelled by route + method + status class.",
		},
		{
			"counter TYPE",
			"# TYPE jn_http_requests_total counter",
		},
		{
			"gauge HELP",
			"# HELP jn_http_in_flight_requests Currently in-flight HTTP requests, labelled by route.",
		},
		{
			"gauge TYPE — Int64UpDownCounter renders as Prometheus gauge",
			"# TYPE jn_http_in_flight_requests gauge",
		},
	}
	for _, req := range requirements {
		if !strings.Contains(body, req.line) {
			t.Errorf("%s missing — wanted %q\n--- scrape ---\n%s",
				req.desc, req.line, body)
		}
	}

	// The duration histogram's HELP/TYPE differ across OTel-Prom
	// exporter versions in their handling of the unit suffix; we
	// pin only the type-level invariant: it MUST surface as a
	// histogram (not a counter or gauge).
	if !regexp.MustCompile(`# TYPE jn_http_request_duration_seconds(_seconds)? histogram`).
		MatchString(body) {
		t.Errorf("histogram TYPE descriptor absent or wrong type:\n%s", body)
	}
}

// ─────────────────────────────────────────────────────────────────────
// classifyStatus
// ─────────────────────────────────────────────────────────────────────

func TestClassifyStatus_Buckets(t *testing.T) {
	cases := map[int]string{200: "2xx", 201: "2xx", 301: "3xx", 400: "4xx", 500: "5xx", 599: "5xx"}
	for code, want := range cases {
		if got := classifyStatus(code); got != want {
			t.Errorf("classifyStatus(%d) = %s, want %s", code, got, want)
		}
	}
}

// TestClassifyStatus_Outliers covers codes outside the 1xx-5xx
// canonical range — the function falls back to the raw integer
// to keep the cardinality bounded by the caller's behavior, not
// by an arbitrary cap.
func TestClassifyStatus_Outliers(t *testing.T) {
	if got := classifyStatus(700); got != "700" {
		t.Errorf("classifyStatus(700) = %s, want 700", got)
	}
	if got := classifyStatus(0); got != "0" {
		t.Errorf("classifyStatus(0) = %s, want 0", got)
	}
}

// Sanity: sprintf is used in the ledger metrics doc; pin that
// we don't accidentally drop fmt from the imports list during
// future edits.
var _ = fmt.Sprintf
