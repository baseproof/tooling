/*
FILE PATH: libs/httpmw/observability/ledger_metrics_test.go

DESCRIPTION:

	Pins the ledger-submit metrics:
	  1. Counter increments per result.
	  2. Duration histogram observes per call.
	  3. Breaker gauge is exclusive — when state="open", the
	     "closed" + "half_open" gauges are 0.
	  4. Initial state is "closed" with gauge=1, others=0.
*/
package observability

import (
	"regexp"
	"strings"
	"testing"
)

func TestLedgerSubmitMetrics_CounterByResult(t *testing.T) {
	r := NewMetricsRegistry()
	m := NewLedgerSubmitMetrics(r)
	m.Observe(0.05, "ok", "closed")
	m.Observe(0.05, "ok", "closed")
	m.Observe(0.10, "error", "closed")
	m.Observe(0.00, "circuit_open", "open")

	body := scrape(t, r)

	cases := []struct {
		result string
		want   float64
	}{
		{"ok", 2},
		{"error", 1},
		{"circuit_open", 1},
	}
	for _, tc := range cases {
		pat := regexp.MustCompile(`result="` + regexp.QuoteMeta(tc.result) + `"`)
		v, ok := findLabeledSeriesValue(body, "jn_ledger_submit_total", pat)
		if !ok {
			t.Fatalf("jn_ledger_submit_total{result=%q} absent:\n%s", tc.result, body)
		}
		if v != tc.want {
			t.Errorf("counter result=%q = %v, want %v", tc.result, v, tc.want)
		}
	}

	if !strings.Contains(body, "# TYPE jn_ledger_submit_total counter") {
		t.Errorf("scrape missing # TYPE jn_ledger_submit_total counter:\n%s", body)
	}
}

func TestLedgerSubmitMetrics_DurationObserved(t *testing.T) {
	r := NewMetricsRegistry()
	m := NewLedgerSubmitMetrics(r)
	m.Observe(0.10, "ok", "closed")
	m.Observe(0.50, "ok", "closed")

	body := scrape(t, r)

	for _, want := range []string{
		"jn_ledger_submit_duration_seconds_count",
		"jn_ledger_submit_duration_seconds_sum",
		"jn_ledger_submit_duration_seconds_bucket",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q:\n%s", want, body)
		}
	}

	// _count = 2 after two observations.
	count, ok := findSeriesValue(body, "jn_ledger_submit_duration_seconds_count", "")
	if !ok {
		t.Fatalf("histogram _count absent:\n%s", body)
	}
	if count != 2 {
		t.Errorf("_count = %v, want 2", count)
	}

	// _sum is the float total — 0.10 + 0.50 = 0.60.
	sum, ok := findSeriesValue(body, "jn_ledger_submit_duration_seconds_sum", "")
	if !ok {
		t.Fatalf("histogram _sum absent:\n%s", body)
	}
	const wantSum = 0.60
	if sum < wantSum-1e-9 || sum > wantSum+1e-9 {
		t.Errorf("_sum = %v, want %v", sum, wantSum)
	}
}

func TestLedgerSubmitMetrics_BreakerGauge_Exclusive(t *testing.T) {
	r := NewMetricsRegistry()
	m := NewLedgerSubmitMetrics(r)
	m.Observe(0.10, "circuit_open", "open")

	body := scrape(t, r)

	cases := []struct {
		state string
		want  float64
	}{
		{"open", 1},
		{"closed", 0},
		{"half_open", 0},
	}
	for _, tc := range cases {
		pat := regexp.MustCompile(`state="` + regexp.QuoteMeta(tc.state) + `"`)
		v, ok := findLabeledSeriesValue(body, "jn_ledger_submit_breaker_state", pat)
		if !ok {
			// OTel UpDownCounter only emits a series when the label
			// has been touched. half_open was never set; an absent
			// series IS the same observable as 0, so tolerate.
			if tc.want == 0 {
				continue
			}
			t.Fatalf("breaker gauge state=%q absent:\n%s", tc.state, body)
		}
		if v != tc.want {
			t.Errorf("breaker gauge state=%q = %v, want %v (exclusive-1 invariant)", tc.state, v, tc.want)
		}
	}
}

func TestLedgerSubmitMetrics_InitialState_Closed(t *testing.T) {
	r := NewMetricsRegistry()
	_ = NewLedgerSubmitMetrics(r) // construction installs the initial gauge
	body := scrape(t, r)
	cases := []struct {
		state string
		want  float64
	}{
		{"closed", 1},
		{"open", 0},
		{"half_open", 0},
	}
	for _, tc := range cases {
		pat := regexp.MustCompile(`state="` + regexp.QuoteMeta(tc.state) + `"`)
		v, ok := findLabeledSeriesValue(body, "jn_ledger_submit_breaker_state", pat)
		if !ok {
			// half_open / open may not yet appear in the
			// scrape until they're touched; tolerate missing-label
			// for the non-current states. The "closed=1" assertion
			// is the load-bearing one.
			if tc.want == 0 {
				continue
			}
			t.Fatalf("breaker gauge state=%q absent on initial scrape:\n%s", tc.state, body)
		}
		if v != tc.want {
			t.Errorf("initial state=%q = %v, want %v", tc.state, v, tc.want)
		}
	}
}

func TestLedgerSubmit_BreakerGauge_TransitionUpdatesScrape(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	m := NewLedgerSubmitMetrics(r)

	// Start: closed (initial). Confirm.
	body := scrape(t, r)
	if v, _ := findLabeledSeriesValue(body, "jn_ledger_submit_breaker_state",
		regexp.MustCompile(`state="closed"`)); v != 1 {
		t.Fatalf("initial closed=%v, want 1", v)
	}

	// Transition to open. Confirm closed=0, open=1.
	m.Observe(0.10, "circuit_open", "open")
	body = scrape(t, r)
	if v, _ := findLabeledSeriesValue(body, "jn_ledger_submit_breaker_state",
		regexp.MustCompile(`state="open"`)); v != 1 {
		t.Errorf("post-transition open=%v, want 1", v)
	}
	if v, _ := findLabeledSeriesValue(body, "jn_ledger_submit_breaker_state",
		regexp.MustCompile(`state="closed"`)); v != 0 {
		t.Errorf("post-transition closed=%v, want 0", v)
	}

	// Transition to half_open. Confirm open=0, half_open=1.
	m.Observe(0.10, "ok", "half_open")
	body = scrape(t, r)
	if v, _ := findLabeledSeriesValue(body, "jn_ledger_submit_breaker_state",
		regexp.MustCompile(`state="half_open"`)); v != 1 {
		t.Errorf("post-transition half_open=%v, want 1", v)
	}
	if v, _ := findLabeledSeriesValue(body, "jn_ledger_submit_breaker_state",
		regexp.MustCompile(`state="open"`)); v != 0 {
		t.Errorf("post-transition open=%v, want 0", v)
	}
}

// ─────────────────────────────────────────────────────────────────────
// HELP + TYPE descriptors
// ─────────────────────────────────────────────────────────────────────

func TestLedgerSubmit_WireFormat_HelpAndType(t *testing.T) {
	r := NewMetricsRegistry()
	defer func() { _ = r.Shutdown(t.Context()) }()

	m := NewLedgerSubmitMetrics(r)
	m.Observe(0.10, "ok", "closed")

	body := scrape(t, r)

	requirements := []string{
		"# HELP jn_ledger_submit_total Total ledger submit attempts, labelled by outcome (ok / error / circuit_open).",
		"# TYPE jn_ledger_submit_total counter",
		"# HELP jn_ledger_submit_breaker_state",
		"# TYPE jn_ledger_submit_breaker_state",
	}
	for _, want := range requirements {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n--- body ---\n%s", want, body)
		}
	}

	// Histogram TYPE: histogram regardless of the exporter's unit-suffix policy.
	if !regexp.MustCompile(`# TYPE jn_ledger_submit_duration_seconds(_seconds)? histogram`).
		MatchString(body) {
		t.Errorf("ledger submit histogram TYPE missing or wrong:\n%s", body)
	}
}
