package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMonitoringMetrics_RecordAndScrape(t *testing.T) {
	reg := NewMetricsRegistry()
	mm := NewMonitoringMetrics(reg)

	mm.RecordRun("mirror_consistency", true, 150*time.Millisecond, map[string]int{"warning": 2, "critical": 1})
	mm.RecordRun("anchor_freshness", false, 2*time.Second, nil)

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)
	for _, want := range []string{
		"jn_monitor_runs", "jn_monitor_up", "jn_monitor_alerts",
		"mirror_consistency", "anchor_freshness",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("scrape output missing %q", want)
		}
	}
}
