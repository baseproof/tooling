package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/gossip"

	sdkmon "github.com/baseproof/baseproof/monitoring"

	"github.com/baseproof/tooling/libs/monitoring"
)

func TestFindings_NilStore_Honest503(t *testing.T) {
	rec := httptest.NewRecorder()
	NewFindingsHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/findings", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("health-only node must say so: %d", rec.Code)
	}
}

func TestFindings_EmptyStore_EmptyListAndCursor(t *testing.T) {
	rec := httptest.NewRecorder()
	NewFindingsHandler(gossip.NewInMemoryStore()).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/v1/findings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("empty store is a 200 with empty findings: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Findings   []json.RawMessage `json:"findings"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Findings) != 0 || body.NextCursor == "" {
		t.Fatalf("want empty findings + a resumable cursor: %+v", body)
	}
}

func TestFindings_BadInputsRefused(t *testing.T) {
	h := NewFindingsHandler(gossip.NewInMemoryStore())
	for _, q := range []string{"?limit=0", "?limit=-3", "?limit=zzz", "?cursor=*bad*", "?cursor=AAAA"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/findings"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s must be a 400: got %d", q, rec.Code)
		}
	}
}

func TestMonitors_NilScheduler_HonestEmpty(t *testing.T) {
	rec := httptest.NewRecorder()
	NewMonitorsHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/monitors", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"monitors":[]`) {
		t.Fatalf("no scheduler = explicit empty list, never invented: %d %s", rec.Code, rec.Body.String())
	}
}

func TestMonitors_RegisteredJobsServed(t *testing.T) {
	sched := monitoring.NewScheduler(monitoring.SchedulerConfig{})
	if err := sched.Register(monitoring.Job{
		Name:     "horizon_audit",
		Interval: time.Hour,
		Run:      func(context.Context) ([]sdkmon.Alert, error) { return nil, nil },
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	NewMonitorsHandler(sched).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/monitors", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "horizon_audit") {
		t.Fatalf("registered monitor must be served: %d %s", rec.Code, rec.Body.String())
	}
}
