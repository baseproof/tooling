package obs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_InstrumentAndScrape(t *testing.T) {
	m := NewMetrics("test-1.2.3")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict) // 409
		_, _ = w.Write([]byte("nope"))
	})
	h := m.Instrument("v1_cosign", inner)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/cosign", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("instrumented status = %d, want 409", rec.Code)
	}

	scrape := httptest.NewRecorder()
	m.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := scrape.Body.String()
	for _, want := range []string{
		"witness_cosign_requests_total",
		`code="409"`,
		`route="v1_cosign"`,
		"witness_cosign_request_seconds",
		"witness_build_info",
		`version="test-1.2.3"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n---\n%s", want, body)
		}
	}
}

func TestMetrics_DefaultVersion(t *testing.T) {
	m := NewMetrics("")
	scrape := httptest.NewRecorder()
	m.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(scrape.Body.String(), `version="dev"`) {
		t.Errorf("empty version not recorded as dev")
	}
}

// statusRecorder must default to 200 when the inner handler writes a
// body without an explicit WriteHeader.
func TestMetrics_Implicit200(t *testing.T) {
	m := NewMetrics("v")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok")) // no WriteHeader
	})
	rec := httptest.NewRecorder()
	m.Instrument("v1_cosign", inner).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	scrape := httptest.NewRecorder()
	m.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(scrape.Body.String(), `code="200"`) {
		t.Errorf("implicit write not counted as 200")
	}
}
