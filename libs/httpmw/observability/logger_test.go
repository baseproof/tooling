/*
FILE PATH: libs/httpmw/observability/logger_test.go

DESCRIPTION:

	Pins the structured-logger middleware:
	  1. Every request emits one JSON log line with the canonical
	     fields (method, route, path, status, latency_ms).
	  2. The request_id from RequestID middleware lands in the
	     log line.
	  3. The caller_did from httpmw.CallerDIDFromContext lands
	     in the log line.
	  4. Status drives the log level: 2xx → info, 4xx → warn,
	     5xx → error.
*/
package observability

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/baseproof/tooling/libs/httpmw"
)

func captureLogger(t *testing.T) (*bytes.Buffer, zerolog.Logger) {
	t.Helper()
	var buf bytes.Buffer
	return &buf, zerolog.New(&buf)
}

type logLine struct {
	Level     string `json:"level"`
	Method    string `json:"method"`
	Route     string `json:"route"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	RequestID string `json:"request_id"`
	CallerDID string `json:"caller_did"`
	Message   string `json:"message"`
}

func decodeLast(t *testing.T, buf *bytes.Buffer) logLine {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) == 0 || len(lines[len(lines)-1]) == 0 {
		t.Fatalf("no log lines captured: %q", buf.String())
	}
	var l logLine
	if err := json.Unmarshal(lines[len(lines)-1], &l); err != nil {
		t.Fatalf("decode log line: %v\n%s", err, lines[len(lines)-1])
	}
	return l
}

func TestLoggerMiddleware_BasicFields(t *testing.T) {
	buf, lg := captureLogger(t)
	mw := LoggerMiddleware(lg, staticRoute("/v1/judicial/cases"))
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", nil)
	h.ServeHTTP(rec, req)

	l := decodeLast(t, buf)
	if l.Method != "POST" {
		t.Errorf("method = %q", l.Method)
	}
	if l.Route != "/v1/judicial/cases" {
		t.Errorf("route = %q", l.Route)
	}
	if l.Path != "/v1/judicial/cases" {
		t.Errorf("path = %q", l.Path)
	}
	if l.Status != http.StatusOK {
		t.Errorf("status = %d", l.Status)
	}
	if l.Message != "http_request" {
		t.Errorf("msg = %q, want http_request", l.Message)
	}
}

func TestLoggerMiddleware_ContextFieldsPropagate(t *testing.T) {
	buf, lg := captureLogger(t)
	mw := LoggerMiddleware(lg, staticRoute("/r"))
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ctx := WithRequestID(httpmw.WithCallerDID(httptest.NewRequest(http.MethodGet, "/r", nil).Context(),
		"did:web:caller"), "rid-123")
	req := httptest.NewRequest(http.MethodGet, "/r", nil).WithContext(ctx)
	h.ServeHTTP(httptest.NewRecorder(), req)

	l := decodeLast(t, buf)
	if l.RequestID != "rid-123" {
		t.Errorf("request_id = %q, want rid-123", l.RequestID)
	}
	if l.CallerDID != "did:web:caller" {
		t.Errorf("caller_did = %q, want did:web:caller", l.CallerDID)
	}
}

func TestLoggerMiddleware_LevelByStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{200, "info"},
		{301, "info"},
		{404, "warn"},
		{503, "error"},
	}
	for _, c := range cases {
		buf, lg := captureLogger(t)
		mw := LoggerMiddleware(lg, staticRoute("/r"))
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/r", nil))
		l := decodeLast(t, buf)
		if l.Level != c.want {
			t.Errorf("status %d: level = %q, want %q", c.status, l.Level, c.want)
		}
	}
}
