/*
FILE PATH: libs/httpmw/observability/request_id_test.go

DESCRIPTION:

	Pins the request-ID middleware contract:
	  1. A fresh request gets a generated 32-char hex ID.
	  2. A valid inbound X-Request-ID header is passed through.
	  3. A malformed inbound header is rejected (CRLF, non-printable,
	     oversize) and a fresh ID is generated.
	  4. The ID is set on the response header BEFORE the wrapped
	     handler runs, so even early-return paths carry it.
	  5. Downstream handlers can read the ID via
	     RequestIDFromContext.
*/
package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestID_GeneratesWhenMissing(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if len(seen) != 32 {
		t.Errorf("generated ID should be 32 hex chars; got %q (len %d)", seen, len(seen))
	}
	if rec.Header().Get(HeaderRequestID) != seen {
		t.Error("response X-Request-ID must mirror the context-attached ID")
	}
}

func TestRequestID_HonorsValidInbound(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := RequestIDFromContext(r.Context()); got != "trace-abc-123" {
			t.Errorf("downstream got %q, want trace-abc-123", got)
		}
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(HeaderRequestID, "trace-abc-123")
	h.ServeHTTP(rec, req)
	if rec.Header().Get(HeaderRequestID) != "trace-abc-123" {
		t.Errorf("response header = %q", rec.Header().Get(HeaderRequestID))
	}
}

func TestRequestID_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"\r\nX-Injected: oops",  // CRLF injection
		strings.Repeat("a", 65), // oversize
		"with space",            // space is < 0x21
		"non\x00ascii",          // null byte
	}
	for _, in := range cases {
		var seen string
		h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = RequestIDFromContext(r.Context())
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if in != "" {
			req.Header.Set(HeaderRequestID, in)
		}
		h.ServeHTTP(rec, req)
		if seen == in && in != "" {
			t.Errorf("malformed input %q was passed through", in)
		}
		if len(seen) != 32 {
			t.Errorf("malformed input %q: regenerated ID len = %d, want 32", in, len(seen))
		}
	}
}

func TestRequestID_HeaderSetBeforeHandler(t *testing.T) {
	// If the wrapped handler short-circuits with 401, the response
	// header MUST still carry the request ID.
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no auth", http.StatusUnauthorized)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get(HeaderRequestID); len(got) != 32 {
		t.Errorf("request ID missing from 401 response; got %q", got)
	}
}

func TestValidRequestID_TableDriven(t *testing.T) {
	good := []string{"trace-abc", "GET-12345", "x", strings.Repeat("a", 64)}
	bad := []string{"", "trace abc", "trace\nabc", strings.Repeat("a", 65), "tab\there"}
	for _, s := range good {
		if !validRequestID(s) {
			t.Errorf("valid input rejected: %q", s)
		}
	}
	for _, s := range bad {
		if validRequestID(s) {
			t.Errorf("invalid input accepted: %q", s)
		}
	}
}
