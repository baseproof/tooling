/*
FILE PATH: libs/httpmw/reliability/timeout_test.go

DESCRIPTION:

	Pins the per-handler timeout:
	  1. A handler that returns within the deadline passes through.
	  2. A handler that blocks past the deadline gets a 503 and
	     the downstream goroutine is allowed to finish (but its
	     response is not used).
	  3. timeout <= 0 disables the wrapper.
*/
package reliability

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestTimeout_FastHandler_PassesThrough(t *testing.T) {
	h := RequestTimeout(50*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want ok", rec.Body.String())
	}
}

func TestRequestTimeout_SlowHandler_503(t *testing.T) {
	h := RequestTimeout(20*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow upstream — block longer than the cap.
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("never seen"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestRequestTimeout_ZeroDisables(t *testing.T) {
	h := RequestTimeout(0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow handler — would normally trip a 50ms wrap, but
		// timeout is disabled here.
		time.Sleep(80 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (timeout disabled)", rec.Code)
	}
}

func TestDefaultRequestTimeout_Stable(t *testing.T) {
	if DefaultRequestTimeout != 30*time.Second {
		t.Errorf("DefaultRequestTimeout = %v, want 30s", DefaultRequestTimeout)
	}
}
