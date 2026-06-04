/*
FILE PATH: libs/httpmw/observability/readyz_test.go

DESCRIPTION:

	Pins the readyz handler:
	  1. Empty Checks → 200 unconditionally.
	  2. All checks pass → 200 with each check's name → "ok".
	  3. Any check fails → 503 with failed check's error in body.
	  4. CheckHTTPGet 200 → ok; non-2xx or unreachable → error.
	  5. Per-check timeout respected (handler doesn't hang on a
	     slow upstream past the configured budget).
*/
package observability

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okCheck(name string) ReadyCheck {
	return ReadyCheck{Name: name, Run: func(_ context.Context) error { return nil }}
}

func errCheck(name string, msg string) ReadyCheck {
	return ReadyCheck{Name: name, Run: func(_ context.Context) error {
		return errors.New(msg)
	}}
}

func TestReadyzHandler_NoChecks_200(t *testing.T) {
	h := ReadyzHandler(ReadyzConfig{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no checks)", rec.Code)
	}
}

func TestReadyzHandler_AllPass_200(t *testing.T) {
	h := ReadyzHandler(ReadyzConfig{
		Checks: []ReadyCheck{okCheck("ledger"), okCheck("artifact_store")},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["ledger"] != "ok" || body["artifact_store"] != "ok" {
		t.Errorf("body = %+v, want all 'ok'", body)
	}
}

func TestReadyzHandler_OneFails_503(t *testing.T) {
	h := ReadyzHandler(ReadyzConfig{
		Checks: []ReadyCheck{
			okCheck("ledger"),
			errCheck("artifact_store", "connection refused"),
		},
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["ledger"] != "ok" {
		t.Errorf("ledger = %q, want ok", body["ledger"])
	}
	if body["artifact_store"] != "connection refused" {
		t.Errorf("artifact_store = %q, want failure detail", body["artifact_store"])
	}
}

// ─────────────────────────────────────────────────────────────────────
// CheckHTTPGet
// ─────────────────────────────────────────────────────────────────────

// testClient returns a *http.Client suitable for the readyz tests — a
// short timeout so the unreachable-host test fails fast. Real binaries
// thread the hoisted outbound client (libs/clienttls.BuildFromEnv).
func testClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second}
}

func TestCheckHTTPGet_2xx_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	check := CheckHTTPGet("test", srv.URL, testClient())
	if err := check.Run(context.Background()); err != nil {
		t.Errorf("CheckHTTPGet against 200: %v", err)
	}
}

func TestCheckHTTPGet_5xx_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	check := CheckHTTPGet("test", srv.URL, testClient())
	if err := check.Run(context.Background()); err == nil {
		t.Error("CheckHTTPGet against 503 should error")
	}
}

func TestCheckHTTPGet_Unreachable_Errors(t *testing.T) {
	check := CheckHTTPGet("test", "http://127.0.0.1:1", testClient()) // nothing listens here
	if err := check.Run(context.Background()); err == nil {
		t.Error("CheckHTTPGet against unreachable host should error")
	}
}

// TestCheckHTTPGet_PanicsOnNilClient pins the v1.27.x contract: a nil
// client is a programmer error, surfaced as a panic at construction
// time. Readyz checks are registered once at boot before serve, so
// the panic appears in tests / CI / pre-flight rather than at probe
// time.
func TestCheckHTTPGet_PanicsOnNilClient(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil *http.Client")
		}
	}()
	_ = CheckHTTPGet("test", "http://example.com", nil)
}

// ─────────────────────────────────────────────────────────────────────
// Timeout respected
// ─────────────────────────────────────────────────────────────────────

func TestReadyzHandler_TimeoutCapsSlowCheck(t *testing.T) {
	// Slow check sleeps longer than the configured timeout. The
	// readyz handler MUST cap the wall-clock budget — if it
	// hangs, this test exceeds its own deadline.
	slow := ReadyCheck{Name: "slow", Run: func(ctx context.Context) error {
		select {
		case <-time.After(500 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	h := ReadyzHandler(ReadyzConfig{
		Checks:  []ReadyCheck{slow},
		Timeout: 50 * time.Millisecond,
	})
	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("readyz took %v, want < 200ms (timeout cap broken)", elapsed)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (slow check should fail on ctx cancel)", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	_ = body // body details vary; status is the load-bearing signal
}
