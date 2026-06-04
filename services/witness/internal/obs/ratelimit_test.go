package obs

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestNewLimiter_DisabledWhenZeroOrNegative(t *testing.T) {
	if NewLimiter(0, 5) != nil {
		t.Error("NewLimiter(0,...) should be nil (disabled)")
	}
	if NewLimiter(-1, 5) != nil {
		t.Error("NewLimiter(<0,...) should be nil (disabled)")
	}
	if NewLimiter(10, 0) == nil {
		t.Error("NewLimiter(10,0) should return a limiter (burst floored to 1)")
	}
}

func TestRateLimit_NilPassesThrough(t *testing.T) {
	h := RateLimit(nil, okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/cosign", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("nil limiter: got %d, want 200 (pass-through)", rec.Code)
	}
}

func TestRateLimit_Throttles(t *testing.T) {
	// 1 rps, burst 1: first request consumes the only token, the
	// immediate second is refused.
	h := RateLimit(NewLimiter(1, 1), okHandler())

	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/v1/cosign", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/v1/cosign", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Errorf("second request: got %d, want 429", second.Code)
	}
	if ct := second.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("429 Content-Type = %q, want application/json", ct)
	}
}
