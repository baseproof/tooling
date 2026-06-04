/*
FILE PATH: libs/httpmw/reliability/ratelimit_test.go

DESCRIPTION:

	Pins the rate-limit middleware:
	  1. Global limiter rejects past burst capacity.
	  2. Per-caller limiter buckets requests by caller DID; one
	     caller's burst doesn't drain another's quota.
	  3. Empty caller DID shares a fallback "anon" bucket.
	  4. rps <= 0 / burst <= 0 disables the wrapper.
*/
package reliability

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/time/rate"

	"github.com/baseproof/tooling/libs/httpmw"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func hit(h http.Handler, callerDID string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if callerDID != "" {
		req = req.WithContext(httpmw.WithCallerDID(req.Context(), callerDID))
	}
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRateLimitGlobal_RejectsPastBurst(t *testing.T) {
	// 0 RPS sustained, burst 2: only the first 2 requests pass; the
	// 3rd gets 429. Sustained is 0 so the bucket never refills.
	h := RateLimitGlobal(rate.Limit(0.0001), 2, okHandler())
	if hit(h, "") != http.StatusOK {
		t.Error("first request should pass")
	}
	if hit(h, "") != http.StatusOK {
		t.Error("second request should pass (within burst)")
	}
	if got := hit(h, ""); got != http.StatusTooManyRequests {
		t.Errorf("third request: got %d, want 429", got)
	}
}

func TestRateLimitGlobal_DisabledWhenZero(t *testing.T) {
	h := RateLimitGlobal(0, 0, okHandler())
	for i := 0; i < 10; i++ {
		if hit(h, "") != http.StatusOK {
			t.Errorf("disabled limiter rejected request %d", i)
		}
	}
}

func TestRateLimitByCaller_PerDIDIsolation(t *testing.T) {
	// 0 RPS / burst 1 per caller — each caller gets exactly 1
	// request before being rate-limited.
	h := RateLimitByCaller(rate.Limit(0.0001), 1, okHandler())

	// Caller A's first call passes; second is 429.
	if hit(h, "did:web:caller-A") != http.StatusOK {
		t.Error("caller-A first call should pass")
	}
	if got := hit(h, "did:web:caller-A"); got != http.StatusTooManyRequests {
		t.Errorf("caller-A second call: got %d, want 429", got)
	}

	// Caller B has its own bucket — first call passes.
	if hit(h, "did:web:caller-B") != http.StatusOK {
		t.Error("caller-B first call should pass (different bucket)")
	}
}

func TestRateLimitByCaller_AnonSharesBucket(t *testing.T) {
	h := RateLimitByCaller(rate.Limit(0.0001), 1, okHandler())
	if hit(h, "") != http.StatusOK {
		t.Error("first anon call should pass")
	}
	if got := hit(h, ""); got != http.StatusTooManyRequests {
		t.Errorf("second anon call: got %d, want 429 (shared anon bucket)", got)
	}
}

func TestRateLimitByCaller_DisabledWhenZero(t *testing.T) {
	h := RateLimitByCaller(0, 0, okHandler())
	for i := 0; i < 10; i++ {
		if hit(h, "did:web:x") != http.StatusOK {
			t.Errorf("disabled limiter rejected request %d", i)
		}
	}
}

func TestDefaultRateLimitConfig_StableValues(t *testing.T) {
	d := DefaultRateLimitConfig()
	if d.GlobalRPS != 1000 || d.GlobalBurst != 200 {
		t.Errorf("global defaults drifted: rps=%v burst=%d", d.GlobalRPS, d.GlobalBurst)
	}
	if d.PerCallerRPS != 100 || d.PerCallerBurst != 50 {
		t.Errorf("per-caller defaults drifted: rps=%v burst=%d", d.PerCallerRPS, d.PerCallerBurst)
	}
}
