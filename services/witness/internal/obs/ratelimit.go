/*
FILE PATH: internal/obs/ratelimit.go

A token-bucket rate limiter middleware for the cosign endpoint. The
signer is cheap (RAM-speed) and the witness is a blind notary, so the
limiter is not a correctness control — it is DoS protection that
keeps a single abusive caller from monopolising the process.

Global (process-wide) bucket by design: per-IP limiting behind a
TLS-terminating proxy needs trustworthy client-IP extraction
(X-Forwarded-For parsing + a trusted-proxy allowlist) that is its own
hazard. A global cap protects the signer simply and predictably; an
operator who needs per-tenant fairness puts that at the proxy/gateway.

On rejection the response is 429 + a WireError-shaped JSON body
({"error": ...}) so callers parse one error envelope across SDK,
guard, and limiter rejections.
*/
package obs

import (
	"net/http"

	"golang.org/x/time/rate"
)

// RateLimit wraps next with a shared token-bucket limiter. A nil
// limiter disables limiting (returns next unchanged) — the explicit
// "off" switch for deployments that rate-limit at the gateway.
func RateLimit(limiter *rate.Limiter, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewLimiter returns a token bucket of rps tokens/sec with the given
// burst, or nil when rps <= 0 (limiting disabled).
func NewLimiter(rps float64, burst int) *rate.Limiter {
	if rps <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return rate.NewLimiter(rate.Limit(rps), burst)
}
