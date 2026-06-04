/*
FILE PATH: libs/httpmw/reliability/ratelimit.go

DESCRIPTION:

	Token-bucket rate limiter middleware. Backs onto
	golang.org/x/time/rate (the canonical Go token bucket).

	Two surfaces:

	  RateLimitGlobal — one bucket shared across all requests. Used
	    as the composer-level safety net so a misbehaving caller
	    cannot drown the binary regardless of which route they hit.

	  RateLimitByCaller — one bucket per caller DID, sourced from
	    httpmw.CallerDIDFromContext. Anonymous (empty caller-DID)
	    traffic shares one fallback bucket so it cannot starve
	    authenticated traffic. Used per-route to enforce per-caller
	    fairness.

	Refused requests get 429 Too Many Requests.

	Defaults are conservative: 1000 RPS sustained / 200 burst at
	the global level; 100 RPS / 50 burst per caller. Both override
	via config.
*/
package reliability

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"

	"github.com/baseproof/tooling/libs/httpmw"
)

// RateLimitConfig configures both the global + per-caller limiters.
// Zero values fall back to the documented defaults.
type RateLimitConfig struct {
	// GlobalRPS is the sustained per-second rate at the global
	// limiter (0 disables). Default 1000.
	GlobalRPS rate.Limit

	// GlobalBurst is the bucket capacity at the global limiter.
	// Default 200.
	GlobalBurst int

	// PerCallerRPS is the sustained per-second rate at the
	// per-caller limiter (0 disables). Default 100.
	PerCallerRPS rate.Limit

	// PerCallerBurst is the bucket capacity at the per-caller limiter.
	// Default 50.
	PerCallerBurst int
}

// DefaultRateLimitConfig returns the production defaults.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		GlobalRPS:      1000,
		GlobalBurst:    200,
		PerCallerRPS:   100,
		PerCallerBurst: 50,
	}
}

// RateLimitGlobal wraps next with a single shared token bucket.
// Calls beyond the configured rate get 429.
func RateLimitGlobal(rps rate.Limit, burst int, next http.Handler) http.Handler {
	if rps <= 0 || burst <= 0 {
		return next
	}
	limiter := rate.NewLimiter(rps, burst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimitByCaller wraps next with a per-caller token bucket.
// Caller DID is read from httpmw.CallerDIDFromContext; empty
// callers share one anon bucket so anonymous traffic can't starve
// authenticated callers.
func RateLimitByCaller(rps rate.Limit, burst int, next http.Handler) http.Handler {
	if rps <= 0 || burst <= 0 {
		return next
	}
	cb := newCallerBuckets(rps, burst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller := httpmw.CallerDIDFromContext(r.Context())
		if !cb.allow(caller) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// callerBuckets is a goroutine-safe cache of token buckets keyed by
// caller DID. Buckets are lazily allocated on first use; the empty
// caller (unauthenticated) gets a shared "anon" bucket.
type callerBuckets struct {
	rps   rate.Limit
	burst int

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
}

func newCallerBuckets(rps rate.Limit, burst int) *callerBuckets {
	return &callerBuckets{
		rps:     rps,
		burst:   burst,
		buckets: make(map[string]*rate.Limiter),
	}
}

func (c *callerBuckets) allow(caller string) bool {
	if caller == "" {
		caller = "__anon__"
	}
	c.mu.Lock()
	lim, ok := c.buckets[caller]
	if !ok {
		lim = rate.NewLimiter(c.rps, c.burst)
		c.buckets[caller] = lim
	}
	c.mu.Unlock()
	return lim.Allow()
}
