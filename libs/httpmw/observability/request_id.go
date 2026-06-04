/*
FILE PATH: libs/httpmw/observability/request_id.go

DESCRIPTION:

	Request-ID middleware. Honours an inbound `X-Request-ID` header
	when present and well-formed; otherwise generates a fresh
	16-byte hex ID. The ID lives in request context for downstream
	handlers + log + metric labels, and is echoed in the response
	header for upstream callers (gateway / browser dev tools / etc.)
	to correlate.

	Stable correlation ID is the load-bearing primitive for
	debugging tail-latency outliers at 1000 TPS — without it you
	cannot tie a slow log line to the specific request, the metric
	bucket it landed in, or the trace span.
*/
package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// HeaderRequestID is the canonical header name. Both inbound
// (read) and outbound (set on response). 50-char cap matches
// the X-Request-Id de-facto standard (Heroku, Cloudflare, etc.).
const (
	HeaderRequestID    = "X-Request-ID"
	maxRequestIDLength = 64
)

type requestIDKey struct{}

// WithRequestID attaches a request ID to ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the request ID, or "" if none was
// attached.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// RequestID is middleware that ensures every request has a
// correlation ID. Reads X-Request-ID inbound; generates a fresh
// 16-byte hex ID when missing or malformed. Writes the final ID
// to the response's X-Request-ID header BEFORE the wrapped
// handler runs, so even early-return paths (auth 401, rate-limit
// 429) carry the correlation ID.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if !validRequestID(id) {
			id = generateRequestID()
		}
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// validRequestID accepts ASCII printable characters up to
// maxRequestIDLength. Anything else is rejected and the middleware
// generates a fresh ID — defends against header-injection attacks
// (CR / LF) and oversized labels that would blow up Prometheus
// cardinality.
func validRequestID(s string) bool {
	if s == "" || len(s) > maxRequestIDLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7E {
			return false
		}
	}
	return true
}

// generateRequestID produces a 32-char hex ID from 16 random bytes.
// rand.Read on a healthy system never errors; the fallback to a
// fixed sentinel keeps the middleware total in case it does.
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "req_unavailable"
	}
	return hex.EncodeToString(b)
}
