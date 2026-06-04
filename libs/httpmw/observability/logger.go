/*
FILE PATH: libs/httpmw/observability/logger.go

DESCRIPTION:

	Structured per-request logging middleware. Backed by zerolog
	(small, allocator-friendly, JSON-by-default). Every request
	emits one log line at end-of-handler with the canonical fields:

	  ts          ISO 8601
	  level       info | warn | error
	  request_id  correlation ID from RequestID middleware
	  caller_did  httpmw.CallerDIDFromContext
	  method      HTTP verb
	  route       static route label (closure-supplied, same as metrics)
	  path        the actual request path (per-request, NOT a metric label)
	  status      raw HTTP status code
	  latency_ms  end-to-end handler duration in ms

	The logger reads the request_id + caller_did from context — both
	populated by upstream middleware (RequestID + composer Auth).
	Empty values are omitted.

	Per-caller fields go HERE (not in metrics labels) because
	structured logs scale to high cardinality where Prometheus
	labels do not.
*/
package observability

import (
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"

	"github.com/baseproof/tooling/libs/httpmw"
)

// NewLogger returns a default zerolog.Logger writing to stderr in
// JSON. Production deploys can swap stderr for a custom writer
// (file, network) by constructing the zerolog.Logger directly and
// passing it to NewLoggerMiddleware.
func NewLogger() zerolog.Logger {
	return zerolog.New(os.Stderr).With().Timestamp().Logger()
}

// LoggerMiddleware emits one structured log line per request,
// reading the route label from routeFn (same closure pattern as
// the metrics wrapper).
func LoggerMiddleware(logger zerolog.Logger, routeFn func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := newStatusRecorder(w)
			start := time.Now()
			next.ServeHTTP(rec, r)
			elapsed := time.Since(start)

			ev := chooseLevel(logger, rec.status)
			ev = ev.
				Str("method", r.Method).
				Str("route", routeFn()).
				Str("path", r.URL.Path).
				Int("status", rec.status).
				Int64("latency_ms", elapsed.Milliseconds())

			if id := RequestIDFromContext(r.Context()); id != "" {
				ev = ev.Str("request_id", id)
			}
			if did := httpmw.CallerDIDFromContext(r.Context()); did != "" {
				ev = ev.Str("caller_did", did)
			}
			ev.Msg("http_request")
		})
	}
}

// chooseLevel maps the response status to a log level: 5xx → error,
// 4xx → warn, everything else → info. Aligns log severity with what
// an ledger would expect to act on.
func chooseLevel(logger zerolog.Logger, status int) *zerolog.Event {
	switch {
	case status >= 500:
		return logger.Error()
	case status >= 400:
		return logger.Warn()
	}
	return logger.Info()
}
