/*
FILE PATH: libs/httpmw/reliability/timeout.go

DESCRIPTION:

	Per-handler request timeout. Wraps next with http.TimeoutHandler
	so a slow upstream / runaway handler cannot pin a goroutine + a
	response writer indefinitely. Returns 503 Service Unavailable
	(with the message "request timeout") when the handler doesn't
	finish in time.

	Default 30s matches the ledger's submit deadline so a slow
	ledger surfaces as a clean 503 to the caller rather than as
	an indefinitely-hung connection.

	The wrapper is stacked at the composer level (after auth) so
	every route gets the timeout uniformly. Handlers that need a
	longer cap (bulk paths) opt in by registering a per-route wrap.
*/
package reliability

import (
	"net/http"
	"time"
)

// DefaultRequestTimeout is the per-request handler-execution cap.
// Matches the SDK's default ledger-submit deadline so JN-side
// timeouts surface before the ledger's own.
const DefaultRequestTimeout = 30 * time.Second

// RequestTimeout wraps next with http.TimeoutHandler. timeout
// <= 0 disables the wrapper (use only in tests + bulk paths).
//
// The 503 body is intentionally short — production deploys MUST
// NOT leak handler-internal context into a timeout response.
func RequestTimeout(timeout time.Duration, next http.Handler) http.Handler {
	if timeout <= 0 {
		return next
	}
	return http.TimeoutHandler(next, timeout, "request timeout")
}
