/*
FILE PATH: internal/retryhttp/retryhttp.go

retryhttp — a resilient HTTP client for the foundational requirement that the
SAME binary runs natively, in Docker, and in Kubernetes without code changes.

WHY THIS EXISTS

	Across those targets, dependency readiness and DNS propagation are never
	guaranteed at startup: a freshly-scheduled pod may dial a Service whose
	endpoints aren't registered yet (DNS "no such host"), or a dependency that
	is still binding its port (connection refused). The baseproof SDK's transport
	deliberately leaves this to the caller:

	    "Transport-level errors are not retried — the caller owns transport-error
	     policy (network DNS, connection refused)."  (baseproof/log/transport.go)

	So we own it here: a RoundTripper that retries TRANSIENT TRANSPORT errors
	(DNS, connection-refused, reset, EOF, timeout) with bounded exponential
	backoff, composed OVER the SDK's 503/Retry-After client (which keeps the
	pooled transport + Retry-After handling). One client, resilient everywhere.

SAFETY

	A transport error means no response was received — the request did not
	complete — so retrying is safe even for POSTs. The ledger's submission path
	is additionally idempotent (dedup by canonical hash), so a retried submit
	never double-appends. Body replay uses http.Request.GetBody, which the
	stdlib sets automatically for bytes.Reader / strings.Reader bodies.
*/
package retryhttp

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
)

// Tunables. Bounded so a genuinely-down dependency fails in reasonable time
// rather than hanging forever — the Client timeout caps total wall-clock.
const (
	defaultMaxRetries = 6
	baseBackoff       = 250 * time.Millisecond
	maxBackoff        = 8 * time.Second
)

// Client returns an *http.Client resilient to transient transport failures,
// composed over the SDK's 503/Retry-After client. timeout caps total wall-clock
// across all retries (<=0 disables the cap, leaving ctx as the only bound).
//
// tlsCfg controls the TLS posture of every retry attempt: pass nil for stdlib
// defaults (server-verify only — the legacy posture); pass non-nil (typically
// from clienttls.Flags.TLSConfig) for mTLS — the SAME *tls.Config flows to
// every retried attempt, so a transient connection-refused on a freshly
// scheduled mTLS peer is retried with the same client cert. Composing TLS
// material onto retryhttp (rather than choosing between retry OR TLS) is
// load-bearing: a startup race against an mTLS-required peer MUST retry, and
// it MUST present its client cert on every retry.
func Client(timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	// Inner: the SDK's transport (pooled DefaultTransport + RetryAfter
	// middleware), with tlsCfg threaded through. Pass 0 so the inner
	// doesn't impose its own timeout; the outer client caps.
	inner := sdklog.DefaultClient(0, tlsCfg).Transport
	return &http.Client{
		Transport: &transport{inner: inner, max: defaultMaxRetries},
		Timeout:   timeout,
	}
}

type transport struct {
	inner http.RoundTripper
	max   int
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	backoff := baseBackoff
	var lastErr error
	for attempt := 0; attempt <= t.max; attempt++ {
		r := req
		if attempt > 0 {
			// Replay the body on retries; if it can't be replayed, give up
			// with the last transport error rather than send a bodiless request.
			if req.Body != nil && req.Body != http.NoBody {
				if req.GetBody == nil {
					return nil, lastErr
				}
				body, err := req.GetBody()
				if err != nil {
					return nil, lastErr
				}
				r = req.Clone(req.Context())
				r.Body = body
			}
		}
		resp, err := t.inner.RoundTrip(r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt == t.max || !transient(err) {
			return nil, err
		}
		select {
		case <-time.After(backoff):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return nil, lastErr
}

// transient reports whether err is a transport failure worth retrying — the
// dependency-not-ready / DNS-not-propagated class that distinguishes Docker/K8s/
// native startup. A transport error implies no response was received, so these
// are safe to retry (and the ledger submit path is idempotent regardless).
func transient(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true // includes NXDOMAIN during DNS propagation
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) {
		return true
	}
	// url.Error wraps opaque transport errors; match the well-known messages
	// as a last resort so startup races on any platform self-heal.
	msg := err.Error()
	for _, s := range []string{"no such host", "connection refused", "connection reset", "EOF", "i/o timeout", "server misbehaving"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
