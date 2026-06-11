/*
FILE PATH: internal/retryhttp/retryhttp_test.go

The retry rule, pinned at its own altitude. retryhttp owns transport-error
policy for every consumer (sequencer, shipper, WAL committer, the cmd tools) —
the SDK deliberately does not retry transport errors — yet nothing anywhere
exercised it. These tests pin:

  - the TRANSIENT taxonomy (DNS, timeout, refused/reset/EOF, the string
    fallbacks) and its NEGATIVES (a non-transient error must not retry;
    context cancellation is never transient);
  - the RoundTrip loop: recovery after transient failures, single attempt on a
    deterministic error, bounded exhaustion, body replay on POST retries, the
    give-up path for non-replayable bodies, and prompt context cancellation
    during backoff;
  - the composed Client self-healing a real startup race (connection refused →
    dependency comes up → success), the scenario the package exists for.

In-package: the transport struct is unexported by design (Client is the only
production door); testing the loop directly keeps the exhaustion cases fast
(small max) instead of walking the production 6-retry backoff ladder.
*/
package retryhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ── transient taxonomy ───────────────────────────────────────────────────

func TestTransient_Taxonomy(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"dns", &net.DNSError{Err: "no such host", Name: "ledger", IsNotFound: true}, true},
		{"timeout", &net.OpError{Op: "dial", Err: &timeoutErr{}}, true},
		{"refused", fmt.Errorf("dial: %w", syscall.ECONNREFUSED), true},
		{"reset", fmt.Errorf("read: %w", syscall.ECONNRESET), true},
		{"eof", fmt.Errorf("transport: %w", io.EOF), true},
		{"string-no-such-host", errors.New("Get \"http://x\": lookup x: no such host"), true},
		{"string-io-timeout", errors.New("read tcp 10.0.0.1: i/o timeout"), true},
		{"deterministic", errors.New("x509: certificate signed by unknown authority"), false},
		{"context-canceled", context.Canceled, false},
		{"context-deadline", context.DeadlineExceeded, true}, // pinned to the stdlib's net.Error classification below
	}
	for _, c := range cases {
		if c.name == "context-deadline" {
			// context.DeadlineExceeded implements net.Error with Timeout()==true
			// in the stdlib — pin whatever the stdlib does so a change there is
			// caught here rather than silently altering retry behavior.
			var netErr net.Error
			want := errors.As(c.err, &netErr) && netErr.Timeout()
			if got := transient(c.err); got != want {
				t.Errorf("transient(context.DeadlineExceeded) = %v, stdlib net.Error classification = %v", got, want)
			}
			continue
		}
		if got := transient(c.err); got != c.want {
			t.Errorf("transient(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// ── the RoundTrip loop (fake inner transport) ────────────────────────────

// scriptedInner fails with err for the first failures attempts, then succeeds,
// recording every body it saw (the replay contract).
type scriptedInner struct {
	failures int
	err      error
	attempts int
	bodies   []string
}

func (s *scriptedInner) RoundTrip(req *http.Request) (*http.Response, error) {
	s.attempts++
	if req.Body != nil && req.Body != http.NoBody {
		b, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		s.bodies = append(s.bodies, string(b))
	}
	if s.attempts <= s.failures {
		return nil, s.err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func post(t *testing.T, body string) *http.Request {
	t.Helper()
	// http.NewRequest sets GetBody automatically for *bytes.Reader.
	req, err := http.NewRequest(http.MethodPost, "http://dep.internal/v1/entries", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRoundTrip_RecoversAfterTransientFailures_ReplayingTheBody(t *testing.T) {
	inner := &scriptedInner{failures: 2, err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED)}
	tr := &transport{inner: inner, max: 3}

	resp, err := tr.RoundTrip(post(t, "payload-bytes"))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("RoundTrip after transient failures: err=%v", err)
	}
	if inner.attempts != 3 {
		t.Errorf("attempts = %d, want 3 (2 failures + success)", inner.attempts)
	}
	for i, b := range inner.bodies {
		if b != "payload-bytes" {
			t.Errorf("attempt %d saw body %q — replay broken (a retried POST must carry the full body)", i, b)
		}
	}
}

func TestRoundTrip_DeterministicErrorIsNotRetried(t *testing.T) {
	inner := &scriptedInner{failures: 99, err: errors.New("x509: certificate signed by unknown authority")}
	tr := &transport{inner: inner, max: 5}

	if _, err := tr.RoundTrip(post(t, "x")); err == nil {
		t.Fatal("deterministic failure returned nil error")
	}
	if inner.attempts != 1 {
		t.Errorf("attempts = %d, want 1 — a deterministic error must fail fast, not retry", inner.attempts)
	}
}

func TestRoundTrip_BoundedExhaustion(t *testing.T) {
	inner := &scriptedInner{failures: 99, err: fmt.Errorf("read: %w", syscall.ECONNRESET)}
	tr := &transport{inner: inner, max: 2}

	_, err := tr.RoundTrip(post(t, "x"))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("exhaustion must surface the transport error, got %v", err)
	}
	if inner.attempts != 3 {
		t.Errorf("attempts = %d, want 3 (initial + max=2 retries) — the loop must be bounded", inner.attempts)
	}
}

func TestRoundTrip_NonReplayableBodyGivesUpWithLastError(t *testing.T) {
	inner := &scriptedInner{failures: 99, err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED)}
	tr := &transport{inner: inner, max: 5}

	// A streaming body with no GetBody cannot be replayed: after the first
	// transient failure the loop must give up with that error rather than
	// retry a bodiless request.
	req, err := http.NewRequest(http.MethodPost, "http://dep.internal/v1/entries", io.NopCloser(strings.NewReader("stream")))
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = nil

	_, rtErr := tr.RoundTrip(req)
	if !errors.Is(rtErr, syscall.ECONNREFUSED) {
		t.Fatalf("want the last transport error, got %v", rtErr)
	}
	if inner.attempts != 1 {
		t.Errorf("attempts = %d, want 1 — never retry a request whose body cannot be replayed", inner.attempts)
	}
}

func TestRoundTrip_ContextCancellationCutsBackoffShort(t *testing.T) {
	inner := &scriptedInner{failures: 99, err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED)}
	tr := &transport{inner: inner, max: 5}

	ctx, cancel := context.WithCancel(context.Background())
	req := post(t, "x").WithContext(ctx)
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()

	start := time.Now()
	_, err := tr.RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled out of the backoff wait, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cancellation took %s — the backoff select must honor ctx promptly", elapsed)
	}
}

// ── the composed Client over a real socket (the startup race) ────────────

func TestClient_SelfHealsAcrossDependencyStartup(t *testing.T) {
	// Reserve a port, then free it: the first dial(s) get connection-refused —
	// exactly a pod racing a dependency that has not bound its port yet.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	srvUp := make(chan struct{})
	go func() {
		time.Sleep(150 * time.Millisecond) // after the client's first attempt
		l2, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			close(srvUp)
			return
		}
		close(srvUp)
		_ = http.Serve(l2, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}()

	c := Client(15*time.Second, nil)
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		<-srvUp
		t.Fatalf("Client did not self-heal across dependency startup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
