package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestBuildDIDRegistry_RegistersKeyAndWeb pins the gossip-originator contract:
// the auditor's DID registry MUST carry BOTH did:key and did:web verifiers.
// did:key is the transparency-log STH originator path (an empty registry rejected
// every event with "DID method has no registered verifier: key" and left
// peer_gossip at 0). did:web is required for PQ coverage — the SDK dispatches the
// post-quantum verifiers (ML-DSA-65/87, SLH-DSA-128s) through the did:web verifier
// too, so a PQ-signed did:web event would otherwise bounce off with
// "method not registered: web".
func TestBuildDIDRegistry_RegistersKeyAndWeb(t *testing.T) {
	reg, err := buildDIDRegistry(&http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("buildDIDRegistry: %v", err)
	}
	methods := reg.RegisteredMethods()
	want := map[string]bool{"key": false, "web": false}
	for _, m := range methods {
		if _, ok := want[m]; ok {
			want[m] = true
		}
	}
	for m, seen := range want {
		if !seen {
			t.Errorf("registry missing required method %q (registered: %v)", m, methods)
		}
	}
}

func TestMux_HealthAndReadiness(t *testing.T) {
	var ready atomic.Bool
	h := newMux(&ready, nil)

	// /healthz is always 200 "ok" (liveness — process is up).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("/healthz = %d %q, want 200 ok", rec.Code, rec.Body.String())
	}

	// /readyz is 503 until ready flips true (readiness — gated on deps).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz (not ready) = %d, want 503", rec.Code)
	}
	ready.Store(true)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz (ready) = %d, want 200", rec.Code)
	}

	// /version reports the build version.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), version) {
		t.Fatalf("/version = %d %q, want 200 containing %q", rec.Code, rec.Body.String(), version)
	}
}

// TestRun_GracefulShutdown proves run() boots, serves, and drains cleanly when
// its context is cancelled (the SIGTERM path), returning nil.
func TestRun_GracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := config{
		listenAddr:   "127.0.0.1:0", // ephemeral port; this test only drives the lifecycle
		readTimeout:  time.Second,
		writeTimeout: time.Second,
		idleTimeout:  time.Second,
		shutdownWait: 2 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	time.Sleep(50 * time.Millisecond) // let the listener come up
	cancel()                          // simulate SIGINT/SIGTERM

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not shut down within 5s")
	}
}

// ─────────────────────────────────────────────────────────────────
// Ladder 5 P10 (#21) — joinGoroutine helper
// ─────────────────────────────────────────────────────────────────

// TestJoinGoroutine_NilDoneChannelIsNoop pins the health-only-mode
// path: with the pipeline disabled, neither pullerDone nor
// schedulerDone is allocated, so the shutdown branch's joinGoroutine
// call receives nil. It MUST return immediately and emit no log
// lines. This guards the health-only mode against a regression where
// joinGoroutine would block on a nil channel (the classic Go pitfall
// of `select { case <-nilChan }` blocking forever).
func TestJoinGoroutine_NilDoneChannelIsNoop(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	shutCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Must return ~immediately (well under the timeout).
	start := time.Now()
	joinGoroutine(shutCtx, nil, "puller", logger)
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Errorf("nil done channel must return immediately; took %v", took)
	}
	if buf.Len() != 0 {
		t.Errorf("nil done channel must emit no log; got %q", buf.String())
	}
}

// TestJoinGoroutine_DoneBeforeDeadline pins the clean-shutdown path:
// the background goroutine exits (closes its done channel) BEFORE the
// shutCtx deadline. joinGoroutine MUST return cleanly and emit the
// "background goroutine drained" log line, NOT the deadline-exceeded
// warn.
func TestJoinGoroutine_DoneBeforeDeadline(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan struct{})
	close(done) // simulate goroutine already finished

	joinGoroutine(shutCtx, done, "puller", logger)
	out := buf.String()
	if !strings.Contains(out, "background goroutine drained") {
		t.Errorf("expected clean-drain log; got: %q", out)
	}
	if !strings.Contains(out, `name=puller`) {
		t.Errorf("log must include the goroutine name; got: %q", out)
	}
	if strings.Contains(out, "deadline exceeded") {
		t.Errorf("clean shutdown must NOT log deadline-exceeded; got: %q", out)
	}
}

// TestJoinGoroutine_DeadlineExceedsDone pins the rough-shutdown path:
// the goroutine is stuck (its done channel never closes within the
// shutCtx budget). joinGoroutine MUST return when shutCtx expires
// and surface a warn naming which goroutine timed out — so the
// operator's log distinguishes "clean shutdown" from "process exited
// while a goroutine was still mid-iteration".
//
// The deadline budget here is small (50ms) so the test stays fast.
func TestJoinGoroutine_DeadlineExceedsDone(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	shutCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{}) // never closed
	start := time.Now()
	joinGoroutine(shutCtx, done, "scheduler", logger)
	took := time.Since(start)

	if took < 40*time.Millisecond {
		t.Errorf("must wait ~50ms before timing out; got %v", took)
	}
	if took > 500*time.Millisecond {
		t.Errorf("must NOT wait significantly past the deadline; got %v", took)
	}
	out := buf.String()
	if !strings.Contains(out, "shutdown deadline exceeded") {
		t.Errorf("stuck goroutine must log deadline-exceeded; got: %q", out)
	}
	if !strings.Contains(out, `name=scheduler`) {
		t.Errorf("warn must name the goroutine; got: %q", out)
	}
	if strings.Contains(out, "background goroutine drained") {
		t.Errorf("stuck shutdown must NOT log clean drain; got: %q", out)
	}
}
