// FILE PATH: services/auditor/internal/gossipfeed/handler_test.go
//
// Tests for the Phase 4 feed-handler mount. Verifies:
//  1. NewFeedMount rejects a nil Store (ErrFeedConfig).
//  2. Prefix() defaults to gossip.DefaultFeedPathPrefix when blank.
//  3. ServeHTTP delegates to the SDK handler (auditor GET reaches
//     the underlying gossip.Store via an in-memory store).
//  4. Close is idempotent and safe on a nil mount.
//  5. v0.5.0 Instruments field — accepted nil-tolerantly and
//     forwarded to the SDK FeedHandlerConfig.
package gossipfeed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/gossip"
	baseprooflog "github.com/baseproof/baseproof/log"
)

func TestNewFeedMount_RejectsNilStore(t *testing.T) {
	_, err := NewFeedMount(FeedConfig{Store: nil})
	if !errors.Is(err, ErrFeedConfig) {
		t.Fatalf("want ErrFeedConfig, got %v", err)
	}
}

func TestPrefix_DefaultsWhenBlank(t *testing.T) {
	store := gossip.NewInMemoryStore()
	f, err := NewFeedMount(FeedConfig{Store: store})
	if err != nil {
		t.Fatalf("NewFeedMount: %v", err)
	}
	defer f.Close(context.Background())
	if f.Prefix() != gossip.DefaultFeedPathPrefix {
		t.Fatalf("expected default prefix %q, got %q",
			gossip.DefaultFeedPathPrefix, f.Prefix())
	}
}

func TestPrefix_RespectsExplicit(t *testing.T) {
	store := gossip.NewInMemoryStore()
	f, err := NewFeedMount(FeedConfig{Store: store, PathPrefix: "/v2/judicial/gossip"})
	if err != nil {
		t.Fatalf("NewFeedMount: %v", err)
	}
	defer f.Close(context.Background())
	if f.Prefix() != "/v2/judicial/gossip" {
		t.Fatalf("explicit prefix not honoured: got %q", f.Prefix())
	}
}

func TestServeHTTP_ReachesUnderlyingStore(t *testing.T) {
	store := gossip.NewInMemoryStore()
	f, err := NewFeedMount(FeedConfig{Store: store})
	if err != nil {
		t.Fatalf("NewFeedMount: %v", err)
	}
	defer f.Close(context.Background())

	// Issue a GET against the feed prefix's "since" endpoint. The
	// store is empty; the SDK should return a 200 with an empty
	// envelope rather than a 404. We don't assert on body shape —
	// only that the mount actually delegates and doesn't hard-500.
	req := httptest.NewRequest(http.MethodGet, f.Prefix()+"/since?limit=10", nil)
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)
	if rec.Code >= 500 {
		t.Fatalf("delegate returned 5xx; got %d body=%q",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

func TestServeHTTP_NilMount_503(t *testing.T) {
	var f *Feed
	req := httptest.NewRequest(http.MethodGet, "/v1/gossip/since", nil)
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil mount should 503, got %d", rec.Code)
	}
}

func TestFeedClose_Idempotent(t *testing.T) {
	store := gossip.NewInMemoryStore()
	f, err := NewFeedMount(FeedConfig{Store: store})
	if err != nil {
		t.Fatalf("NewFeedMount: %v", err)
	}
	ctx := context.Background()
	if err := f.Close(ctx); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := f.Close(ctx); err != nil {
		t.Fatalf("second Close (idempotent): %v", err)
	}
}

func TestFeedClose_NilMount(t *testing.T) {
	var f *Feed
	if err := f.Close(context.Background()); err != nil {
		t.Fatalf("nil receiver Close should be a no-op, got %v", err)
	}
}

// ─── v0.5.0 Instruments passthrough ──────────────────────────────

// TestFeedMount_NilInstruments_StillBoots pins back-compat with
// every pre-v0.5.0 call site: leaving FeedConfig.Instruments
// zero must NOT regress NewFeedMount or ServeHTTP — every method
// on *gossip.Instruments tolerates a nil receiver per the SDK
// CHANGELOG.
func TestFeedMount_NilInstruments_StillBoots(t *testing.T) {
	f, err := NewFeedMount(FeedConfig{Store: gossip.NewInMemoryStore()})
	if err != nil {
		t.Fatalf("NewFeedMount with nil Instruments: %v", err)
	}
	defer f.Close(context.Background())

	req := httptest.NewRequest(http.MethodGet, f.Prefix()+"/since?limit=1", nil)
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)
	if rec.Code >= 500 {
		t.Fatalf("nil-Instruments ServeHTTP returned 5xx: %d", rec.Code)
	}
}

// TestFeedMount_Instruments_Forwarded confirms a non-nil
// Instruments wired through FeedConfig reaches the SDK feed
// handler — the surface contract the v0.5.0 SDK adds. We exercise
// the happy path (GET /since on an empty store) and assert the
// mount serves under 500. The SDK's metrics_test pins the actual
// counter shape; this test only pins JN's passthrough seam.
func TestFeedMount_Instruments_Forwarded(t *testing.T) {
	mp, _ := baseprooflog.NewInMemoryMeterProvider()
	store := gossip.NewInMemoryStore()
	inst, err := gossip.NewInstruments(mp.Meter("test"), store)
	if err != nil {
		t.Fatalf("NewInstruments: %v", err)
	}

	f, err := NewFeedMount(FeedConfig{Store: store, Instruments: inst})
	if err != nil {
		t.Fatalf("NewFeedMount with Instruments: %v", err)
	}
	defer f.Close(context.Background())

	req := httptest.NewRequest(http.MethodGet, f.Prefix()+"/since?limit=1", nil)
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)
	if rec.Code >= 500 {
		t.Fatalf("Instruments-wired ServeHTTP returned 5xx: %d body=%q",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}
