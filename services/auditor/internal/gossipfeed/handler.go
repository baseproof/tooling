// FILE PATH: services/auditor/internal/gossipfeed/handler.go
//
// DESCRIPTION:
//
//	Phase 4 — Mounts the SDK's gossip.FeedHandler at
//	/v1/gossip/* on the judicial-network API surface. This
//	exposes the pull-based gossip feed required by Trust
//	Alignment 11 (CDN-offloaded anti-entropy): independent
//	auditors and peer ledgers fetch findings via HTTP GET with
//	standard ETag / Cache-Control semantics, eliminating fan-out
//	pressure on the JN API hot path.
//
//	The handler is thin — all the wire logic lives in the SDK.
//	JN's only job is to construct the FeedHandler from a Store,
//	configure the prefix, and return an http.Handler the api/
//	composer can mount.
//
// KEY DEPENDENCIES:
//   - baseproof/gossip: FeedHandler, FeedHandlerConfig, Store
package gossipfeed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/baseproof/baseproof/gossip"
)

// FeedConfig wraps gossip.FeedHandlerConfig with JN-friendly
// defaults. PathPrefix is mandatory; the rest is optional.
type FeedConfig struct {
	Store      gossip.Store
	PathPrefix string // defaults to gossip.DefaultFeedPathPrefix
	Logger     *slog.Logger

	// Instruments wires the SDK's OTel panic counter to the
	// feed-handler-side recoverPanic (baseproof v0.5.0+). When
	// non-nil, panics in feed serving increment the shared
	// baseproof_gossip_panic_total counter alongside POST-side
	// panics — production deployments share one *Instruments
	// across feed and push so the dashboard sees one metric for
	// the whole gossip surface (Trust Alignment 14: one
	// telemetry seam). Nil-tolerant: every *Instruments method
	// is a no-op on a nil receiver, so leaving this field zero
	// preserves the v0.4.x behaviour byte-for-byte.
	Instruments *gossip.Instruments
}

// ErrFeedConfig surfaces NewFeedMount validation faults.
var ErrFeedConfig = errors.New("gossipfeed: invalid feed handler configuration")

// Feed wraps a gossip.FeedHandler and surfaces a standard
// http.Handler plus a graceful-shutdown hook.
type Feed struct {
	handler *gossip.FeedHandler
	prefix  string
}

// NewFeedMount constructs the feed-serving side of the gossip
// pipeline. Pass the same gossip.Store the publisher writes to so
// the read-side is consistent with the write-side.
func NewFeedMount(cfg FeedConfig) (*Feed, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: nil Store", ErrFeedConfig)
	}
	prefix := cfg.PathPrefix
	if prefix == "" {
		prefix = gossip.DefaultFeedPathPrefix
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	h, err := gossip.NewFeedHandler(gossip.FeedHandlerConfig{
		Store:       cfg.Store,
		PathPrefix:  prefix,
		Logger:      logger,
		Instruments: cfg.Instruments,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFeedConfig, err)
	}
	return &Feed{handler: h, prefix: prefix}, nil
}

// Prefix returns the path prefix the mount listens on (e.g.
// "/v1/gossip"). The api/ composer uses this to register the
// handler under exactly the right mux path.
func (f *Feed) Prefix() string {
	if f == nil {
		return ""
	}
	return f.prefix
}

// ServeHTTP delegates to the underlying SDK feed handler. Standard
// http.Handler interface so the composer treats this like any
// other route.
func (f *Feed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f == nil || f.handler == nil {
		http.Error(w, "gossipfeed: not configured", http.StatusServiceUnavailable)
		return
	}
	f.handler.ServeHTTP(w, r)
}

// Close releases any background workers the SDK handler holds.
// Idempotent — safe to call from multiple shutdown paths.
func (f *Feed) Close(ctx context.Context) error {
	if f == nil || f.handler == nil {
		return nil
	}
	return f.handler.Close(ctx)
}
