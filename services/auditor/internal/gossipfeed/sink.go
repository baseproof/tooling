// FILE PATH: services/auditor/internal/gossipfeed/sink.go
//
// DESCRIPTION:
//
//	Phase 4 — Non-blocking gossip emit for judicial-network. Wraps
//	the SDK's BufferedSink so the API process publishes
//	cosigned tree heads, equivocation findings, escrow-override
//	authorizations, and originator-rotation events without ever
//	stalling the HTTP admission hot-path.
//
//	The sink is intentionally lossy on the STH channel (DropOldest
//	when the queue fills — a fresher head supersedes a stale one)
//	and strict on equivocation / escrow-override channels (
//	ReturnError so back-pressure surfaces to the publisher and the
//	caller decides whether to retry or escalate). This split honours
//	Trust Alignment 12 (Non-Blocking Gossip Sinks) and Ledger
//	Principle 12 (Two Clocks — the transparency clock is async and
//	never blocks the commit clock).
//
//	The publisher is constructed once at boot via NewPublisher and
//	shared across handlers. Close drains in two phases: stop
//	accepting new emits, then wait for in-flight workers to finish.
//
// KEY DEPENDENCIES:
//   - baseproof/gossip: BufferedSink, BufferedSinkConfig, DropPolicy
//   - baseproof/gossip/findings: CosignedTreeHeadFinding,
//     EquivocationFinding, EntryCommitmentEquivocationFinding,
//     EscrowOverrideAuthorizationFinding,
//     OriginatorRotationFinding
package gossipfeed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/baseproof/baseproof/gossip"
)

// PublisherConfig configures the gossip publisher. Fields are
// validated at NewPublisher time; misconfigured queues never reach
// the sink.
type PublisherConfig struct {
	// Underlying is the wire-bound sink that does the actual emit.
	// Production deployments point this at a gossip.HTTPSink or
	// gossip.MultiSink fanning out to N peers; tests inject a
	// channel-based fake.
	Underlying gossip.Sink

	// STHQueueSize bounds the cosigned-tree-head channel. A fresher
	// head supersedes a stale one, so the channel uses DropOldest
	// when full — bandwidth tail latency stays bounded even when a
	// peer subgraph degrades.
	STHQueueSize int

	// FindingQueueSize bounds the equivocation / escrow-override
	// / originator-rotation channels. These are evidentiary; we
	// surface ErrSinkQueueFull on overflow so the publisher knows
	// to retry rather than silently drop a fork proof.
	FindingQueueSize int

	// Workers controls the per-channel worker count. Default 4.
	Workers int

	// PerEventTimeout caps how long a single event spends inside
	// the worker before it's considered failed. Default 10 s
	// (matches gossip.DefaultBufferedSinkPerEventTimeout).
	PerEventTimeout time.Duration

	// Logger is the structured logger every sink writes to. Nil →
	// slog.Default.
	Logger *slog.Logger
}

// ErrInvalidConfig surfaces NewPublisher configuration faults.
var ErrInvalidConfig = errors.New("gossipfeed: invalid publisher configuration")

// Publisher owns the two BufferedSink pipelines (STH vs evidence)
// and exposes one Emit method per finding type. The split avoids
// head-of-line blocking: a stuck evidence channel never starves
// STH emission, and vice versa.
type Publisher struct {
	sthSink      *gossip.BufferedSink
	evidenceSink *gossip.BufferedSink
	logger       *slog.Logger
}

// NewPublisher constructs both sink pipelines or returns
// ErrInvalidConfig.
func NewPublisher(cfg PublisherConfig) (*Publisher, error) {
	if cfg.Underlying == nil {
		return nil, fmt.Errorf("%w: nil Underlying sink", ErrInvalidConfig)
	}
	if cfg.STHQueueSize <= 0 {
		cfg.STHQueueSize = 256
	}
	if cfg.FindingQueueSize <= 0 {
		cfg.FindingQueueSize = 64
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.PerEventTimeout <= 0 {
		cfg.PerEventTimeout = gossip.DefaultBufferedSinkPerEventTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	sthSink, err := gossip.NewBufferedSink(gossip.BufferedSinkConfig{
		Underlying:      cfg.Underlying,
		QueueSize:       cfg.STHQueueSize,
		Workers:         cfg.Workers,
		Policy:          gossip.DropPolicyDropOldest,
		Logger:          logger.With(slog.String("channel", "sth")),
		PerEventTimeout: cfg.PerEventTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: sth sink: %v", ErrInvalidConfig, err)
	}

	evidenceSink, err := gossip.NewBufferedSink(gossip.BufferedSinkConfig{
		Underlying:      cfg.Underlying,
		QueueSize:       cfg.FindingQueueSize,
		Workers:         cfg.Workers,
		Policy:          gossip.DropPolicyReturnError,
		Logger:          logger.With(slog.String("channel", "evidence")),
		PerEventTimeout: cfg.PerEventTimeout,
	})
	if err != nil {
		_ = sthSink.Close(context.Background())
		return nil, fmt.Errorf("%w: evidence sink: %v", ErrInvalidConfig, err)
	}

	return &Publisher{
		sthSink:      sthSink,
		evidenceSink: evidenceSink,
		logger:       logger,
	}, nil
}

// EmitSTH publishes a cosigned tree head. Lossy by design — the
// STH channel uses DropOldest because a fresher head obsoletes a
// stale one.
func (p *Publisher) EmitSTH(ctx context.Context, ev gossip.SignedEvent) error {
	if p == nil || p.sthSink == nil {
		return errors.New("gossipfeed: STH sink not configured")
	}
	if err := p.sthSink.Broadcast(ctx, ev); err != nil {
		// DropOldest semantics return ErrSinkQueueFull only when
		// the queue is closed; log + return so the caller can
		// distinguish from a transient back-pressure drop.
		p.logger.Warn("gossipfeed: STH emit failed",
			slog.String("error", err.Error()),
			slog.String("kind", string(ev.Kind)),
		)
		return err
	}
	return nil
}

// EmitEvidence publishes an evidentiary finding (equivocation,
// escrow override, originator rotation). Strict back-pressure — a
// full queue surfaces ErrSinkQueueFull so the caller decides
// whether to retry or escalate to an out-of-band alert path.
func (p *Publisher) EmitEvidence(ctx context.Context, ev gossip.SignedEvent) error {
	if p == nil || p.evidenceSink == nil {
		return errors.New("gossipfeed: evidence sink not configured")
	}
	if err := p.evidenceSink.Broadcast(ctx, ev); err != nil {
		p.logger.Error("gossipfeed: evidence emit failed",
			slog.String("error", err.Error()),
			slog.String("kind", string(ev.Kind)),
		)
		return err
	}
	return nil
}

// QueueDepth reports the current per-channel depth. Useful for
// SRE dashboards (Trust Alignment 14: actionable telemetry).
func (p *Publisher) QueueDepth() (sth, evidence int) {
	if p == nil {
		return 0, 0
	}
	return p.sthSink.QueueDepth(), p.evidenceSink.QueueDepth()
}

// Close gracefully drains both sinks. Phase 1 stops accepting new
// emits; phase 2 waits for in-flight workers to finish or for ctx
// to fire. Idempotent — safe to call from multiple shutdown paths.
func (p *Publisher) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var firstErr error
	if p.sthSink != nil {
		if err := p.sthSink.Close(ctx); err != nil {
			firstErr = err
		}
	}
	if p.evidenceSink != nil {
		if err := p.evidenceSink.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
