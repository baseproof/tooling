/*
FILE PATH: libs/gossipingest/throttle.go

Ladder 5 P9 (#21) — bounded-concurrency backpressure for the
puller→reconciler hot path.

# THE PROBLEM

The PeerPuller delivers each fetched event to its Sink synchronously
(peers.PeerPuller.deliver → SignedEventSink.HandleSignedEvent). At
sustained 1K+ TPS, if the reconciler's verify-then-act stage slows
(slow DB, a deadlocked transaction, a backed-up equivocation responder),
the puller keeps fetching pages from peers and the verify backlog grows
unboundedly inside the puller's per-peer pollPeer loops. Memory pressure
spikes; latency tail lengthens; an unrelated failure mode (OOM kill)
takes down a binary that was otherwise responding to traffic.

# THE FIX — A COUNTING SEMAPHORE

Throttler wraps a SignedEventSink and gates each HandleSignedEvent call
through a fixed-capacity buffered channel. When the channel is full,
the next caller BLOCKS until a slot frees — natural backpressure to the
puller's pollPeer loop. The puller is happy to block (its own loop
just waits longer between page fetches); peer ledgers see slower
/v1/gossip/since traffic; the binary's memory profile stays bounded.

No additional goroutines; no async queue; no failure-handling surprise
(the wrapped HandleSignedEvent's error and ctx semantics flow through
unchanged).

# %-CAPACITY (NOT REQUEST COUNT)

The cap is a CEILING the operator picks (e.g., 64 concurrent verifies).
The runtime exposes InFlight() / Capacity() so an OTel observable
gauge — or a K8s HPA custom metric — can scrape saturation
(InFlight / Capacity, 0.0..1.0) and scale the replicaset on it. This
decouples the autoscale signal from raw traffic: a binary at 99%
saturation needs another replica regardless of QPS; a binary at 10%
doesn't need scaling even at high QPS. The observability layer is
caller-owned — Throttler stays a pure mechanism.

# MULTI-NETWORK FORWARD SEAM

The auditor today is mono-network (one bootstrap → one pipeline → one
reconciler → one Throttler). A future multi-network deployment has two
shapes available, BOTH of which fit the current API:

  - PER-NETWORK Throttler: each network's pipeline.Build is invoked
    with its own MaxInFlightVerify. Each network gets a dedicated
    quota; no cross-network contention. Simple and isolated.

  - SHARED Throttler instance passed by the binary to each pipeline's
    Build via a forthcoming "Sink" or "Throttler" Config field. Then
    one capacity is split across N networks via the semaphore's FIFO
    ordering. Cross-network fairness is the FIFO property: a network
    bursting onto the shared semaphore doesn't starve quieter peers
    because the channel-of-tokens-released-by-FIFO arrangement gives
    each Acquire its turn.

Both shapes are admitted by today's interface (Throttler is a
SignedEventSink). The currently-implemented mono-network deployment
uses the per-network shape with a single Throttler per Pipeline.

# CTX SEMANTICS

HandleSignedEvent respects ctx in TWO places:

  - acquire: the buffered-channel write is selected against ctx.Done;
    a cancelled-during-acquire returns ctx.Err WITHOUT calling the
    wrapped sink.
  - delegated call: ctx flows to the wrapped sink unchanged; whatever
    sink does (verify, store, dispatch) operates on the same ctx.

Release is unconditional (defer); a ctx-cancelled call between Acquire
and the wrapped call's start still releases the slot, so a flood of
cancelled requests cannot leak slots.

# WHY NOT golang.org/x/sync/semaphore

The x/sync/semaphore.Weighted exists; we use a plain buffered chan
because:
  - Weighted is for variable cost (Acquire(N)); each event here is
    cost-1, so the simpler chan is the right primitive.
  - The chan-of-tokens shape lets InFlight = cap - len(ch) without an
    additional atomic counter — single source of truth.
  - Zero added dependencies; libs/ stays lean.
*/
package gossipingest

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/baseproof/baseproof/gossip"

	"github.com/baseproof/tooling/libs/auditing/peers"
)

// Throttler bounds the concurrency of an underlying SignedEventSink.
// At capacity, HandleSignedEvent blocks until a slot frees or ctx
// cancels. Zero added goroutines; the channel itself is the queue
// + the depth counter.
//
// Throttler implements peers.SignedEventSink so it can be substituted
// for the bare reconciler at the Puller's Sink seam in pipeline.Build.
type Throttler struct {
	inner    peers.SignedEventSink
	tokens   chan struct{}
	capacity int
	logger   *slog.Logger
}

// NewThrottler returns a Throttler with the given capacity. capacity
// MUST be > 0 (zero would deadlock every Acquire; negative is a
// programmer error).
//
// Choose capacity to match the binary's CPU + DB connection budget:
// each in-flight HandleSignedEvent typically holds one DB-pool
// connection for the duration of the verify-then-persist stage,
// plus CPU for cosignature verification. A typical starting point
// is 2 × (DB pool max) or 4 × (vCPU count), bounded above by
// available RAM / per-event allocation.
//
// inner MUST be non-nil; logger MUST be non-nil (slog.Default() is
// the caller's responsibility to plumb).
func NewThrottler(inner peers.SignedEventSink, capacity int, logger *slog.Logger) (*Throttler, error) {
	if inner == nil {
		return nil, fmt.Errorf("gossipingest: throttler inner sink is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("gossipingest: throttler logger is required")
	}
	if capacity <= 0 {
		return nil, fmt.Errorf("gossipingest: throttler capacity must be > 0; got %d", capacity)
	}
	return &Throttler{
		inner:    inner,
		tokens:   make(chan struct{}, capacity),
		capacity: capacity,
		logger:   logger,
	}, nil
}

// HandleSignedEvent implements peers.SignedEventSink. Acquires a slot
// (blocks if at capacity, returns ctx.Err on cancellation), delegates
// to the wrapped sink, releases the slot unconditionally.
func (t *Throttler) HandleSignedEvent(ctx context.Context, ev gossip.SignedEvent) error {
	select {
	case t.tokens <- struct{}{}:
		// Acquired; ensure release on every exit path (including panic).
		defer func() { <-t.tokens }()
	case <-ctx.Done():
		// Cancelled-during-acquire: skip the wrapped call. Returning
		// ctx.Err() matches the contract callers expect — the same shape
		// every other ctx-respecting Go API surfaces on cancellation.
		return ctx.Err()
	}
	return t.inner.HandleSignedEvent(ctx, ev)
}

// Capacity returns the configured maximum concurrency.
func (t *Throttler) Capacity() int { return t.capacity }

// InFlight returns the current number of HandleSignedEvent calls that
// have acquired a slot but not yet released. Bounded in [0, Capacity].
// Safe to call from any goroutine; the channel's len is atomic.
func (t *Throttler) InFlight() int { return len(t.tokens) }

// Saturation returns InFlight / Capacity in [0.0, 1.0]. Useful as a
// K8s HPA custom metric source — autoscale on saturation > 0.8 to
// add a replica before the verify path starts blocking the puller.
func (t *Throttler) Saturation() float64 {
	return float64(t.InFlight()) / float64(t.capacity)
}
