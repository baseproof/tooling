// FILE PATH: services/auditor/internal/gossipfeed/sink_test.go
//
// DESCRIPTION:
//
//	Tests for the Phase 4 gossip publisher. Verifies:
//	  1. NewPublisher rejects a nil underlying sink (ErrInvalidConfig).
//	  2. EmitSTH is non-blocking — sthSink's DropOldest policy means
//	     a backed-up underlying sink never wedges the publisher.
//	  3. EmitEvidence applies strict back-pressure — when the queue
//	     fills, the publisher returns an error rather than dropping.
//	  4. Close drains both sinks idempotently.
//	  5. QueueDepth reports both channels independently.
//
//	The tests use a controllable fake Sink (slowSink) so we
//	deterministically observe queue back-pressure without relying on
//	wall-clock timing.
package gossipfeed

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/gossip"
)

// slowSink blocks every Broadcast on a channel the test closes when
// it wants to drain. Used to deterministically fill the
// BufferedSink queue. Counts received events under a mutex; tests
// inspect via Count().
type slowSink struct {
	release chan struct{}
	mu      sync.Mutex
	count   int
}

func newSlowSink() *slowSink {
	return &slowSink{release: make(chan struct{})}
}

func (s *slowSink) Broadcast(ctx context.Context, _ gossip.SignedEvent) error {
	select {
	case <-s.release:
		s.mu.Lock()
		s.count++
		s.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *slowSink) Close(_ context.Context) error { return nil }

func (s *slowSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func TestNewPublisher_RejectsNilUnderlying(t *testing.T) {
	_, err := NewPublisher(PublisherConfig{Underlying: nil})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestNewPublisher_AppliesDefaults(t *testing.T) {
	sink := newSlowSink()
	close(sink.release) // unblock all sends
	p, err := NewPublisher(PublisherConfig{
		Underlying: sink,
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	defer p.Close(context.Background())

	// Both sinks were constructed; QueueDepth returns two values.
	sth, evidence := p.QueueDepth()
	if sth != 0 || evidence != 0 {
		t.Fatalf("expected both queues empty at boot, got sth=%d evidence=%d", sth, evidence)
	}
}

func TestEmitSTH_NonBlocking_DropOldest(t *testing.T) {
	sink := newSlowSink()
	p, err := NewPublisher(PublisherConfig{
		Underlying:       sink,
		STHQueueSize:     2,
		FindingQueueSize: 2,
		Workers:          1,
		PerEventTimeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	defer p.Close(context.Background())

	// Don't release any sink — slowSink blocks. Queue fills then
	// DropOldest takes over. EmitSTH must return nil for each call;
	// the SDK's DropPolicyDropOldest doesn't surface an error to
	// the caller, the metric records the drop.
	ev := gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead}
	for i := 0; i < 5; i++ {
		if err := p.EmitSTH(context.Background(), ev); err != nil {
			t.Fatalf("EmitSTH[%d]: expected non-blocking nil, got %v", i, err)
		}
	}
	// Release everything; the test isn't checking what got
	// delivered, only that the publisher never wedged.
	close(sink.release)
}

func TestEmitEvidence_StrictBackpressure(t *testing.T) {
	sink := newSlowSink()
	p, err := NewPublisher(PublisherConfig{
		Underlying:       sink,
		STHQueueSize:     2,
		FindingQueueSize: 2,
		Workers:          1,
		PerEventTimeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	defer p.Close(context.Background())

	ev := gossip.SignedEvent{Kind: gossip.KindEquivocationFinding}

	// First two emits fit in the queue (1 worker stuck on the
	// blocked sink + up to QueueSize buffered = ~3 in-flight). The
	// third should surface back-pressure as ErrSinkQueueFull. Wait
	// briefly between calls so the worker drains into its blocking
	// Broadcast first.
	_ = p.EmitEvidence(context.Background(), ev)
	_ = p.EmitEvidence(context.Background(), ev)
	_ = p.EmitEvidence(context.Background(), ev)

	// At least one of the next emits must return an error — the
	// DropPolicyReturnError contract is "fail when full".
	saw := false
	for i := 0; i < 8; i++ {
		if err := p.EmitEvidence(context.Background(), ev); err != nil {
			if errors.Is(err, gossip.ErrSinkQueueFull) {
				saw = true
			}
			break
		}
	}
	close(sink.release)
	if !saw {
		t.Fatalf("expected ErrSinkQueueFull under sustained back-pressure")
	}
}

func TestClose_Idempotent(t *testing.T) {
	sink := newSlowSink()
	close(sink.release)
	p, err := NewPublisher(PublisherConfig{Underlying: sink})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.Close(ctx); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(ctx); err != nil {
		t.Fatalf("second Close (idempotent): %v", err)
	}
}

func TestClose_NilPublisher(t *testing.T) {
	var p *Publisher
	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("nil receiver Close should be a no-op, got %v", err)
	}
}

func TestEmitSTH_AfterClose(t *testing.T) {
	sink := newSlowSink()
	close(sink.release)
	p, err := NewPublisher(PublisherConfig{Underlying: sink})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	_ = p.Close(context.Background())
	err = p.EmitSTH(context.Background(), gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead})
	if err == nil {
		t.Fatalf("expected error emitting on closed sink; got nil")
	}
}

func TestParallelEmits_NoRace(t *testing.T) {
	sink := newSlowSink()
	close(sink.release)
	p, err := NewPublisher(PublisherConfig{
		Underlying:       sink,
		STHQueueSize:     64,
		FindingQueueSize: 64,
		Workers:          4,
	})
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	defer p.Close(context.Background())

	var wg sync.WaitGroup
	wg.Add(8)
	for i := 0; i < 8; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				_ = p.EmitSTH(context.Background(),
					gossip.SignedEvent{Kind: gossip.KindCosignedTreeHead})
			}
		}()
	}
	wg.Wait()
}
