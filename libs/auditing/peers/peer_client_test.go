package peers

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/baseproof/baseproof/gossip"
)

// fakeClient serves events strictly after cursor.Lamport (lamport == position),
// then empty pages once drained — mirroring the SDK /since contract.
type fakeClient struct {
	events []gossip.SignedEvent
}

func (f *fakeClient) Since(_ context.Context, cursor gossip.IterCursor, limit int) (gossip.FeedListResponse, error) {
	var out []gossip.SignedEvent
	for _, e := range f.events {
		if e.LamportTime > cursor.Lamport {
			out = append(out, e)
			if len(out) >= limit {
				break
			}
		}
	}
	next := cursor.Lamport
	if len(out) > 0 {
		next = out[len(out)-1].LamportTime
	}
	return gossip.FeedListResponse{Events: out, NextLamport: next}, nil
}

type sinkFunc func(context.Context, gossip.SignedEvent) error

func (f sinkFunc) HandleSignedEvent(ctx context.Context, ev gossip.SignedEvent) error {
	return f(ctx, ev)
}

func newTestPuller(t *testing.T, fc feedClient, sink SignedEventSink) *PeerPuller {
	t.Helper()
	p, err := NewPeerPuller(PeerPullerConfig{
		Peers:      []PeerFeed{{LogDID: "did:peer", BaseURL: "http://peer.example"}},
		Sink:       sink,
		Interval:   5 * time.Millisecond,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		newClient:  func(string, *http.Client) (feedClient, error) { return fc, nil },
	})
	if err != nil {
		t.Fatalf("NewPeerPuller: %v", err)
	}
	return p
}

func TestPeerPuller_DeliversAllEvents(t *testing.T) {
	fc := &fakeClient{events: []gossip.SignedEvent{
		{Kind: gossip.KindCosignedTreeHead, LamportTime: 1, Originator: "did:a"},
		{Kind: gossip.KindGhostLeaf, LamportTime: 2, Originator: "did:a"},
		{Kind: gossip.KindCosignedTreeHead, LamportTime: 3, Originator: "did:a"},
	}}
	got := make(chan uint64, 16)
	p := newTestPuller(t, fc, sinkFunc(func(_ context.Context, ev gossip.SignedEvent) error {
		got <- ev.LamportTime
		return nil
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	seen := map[uint64]bool{}
	for i := 0; i < 3; i++ {
		select {
		case lt := <-got:
			seen[lt] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout; seen=%v", seen)
		}
	}
	if !seen[1] || !seen[2] || !seen[3] {
		t.Fatalf("missing events: %v", seen)
	}
}

// A sink error on one event must not stop delivery of subsequent events.
func TestPeerPuller_SinkErrorDoesNotStopLoop(t *testing.T) {
	fc := &fakeClient{events: []gossip.SignedEvent{
		{Kind: gossip.KindCosignedTreeHead, LamportTime: 1},
		{Kind: gossip.KindGhostLeaf, LamportTime: 2},
	}}
	got := make(chan uint64, 8)
	p := newTestPuller(t, fc, sinkFunc(func(_ context.Context, ev gossip.SignedEvent) error {
		if ev.LamportTime == 1 {
			return errors.New("verification rejected")
		}
		got <- ev.LamportTime
		return nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	select {
	case lt := <-got:
		if lt != 2 {
			t.Fatalf("got %d, want 2", lt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event 2 not delivered after event 1 was rejected")
	}
}

// A sink panic on one event must be recovered; subsequent events still flow.
func TestPeerPuller_SinkPanicRecovered(t *testing.T) {
	fc := &fakeClient{events: []gossip.SignedEvent{
		{Kind: gossip.KindCosignedTreeHead, LamportTime: 1},
		{Kind: gossip.KindGhostLeaf, LamportTime: 2},
	}}
	got := make(chan uint64, 8)
	p := newTestPuller(t, fc, sinkFunc(func(_ context.Context, ev gossip.SignedEvent) error {
		if ev.LamportTime == 1 {
			panic("boom")
		}
		got <- ev.LamportTime
		return nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	select {
	case lt := <-got:
		if lt != 2 {
			t.Fatalf("got %d, want 2", lt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event 2 not delivered after panic on event 1")
	}
}

func TestNewPeerPuller_RequiresSink(t *testing.T) {
	if _, err := NewPeerPuller(PeerPullerConfig{}); !errors.Is(err, ErrPeerPuller) {
		t.Fatalf("err = %v, want ErrPeerPuller", err)
	}
}

// TestNewPeerPuller_RequiresHTTPClient pins the v1.27.1 contract: a nil
// HTTPClient is a programmer error and the constructor must refuse it
// rather than silently fall back to a plaintext 10s default. Mirrors
// the v1.27.0 SDK removal of optional-Client-with-fallback from
// HTTPSubmitterConfig and TesseraFetcherConfig.
func TestNewPeerPuller_RequiresHTTPClient(t *testing.T) {
	sink := sinkFunc(func(context.Context, gossip.SignedEvent) error { return nil })
	if _, err := NewPeerPuller(PeerPullerConfig{
		Peers: []PeerFeed{{LogDID: "did:peer", BaseURL: "http://peer.example"}},
		Sink:  sink,
		// HTTPClient deliberately omitted.
	}); !errors.Is(err, ErrPeerPuller) {
		t.Fatalf("err = %v, want ErrPeerPuller on nil HTTPClient", err)
	}
}
