// FILE PATH: libs/auditing/peers/peer_client.go
//
// DESCRIPTION:
//
//	PeerPuller is the inbound transport for the gossip anti-entropy plane: a
//	background poll loop that pulls each configured peer ledger's
//	/v1/gossip/since feed (via the SDK's gossip.FeedClient) and hands every
//	raw, UNVERIFIED SignedEvent to a SignedEventSink. It is pure transport —
//	it performs NO verification and grants a peer NO trust beyond "here are
//	bytes a peer served." The sink (the gossip reconciler, composed in cmd)
//	runs the zero-trust verify-then-act pipeline.
//
//	Why transport-only: a pulling client receives attacker-controlled JSON.
//	Trust is established by the consumer (verify_gossip.GossipVerifier), not by
//	the transport. Keeping the puller dumb keeps the trust boundary in exactly
//	one place.
//
//	MELT-PROOF: one goroutine per peer (isolation — a slow/hostile peer never
//	starves another), a bounded page size, a poll interval between catch-up
//	rounds, ctx-bounded fetches, and per-event panic recovery so one bad event
//	never kills the loop.
package peers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/baseproof/baseproof/gossip"
)

// SignedEventSink consumes raw, UNVERIFIED gossip events pulled from a peer.
// Implementations MUST verify (envelope + finding proof) before acting; the
// puller guarantees nothing about authenticity.
type SignedEventSink interface {
	HandleSignedEvent(ctx context.Context, ev gossip.SignedEvent) error
}

// PeerFeed names one peer ledger's gossip feed.
type PeerFeed struct {
	// LogDID is the peer's log DID — diagnostic + per-peer cursor key. The
	// puller does NOT use it for trust (each event is verified on its own
	// envelope), only for logging and goroutine identity.
	LogDID string
	// BaseURL is the peer's base URL; the SDK FeedClient appends the
	// /v1/gossip prefix. MUST be an operator-pinned allowlist entry.
	BaseURL string
}

// feedClient is the subset of *gossip.FeedClient the loop needs (interface so
// tests inject a fake without HTTP).
type feedClient interface {
	Since(ctx context.Context, cursor gossip.IterCursor, limit int) (gossip.FeedListResponse, error)
}

// PeerPullerConfig configures the poll loop.
type PeerPullerConfig struct {
	// Peers is the operator-pinned allowlist of peer feeds to pull.
	Peers []PeerFeed
	// Sink receives every pulled raw event. Required.
	Sink SignedEventSink
	// HTTPClient is the *http.Client used for every peer-feed fetch.
	// Required. The caller owns transport posture (timeout, mTLS material,
	// retry, middleware). v1.27.1 removed the prior optional-Client +
	// 10s-plaintext-fallback shape that silently bypassed the binary's
	// mTLS posture; the SDK's HTTPSubmitterConfig / TesseraFetcherConfig
	// underwent the same migration. Typical:
	//   sdklog.DefaultClient(10*time.Second, tlsCfg)
	HTTPClient *http.Client
	// Interval is the wait between catch-up rounds per peer; <=0 ⇒ 5s.
	Interval time.Duration
	// PageLimit caps events per /since page; <=0 ⇒ 256.
	PageLimit int
	// Logger; nil ⇒ slog.Default().
	Logger *slog.Logger

	// newClient overrides FeedClient construction (test injection). nil ⇒
	// gossip.NewFeedClient.
	newClient func(baseURL string, hc *http.Client) (feedClient, error)
}

// PeerPuller runs the inbound poll loop. Construct via NewPeerPuller.
type PeerPuller struct {
	cfg PeerPullerConfig
}

// ErrPeerPuller wraps configuration faults.
var ErrPeerPuller = errors.New("topology/peer_client")

// NewPeerPuller validates config and returns a PeerPuller.
func NewPeerPuller(cfg PeerPullerConfig) (*PeerPuller, error) {
	if cfg.Sink == nil {
		return nil, fmt.Errorf("%w: nil Sink", ErrPeerPuller)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.PageLimit <= 0 {
		cfg.PageLimit = 256
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("%w: HTTPClient is required (build via sdklog.DefaultClient or any *http.Client)", ErrPeerPuller)
	}
	if cfg.newClient == nil {
		cfg.newClient = func(baseURL string, hc *http.Client) (feedClient, error) {
			return gossip.NewFeedClient(baseURL, hc)
		}
	}
	return &PeerPuller{cfg: cfg}, nil
}

// Run pulls every configured peer concurrently until ctx is cancelled, one
// goroutine per peer. Returns ctx.Err() once all peer loops have stopped.
// Blocks; callers run it as a background worker.
func (p *PeerPuller) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, peer := range p.cfg.Peers {
		client, err := p.cfg.newClient(peer.BaseURL, p.cfg.HTTPClient)
		if err != nil {
			p.cfg.Logger.Error("gossip puller: skip peer (client init failed)",
				slog.String("peer", peer.LogDID), slog.String("error", err.Error()))
			continue
		}
		wg.Add(1)
		go func(peer PeerFeed, client feedClient) {
			defer wg.Done()
			p.pollPeer(ctx, peer, client)
		}(peer, client)
	}
	wg.Wait()
	return ctx.Err()
}

// pollPeer pulls one peer in a loop: drain all available pages (catch up),
// then wait Interval and repeat. The cursor persists across rounds so each
// round resumes strictly after the last consumed Lamport.
func (p *PeerPuller) pollPeer(ctx context.Context, peer PeerFeed, client feedClient) {
	cursor := gossip.IterCursor{}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		cursor = p.drain(ctx, peer, client, cursor)
		timer.Reset(p.cfg.Interval)
	}
}

// drain consumes consecutive pages until the peer reports no more events (or a
// fetch fails). Returns the advanced cursor for the next round.
func (p *PeerPuller) drain(ctx context.Context, peer PeerFeed, client feedClient, cursor gossip.IterCursor) gossip.IterCursor {
	for {
		if ctx.Err() != nil {
			return cursor
		}
		resp, err := client.Since(ctx, cursor, p.cfg.PageLimit)
		if err != nil {
			// Transient (incl. 429 rate-limit): log and retry next round
			// from the same cursor. No advance — fail-closed on progress.
			p.cfg.Logger.Warn("gossip puller: fetch failed",
				slog.String("peer", peer.LogDID), slog.String("error", err.Error()))
			return cursor
		}
		for i := range resp.Events {
			p.deliver(ctx, peer, resp.Events[i])
		}
		if len(resp.Events) == 0 {
			return cursor // caught up
		}
		cursor.Lamport = resp.NextLamport
	}
}

// deliver hands one raw event to the sink under a panic guard so a malformed /
// adversarial event cannot crash the loop. Sink errors (verification rejects,
// etc.) are logged and skipped — fail-closed by omission.
func (p *PeerPuller) deliver(ctx context.Context, peer PeerFeed, ev gossip.SignedEvent) {
	defer func() {
		if r := recover(); r != nil {
			p.cfg.Logger.Error("gossip puller: sink panic recovered",
				slog.String("peer", peer.LogDID), slog.String("kind", string(ev.Kind)), slog.Any("panic", r))
		}
	}()
	if err := p.cfg.Sink.HandleSignedEvent(ctx, ev); err != nil {
		p.cfg.Logger.Warn("gossip puller: event rejected",
			slog.String("peer", peer.LogDID), slog.String("kind", string(ev.Kind)), slog.String("error", err.Error()))
	}
}
