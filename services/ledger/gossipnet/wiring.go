/*
FILE PATH: gossipnet/wiring.go

Ledger-side gossip plumbing: connects the SDK's gossip handler /
feed handler / cached DID verifier / buffered sink to the
ledger's BadgerStore-backed gossip.Store and the cmd/ledger
main.go startup sequence.

# WHY THIS PACKAGE

The SDK ships every gossip primitive (Store interface, Handler,
FeedHandler, Sink, OriginatorVerifier) as an independent component.
The ledger owns the choices a single-deployment binary makes:

  - Which Store implementation? (gossipstore.BadgerStore)
  - Which DID verifiers are in scope? (did:key today; did:web later)
  - What rate-limit policy? (crypto/middleware token bucket)
  - What sink topology? (BufferedSink → MultiSink over peer
    ledgers, or NopSink in single-process tests)
  - What cache TTL on the originator key resolver?

Bundling these decisions into one wiring helper keeps
cmd/ledger/main.go from carrying ~200 lines of plumbing for a
sub-feature.

# RATE LIMITING

The cosign endpoint and the gossip endpoint are independently
rate-limited. Sharing a single middleware instance (and therefore
a single token bucket per peer-IP) would let a noisy gossip
publisher starve cosign requests from the same peer. Two
middleware instances keep the budgets independent.

# ORIGINATOR-VERIFIER CACHE

CachedDIDOriginatorVerifier wraps the base DIDOriginatorVerifier
with an LRU+TTL of resolved PubKeyIDs. The handler invokes
Invalidate(originator) automatically after a successful
KindOriginatorRotation Append, so cached entries that rotated mid-
session don't poison subsequent verifies. TTL is the failure
budget for a rotation that bypasses the gossip publishing path
(should not happen, but bounded staleness is the safe default).

# FAN-OUT TOPOLOGY

Single-network deployments use NopSink — the ledger's own
BadgerStore is the only consumer; nothing to fan out to.

Multi-network deployments wrap a MultiSink over an HTTPSink per
peer ledger's /v1/gossip endpoint. The MultiSink is wrapped in a
BufferedSink so the publish call site (builder loop hot path)
never blocks on slow peers. Drop policy = DropOldest so a
persistently-slow peer doesn't accumulate unbounded backlog.
*/
package gossipnet

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/middleware"
	"github.com/baseproof/baseproof/did"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"go.opentelemetry.io/otel/metric"
)

// Config bundles everything gossipnet.Build needs to wire the
// ledger's gossip stack.
type Config struct {
	// Store is the persistent gossip store. Required.
	Store sdkgossip.Store

	// AuditorRegistrySource enables the v1.32.0 auditor-scope
	// authorization gate on inbound finding-class events
	// (KindEquivocationFinding, KindSMTReplayFinding,
	// KindHistoryRewriteFinding). Build wraps Store in an
	// AuditorScopeGate when this field is non-nil; the Handler
	// then sees the gated Store and every finding-class Append
	// is checked against AuditorRegistration.AuthorizedFor before
	// persistence.
	//
	// nil DISABLES THE GATE — the pre-v1.32.0 wide-open behaviour
	// (any signed event from any DID gets persisted). Operators
	// running with auditor-scope enforcement MUST wire this from
	// boot (cmd/ledger/boot/wire/gossip.go) against an on-log
	// AuditorRegistrationV1 walker source.
	AuditorRegistrySource AuditorRegistrySource

	// AuditorAmendmentSource enables the v1.33.0 Gap 2 amendment
	// stream. The gate merges these records with AuditorRegistrySource
	// when resolving an auditor's effective scope at a position.
	// Optional — nil ⇒ "no amendments yet", which is equivalent to
	// the v1.32.0 registration-only behaviour.
	AuditorAmendmentSource AuditorAmendmentSource

	// AuditorScopeAsOf returns the log position the auditor-scope
	// gate uses for its walker's asOf. nil ⇒ zero LogPosition
	// (all registrations are treated as in-effect; appropriate
	// only when records are pre-filtered).
	AuditorScopeAsOf AsOfProvider

	// NetworkID is the deployment's cosign-domain identifier.
	// Required (non-zero).
	NetworkID sdkcosign.NetworkID

	// PeerEndpoints is the set of base URLs of peer ledgers
	// running their own /v1/gossip endpoint. Empty ⇒ NopSink
	// (no fan-out; single-process or single-ledger deployment).
	PeerEndpoints []string

	// RateLimitRPS is the per-peer-IP rate limit on /v1/gossip.
	// 0 ⇒ middleware default (100 RPS). Negative ⇒ no rate
	// limiting (only for trusted-network test rigs).
	RateLimitRPS float64

	// RateLimitBurst is the per-peer-IP burst cap. 0 ⇒ middleware
	// default (200).
	RateLimitBurst int

	// FeedRateLimitRPS is the per-peer-IP rate limit on
	// /v1/gossip/{since,sth/latest,event,by-kind}. Audit
	// consumers fan out reads more than writers fan out writes;
	// this is typically higher than RateLimitRPS. 0 ⇒ middleware
	// default (100 RPS).
	FeedRateLimitRPS float64

	// VerifierCacheTTL is the LRU+TTL of resolved PubKeyIDs in the
	// CachedDIDOriginatorVerifier. 0 ⇒ SDK default (5 minutes).
	VerifierCacheTTL time.Duration

	// VerifierCacheSize is the max entries in the LRU. 0 ⇒ SDK
	// default (4096).
	VerifierCacheSize int

	// SinkQueueSize sizes the BufferedSink queue. Only consulted
	// when PeerEndpoints is non-empty. 0 ⇒ DefaultSinkQueueSize.
	SinkQueueSize int

	// HTTPClient overrides the HTTP client used by the per-peer
	// gossip clients. nil ⇒ SDK default (with retry on 503).
	HTTPClient *http.Client

	// Meter, if non-nil, drives the gossip subsystem's OTel
	// instruments (received_total, published_total,
	// verify_duration_seconds, queue_depth, drops_total). When
	// nil, gossip.NewInstruments is skipped and the handler /
	// sink run un-instrumented.
	Meter metric.Meter

	// Logger receives diagnostics. nil ⇒ slog.Default().
	Logger *slog.Logger
}

// DefaultSinkQueueSize is the BufferedSink queue depth when
// Config.SinkQueueSize is zero. 1024 absorbs ~1 second of peak
// (1K TPS) commits before drop-oldest kicks in; longer than that
// the sink is genuinely overwhelmed and dropping is the right
// call (lower-priority finding events shouldn't block the commit
// path).
const DefaultSinkQueueSize = 1024

// Bundle holds the constructed gossip components.
type Bundle struct {
	PostHandler http.Handler
	FeedHandler http.Handler
	Sink        sdkgossip.Sink
	Verifier    *RotationCachedVerifier
	Closeables  []sdkgossip.Closeable
}

// RotationCachedVerifier composes:
//
//   - DIDOriginatorVerifier (resolves did:key →
//     types.WitnessPublicKey + verifies signatures)
//   - CachedDIDOriginatorVerifier (LRU+TTL on resolved
//     PubKeyIDs)
//   - InMemoryKeyManager (rotation override map; falls
//     through to the cached verifier when no rotation is
//     present)
type RotationCachedVerifier struct {
	keyMgr *sdkgossip.InMemoryKeyManager
	cached *sdkgossip.CachedDIDOriginatorVerifier
}

func (v *RotationCachedVerifier) VerifyOriginator(
	ctx context.Context, originator string, digest [32]byte, sigBytes []byte, schemeTag uint8,
) error {
	return v.keyMgr.VerifyOriginator(ctx, originator, digest, sigBytes, schemeTag)
}

func (v *RotationCachedVerifier) ResolvePubKeyID(ctx context.Context, originator string) ([32]byte, error) {
	return v.keyMgr.ResolvePubKeyID(ctx, originator)
}

func (v *RotationCachedVerifier) RotateOriginator(
	ctx context.Context, originator string, newPublicKey []byte, checkpoint [32]byte,
) error {
	return v.keyMgr.RotateOriginator(ctx, originator, newPublicKey, checkpoint)
}

func (v *RotationCachedVerifier) Invalidate(originator string) {
	v.cached.Invalidate(originator)
}

// Build constructs the ledger's gossip stack from cfg.
func Build(cfg Config) (*Bundle, error) {
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet: Config.NetworkID required (non-zero)")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet: Config.Store required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	verifier, err := buildVerifier(cfg)
	if err != nil {
		return nil, err
	}

	// v1.32.0 — wrap Store in the auditor-scope gate when the
	// caller wired a registry source. This is the L5 authorization
	// gate the SDK ships AuditorRegistration.AuthorizedFor for.
	// Skipped when no source is wired (operators running the legacy
	// open-ingest posture during transition).
	gatedStore := cfg.Store
	if cfg.AuditorRegistrySource != nil {
		gate, gerr := NewAuditorScopeGate(AuditorScopeGateConfig{
			Underlying: cfg.Store,
			Registry:   cfg.AuditorRegistrySource,
			Amendments: cfg.AuditorAmendmentSource,
			AsOf:       cfg.AuditorScopeAsOf,
			Logger:     cfg.Logger,
		})
		if gerr != nil {
			return nil, fmt.Errorf("gossipnet: NewAuditorScopeGate: %w", gerr)
		}
		gatedStore = gate
		cfg.Logger.Info("gossipnet: auditor-scope gate ENABLED (inbound findings checked against AuditorRegistration.AuthorizedFor)")
	} else {
		cfg.Logger.Warn("gossipnet: auditor-scope gate DISABLED (no AuditorRegistrySource wired) — finding-class events accepted regardless of originator scope")
	}

	var instruments *sdkgossip.Instruments
	if cfg.Meter != nil {
		instruments, err = sdkgossip.NewInstruments(cfg.Meter, cfg.Store)
		if err != nil {
			return nil, fmt.Errorf("gossipnet: NewInstruments: %w", err)
		}
	}

	sink, sinkClose, err := buildSink(cfg, instruments)
	if err != nil {
		return nil, err
	}

	postHandler, err := sdkgossip.NewHandler(sdkgossip.HandlerConfig{
		Store:           gatedStore, // v1.32.0: AuditorScopeGate when wired
		Verifier:        verifier,
		AllowedNetworks: map[sdkcosign.NetworkID]struct{}{cfg.NetworkID: {}},
		Sink:            sink,
		Logger:          cfg.Logger,
		Instruments:     instruments,
	})
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewHandler: %w", err)
	}

	feedHandler, err := sdkgossip.NewFeedHandler(sdkgossip.FeedHandlerConfig{
		Store:       cfg.Store,
		Logger:      cfg.Logger,
		Instruments: instruments,
	})
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewFeedHandler: %w", err)
	}

	postWithMiddleware := wrapRateLimit(
		postHandler,
		cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.Logger,
	)
	feedWithMiddleware := wrapRateLimit(
		feedHandler,
		cfg.FeedRateLimitRPS, cfg.RateLimitBurst, cfg.Logger,
	)

	closeables := []sdkgossip.Closeable{}
	if sinkClose != nil {
		closeables = append(closeables, sinkClose)
	}
	closeables = append(closeables, postHandler, feedHandler)

	return &Bundle{
		PostHandler: postWithMiddleware,
		FeedHandler: feedWithMiddleware,
		Sink:        sink,
		Verifier:    verifier,
		Closeables:  closeables,
	}, nil
}

func buildVerifier(cfg Config) (*RotationCachedVerifier, error) {
	registry := did.NewVerifierRegistry()
	if err := registry.Register("key", did.NewKeyVerifier()); err != nil {
		return nil, fmt.Errorf("gossipnet: register did:key: %w", err)
	}
	base, err := sdkgossip.NewDIDOriginatorVerifier(registry)
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewDIDOriginatorVerifier: %w", err)
	}

	opts := []sdkgossip.CachedOption{}
	if cfg.VerifierCacheTTL > 0 {
		opts = append(opts, sdkgossip.WithCachedTTL(cfg.VerifierCacheTTL))
	}
	if cfg.VerifierCacheSize > 0 {
		opts = append(opts, sdkgossip.WithCachedMaxEntries(cfg.VerifierCacheSize))
	}
	cached, err := sdkgossip.NewCachedDIDOriginatorVerifier(base, opts...)
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewCachedDIDOriginatorVerifier: %w", err)
	}
	keyMgr, err := sdkgossip.NewInMemoryKeyManager(cached)
	if err != nil {
		return nil, fmt.Errorf("gossipnet: NewInMemoryKeyManager: %w", err)
	}
	return &RotationCachedVerifier{keyMgr: keyMgr, cached: cached}, nil
}

func buildSink(cfg Config, instruments *sdkgossip.Instruments) (sdkgossip.Sink, sdkgossip.Closeable, error) {
	if len(cfg.PeerEndpoints) == 0 {
		return sdkgossip.NopSink, nil, nil
	}
	// v1.34 contract: when there are peer endpoints to fan out to,
	// the caller MUST supply a configured *http.Client. The SDK no
	// longer manufactures a plaintext default (baseproof v1.34
	// CHANGELOG); we don't either. The boot wiring at
	// cmd/ledger/boot/wire/wire.go always populates
	// d.OutboundHTTPClient, so a nil here means a programming error
	// in a caller that constructed gossipnet.Config{} by hand —
	// fail-closed with a clear directive.
	if cfg.HTTPClient == nil {
		return nil, nil, fmt.Errorf("gossipnet: HTTPClient required when PeerEndpoints is non-empty (pass cfg.HTTPClient — the SDK no longer manufactures a plaintext default)")
	}
	peerSinks := make([]sdkgossip.Sink, 0, len(cfg.PeerEndpoints))
	for _, ep := range cfg.PeerEndpoints {
		client, err := sdkgossip.NewClient(ep, sdkgossip.WithHTTPClient(cfg.HTTPClient))
		if err != nil {
			return nil, nil, fmt.Errorf("gossipnet: NewClient(%s): %w", ep, err)
		}
		sink, err := sdkgossip.NewHTTPSink(client)
		if err != nil {
			return nil, nil, fmt.Errorf("gossipnet: NewHTTPSink(%s): %w", ep, err)
		}
		peerSinks = append(peerSinks, sink)
	}
	multiOpts := []sdkgossip.MultiSinkOption{}
	if instruments != nil {
		multiOpts = append(multiOpts, sdkgossip.WithMultiSinkInstruments(instruments))
	}
	multi, err := sdkgossip.NewMultiSink(peerSinks, multiOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("gossipnet: NewMultiSink: %w", err)
	}

	queueSize := cfg.SinkQueueSize
	if queueSize <= 0 {
		queueSize = DefaultSinkQueueSize
	}
	buffered, err := sdkgossip.NewBufferedSink(sdkgossip.BufferedSinkConfig{
		Underlying:  multi,
		QueueSize:   queueSize,
		Workers:     1,
		Policy:      sdkgossip.DropPolicyDropOldest,
		Logger:      cfg.Logger,
		Instruments: instruments,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("gossipnet: NewBufferedSink: %w", err)
	}
	return buffered, buffered, nil
}

func wrapRateLimit(h http.Handler, rps float64, burst int, logger *slog.Logger) http.Handler {
	if rps < 0 {
		return h
	}
	cfg := middleware.RateLimitConfig{
		RatePerSecond: rps,
		BurstSize:     burst,
	}
	return middleware.NewRateLimitMiddleware(cfg)(h)
}
