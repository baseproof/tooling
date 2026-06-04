/*
Package gossipingest is the reusable inbound-gossip pipeline: pull from peers'
/v1/gossip/since feeds → verify (envelope + finding proof) → reconcile against
the trusted-heads store → persist to the caller's gossip.Store.

WHY THIS PACKAGE EXISTS

	Every network that ingests cross-log gossip wires the SAME components
	in the SAME order:

	  gossipverify.NewGossipVerifier(...)
	  gossipverify.NewWitnessSetRegistry(...)
	  monitoring.NewTrustedHeadStore(...)
	  monitoring.NewReconciler(...)
	  peers.NewPeerPuller(...)

	Until now there were two implementations — one in
	services/auditor/internal/app/app.go and one in JN's
	cmd/network-api/gossip_reconciler.go — each subtly different and
	each making different mistakes (the JN's wiring forgot to pass
	HTTPClient to NewPeerPuller; the auditor's wiring missed mTLS on
	the tile mirrors). gossipingest is the one place this scaffold lives.

	Future networks call Build(Config{...}) and inherit the verified-then-
	persisted contract — no reimplementation, no per-network drift.

WHAT THE PIPELINE OWNS

	The CORE — verifier, reconciler, puller, trusted-head store — is the
	zero-trust receive path the SDK's gossip semantics require. It is
	identical across consumers; gossipingest owns it.

	Aux behaviors that vary per consumer stay in the consumer:
	  - Equivocation responder (caller-built; injected as optional
	    EquivocationResponder on Config)
	  - Tile mirrors for cross-log inclusion proofs (caller-built; passed
	    via Config.Tiles — gossipverify.TileFetcherSource)
	  - Scheduler / horizon audit / retention prune (caller registers jobs
	    on its own monitoring.Scheduler — gossipingest doesn't own
	    long-running goroutines beyond what PeerPuller starts on Run)
	  - Feed mount (the read-side HTTP handler that serves the persisted
	    store — caller composes whatever HTTP surface it likes)

WHAT THE PIPELINE REQUIRES

	Config validates at construction. Every field marked Required (see the
	docstrings) must be non-nil/non-empty or Build returns
	ErrInvalidConfig wrapping the missing-field name. v1.27.x posture: no
	silent defaults, no plaintext fallback. The HTTPClient field in
	particular MUST be the binary's hoisted outbound client (build via
	clienttls.BuildFromEnv); a nil client closes the door on every mTLS
	posture decision the operator made.

v1.32.0 AUDITOR-SCOPE GATE (T3.1)

	Config.AuditorRegistry threads the on-log AuditorRegistrationV1 record
	slice through to monitoring.NewReconciler. When non-nil, the
	reconciler rejects every verified finding-class event whose originator
	isn't registered as an auditor at AuditorScopeAsOf (or whose Scope
	mask doesn't cover the event Kind). The check is symmetric to the
	ledger's gossipnet/auditor_scope_gate.go — same v1.32.0 L5
	authorization gate on the symmetric ingest path.

	nil PRESERVES the pre-v1.32 behavior — existing deployments compile
	and run unchanged until operators opt in by populating AuditorRegistry
	(typically via crosslog.MaterializeFromEntries + an on-log scan).
*/
package gossipingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/auditing/gossipverify"
	"github.com/baseproof/tooling/libs/auditing/peers"
	"github.com/baseproof/tooling/libs/monitoring"
)

// ErrInvalidConfig is returned by Build when a required field is missing.
var ErrInvalidConfig = errors.New("gossipingest: invalid Config")

// Config wires the inbound pipeline. Every field marked Required is
// validated at Build time; v1.27.x posture forbids silent defaults.
type Config struct {
	// HTTPClient is the binary's hoisted outbound *http.Client (built
	// once at boot via clienttls.BuildFromEnv). Threaded into
	// peers.NewPeerPuller so every peer-feed pull uses the same
	// transport posture (mTLS material, timeout, retry, pool) as the
	// rest of the binary's outbound surfaces. REQUIRED.
	HTTPClient *http.Client

	// Peers is the operator-pinned allowlist of peer feeds to pull.
	// REQUIRED (an empty slice is valid — the puller starts with no
	// feeds and waits for ctx cancel; useful in tests).
	Peers []peers.PeerFeed

	// NetworkID is the 32-byte network identity every cosigned head
	// must bind to. REQUIRED. Resolved at boot from the bootstrap
	// document; mismatched IDs cause envelope verification to reject
	// every finding.
	NetworkID cosign.NetworkID

	// WitnessSets maps each gossip-originator did:key to its K-of-N
	// witness key set. REQUIRED to be non-nil (an empty map is valid
	// — every finding will fail "no witness set for originator"
	// verification, which is the correct behavior pre-bootstrap).
	WitnessSets map[string]*cosign.WitnessKeySet

	// DIDRegistry resolves originator + signer DIDs (did:key / did:web /
	// did:pkh) into verifiers. REQUIRED.
	DIDRegistry *did.VerifierRegistry

	// Store is the caller's durable evidence store. Every verified
	// finding persists here. REQUIRED. The auditor implements this
	// over Postgres; tests can stub via an in-memory store.
	Store gossip.Store

	// Tiles is the cross-log tile source for ClassMerkle findings.
	// Optional — pass nil if the deployment does not verify cross-log
	// inclusion proofs. When non-nil, callers MUST construct the
	// underlying mirrors with the binary's hoisted HTTPClient (see
	// gossipverify.NewHTTPTileMirrors); pipeline does not build them
	// for you because the per-mirror endpoint list is deployment-specific.
	Tiles gossipverify.TileFetcherSource

	// Equivocation is the optional slashing responder routed in by the
	// caller. nil disables slashing — findings are still verified +
	// persisted, just not slashed. The auditor wires this; pure read-
	// only consumers don't.
	Equivocation *monitoring.EquivocationResponder

	// RotationJournal durably records each verified witness-set rotation as a
	// position-bearing record (the historical rotation chain), so
	// witness.WitnessSetAt can reconstruct the set authoritative at any asOf
	// years later (ZT-SCN-02). Optional; nil ⇒ rotations advance the live
	// trust root but are not journaled (no historical reconstruction). The
	// auditor wires *store.PostgresWitnessRotationJournal.
	RotationJournal monitoring.RotationJournal

	// WitnessSetResolver makes CosignedTreeHeadFinding verification POSITION-
	// AWARE: a finding's head is verified against the set that COSIGNED it
	// (reconstructed from the log), not the position-blind current-set snapshot —
	// the fix for a historical (year-1) head being mis-checked against the
	// modern, rotated-away set (ZT-SCN-02). Optional; nil PRESERVES the legacy
	// snapshot behavior. The auditor wires *store.HistoricalResolverRegistry.
	WitnessSetResolver gossipverify.HeadWitnessSetResolver

	// PollInterval governs the per-peer catch-up cadence. 0 → puller
	// defaults (5s; see peers.NewPeerPuller).
	PollInterval time.Duration

	// PageLimit caps events per /since page. 0 → puller defaults
	// (256; see peers.NewPeerPuller).
	PageLimit int

	// Logger is the slog.Logger used by the verifier, reconciler, and
	// puller. nil → slog.Default().
	Logger *slog.Logger

	// AuditorRegistry is the v1.32.0 on-log AuditorRegistrationV1 record
	// slice the inbound scope gate dispatches against. When non-nil,
	// monitoring.Reconciler rejects every verified finding-class event
	// whose originator isn't registered as an auditor at
	// AuditorScopeAsOf — or whose Scope mask doesn't cover the event
	// Kind.
	//
	// nil PRESERVES the pre-v1.32 ingest behavior. The audit's D7
	// backward-compat env var (AUDITOR_ENFORCE_SCOPES, wired in the
	// auditor's main) toggles whether this field is populated or left
	// nil during rollout.
	//
	// Typically built via crosslog.BuildAuditorRegistryFromConfig (the
	// operator's deployment manifest — sorted in v1.33.1+ at the
	// constructor) or crosslog.MaterializeFromEntries (a fresh on-log
	// scan; also sorted). The SDK's ResolveAuditorAt 4-arg signature
	// returns ErrAuditorRecordsUnsorted on unsorted input — the gate
	// surfaces this with reason="registry unsorted (operator config
	// bug)" (Ladder 1 B1).
	AuditorRegistry network.AuditorRegistrationByPosition

	// AuditorAmendments is the v1.33.x on-log AuditorScopeAmendmentV1
	// record slice the scope gate merges with the registration stream
	// when resolving an auditor at a position (SDK Gap 2). Optional —
	// nil means "no amendments published yet", equivalent to v1.32.0
	// registration-only behavior. The slice MUST be sorted by
	// EffectivePos ascending (same contract as AuditorRegistry); the
	// gate's unsorted-reason path applies symmetrically.
	//
	// Typically populated from crosslog.MaterializeFromEntries
	// (the on-log scan path) or from a separate operator manifest via
	// app.LoadAuditorAmendmentsFromFile.
	AuditorAmendments network.AuditorScopeAmendmentByPosition

	// AuditorScopeAsOf returns the LogPosition the scope gate uses for
	// its network.ResolveAuditorAt asOf argument. nil ⇒ zero LogPosition
	// (every record in AuditorRegistry treated as in-effect; appropriate
	// when the registry was assembled from a fully-walked snapshot).
	AuditorScopeAsOf func(ctx context.Context) types.LogPosition

	// MaxInFlightVerify caps the concurrency of HandleSignedEvent calls
	// from the Puller into the Reconciler. 0 (default) disables the
	// throttle — preserves the pre-Ladder-5 unbounded-concurrency
	// behavior. >0 wraps the Reconciler in a Throttler with this
	// capacity; at sustained 1K+ TPS with a slow-verify state, the
	// throttle gives natural backpressure to the puller instead of
	// letting the verify backlog grow unboundedly inside the puller's
	// pollPeer loops.
	//
	// Sizing rule of thumb: 2 × (DB pool max) or 4 × (vCPU count),
	// bounded above by RAM / per-event allocation. See
	// libs/gossipingest/throttle.go for the rationale.
	MaxInFlightVerify int
}

// Pipeline is the constructed inbound graph: the puller (caller runs it),
// the verifier, the reconciler (the puller's sink), and the trusted-heads
// store the reconciler advances. Callers typically:
//
//	pipe, err := gossipingest.Build(cfg)
//	if err != nil { ... }
//	go pipe.Puller.Run(ctx)
//	// expose pipe.Heads to a read-side handler if you want operators to
//	// see the trusted state
type Pipeline struct {
	// Puller pulls per-peer /v1/gossip/since feeds and hands every raw
	// (unverified) event to Reconciler. Goroutine: callers invoke
	// pipe.Puller.Run(ctx) on a background goroutine.
	Puller *peers.PeerPuller

	// Verifier is the zero-trust verify engine the Reconciler consumes.
	// Exposed so callers can serve diagnostic endpoints or hot-rebind
	// trust roots (verify-before-swap rotation) via the WitnessSetRegistry.
	Verifier *gossipverify.GossipVerifier

	// Reconciler is the SignedEventSink the Puller feeds. It runs the
	// verify-then-act pipeline: envelope verify → finding-proof verify
	// → advance heads → equivocation route → persist.
	Reconciler *monitoring.Reconciler

	// Heads is the trusted-head store the Reconciler advances on each
	// successful cosigned-head finding. Exposed so the caller can serve
	// a read-only handler (the auditor's "what does my trusted-state
	// look like right now" surface).
	Heads *monitoring.TrustedHeadStore

	// WitnessSets is the live witness-set registry the verifier consults
	// for every cosigned-head check. Exposed so callers can pass it as
	// the Rotator into a higher-level Reconciler (Tier-2 rotation),
	// surface its state on an /admin endpoint, or refresh it from a
	// bootstrap watcher.
	WitnessSets *gossipverify.WitnessSetRegistry

	// Throttler is non-nil when Config.MaxInFlightVerify > 0. Exposed
	// so the caller can register an OTel observable gauge against
	// Throttler.Saturation() — useful as a K8s HPA custom metric
	// source. nil when the throttle is disabled (the default).
	Throttler *Throttler
}

// Build constructs the pipeline from cfg. Validates every required field;
// failure returns ErrInvalidConfig wrapping the specific missing field.
//
// On success, the returned Pipeline's Puller is NOT yet running — the
// caller starts it with pipe.Puller.Run(ctx) on a goroutine. This
// separation lets callers compose the pipeline alongside additional
// goroutines (schedulers, feed handlers) without gossipingest taking
// ownership of process-level concurrency.
func Build(cfg Config) (*Pipeline, error) {
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("%w: HTTPClient is required (thread the binary's hoisted outbound client; build via clienttls.BuildFromEnv)", ErrInvalidConfig)
	}
	if cfg.DIDRegistry == nil {
		return nil, fmt.Errorf("%w: DIDRegistry is required", ErrInvalidConfig)
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: Store is required", ErrInvalidConfig)
	}
	if cfg.WitnessSets == nil {
		return nil, fmt.Errorf("%w: WitnessSets map is required (empty map is valid — every finding will fail 'no witness set' verification, which is the correct pre-bootstrap behavior; nil is a programmer error)", ErrInvalidConfig)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	originator, err := gossip.NewDIDOriginatorVerifier(cfg.DIDRegistry)
	if err != nil {
		return nil, fmt.Errorf("gossipingest: originator verifier: %w", err)
	}
	registry := gossipverify.NewWitnessSetRegistry(cfg.WitnessSets, cfg.NetworkID)
	heads := monitoring.NewTrustedHeadStore(cfg.Logger)

	verifier, err := gossipverify.NewGossipVerifier(gossipverify.GossipVerifierConfig{
		Originator:     originator,
		NetworkID:      cfg.NetworkID,
		WitnessSets:    registry,
		SignerVerifier: cfg.DIDRegistry,
		Heads:          heads,
		Tiles:          cfg.Tiles,
		Resolver:       cfg.WitnessSetResolver,
	})
	if err != nil {
		return nil, fmt.Errorf("gossipingest: verifier: %w", err)
	}

	reconciler, err := monitoring.NewReconciler(monitoring.ReconcilerConfig{
		Verifier:          verifier,
		Heads:             heads,
		Equivocation:      cfg.Equivocation,
		Rotator:           registry,
		RotationJournal:   cfg.RotationJournal,
		Store:             cfg.Store,
		Logger:            cfg.Logger,
		AuditorRegistry:   cfg.AuditorRegistry,
		AuditorAmendments: cfg.AuditorAmendments,
		AuditorScopeAsOf:  cfg.AuditorScopeAsOf,
	})
	if err != nil {
		return nil, fmt.Errorf("gossipingest: reconciler: %w", err)
	}

	// Ladder 5 P9 (#21): when MaxInFlightVerify > 0, wrap the
	// reconciler in a Throttler so the puller's per-event delivery
	// is bounded-concurrency. 0 preserves the pre-Ladder-5 unbounded
	// behavior — operators opt in via the env-var-fed
	// MaxInFlightVerify field. The Throttler is exposed on the
	// returned Pipeline so the caller can register an OTel observable
	// gauge against its Saturation() method.
	var sink peers.SignedEventSink = reconciler
	var throttler *Throttler
	if cfg.MaxInFlightVerify > 0 {
		throttler, err = NewThrottler(reconciler, cfg.MaxInFlightVerify, cfg.Logger)
		if err != nil {
			return nil, fmt.Errorf("gossipingest: throttler: %w", err)
		}
		sink = throttler
	}

	puller, err := peers.NewPeerPuller(peers.PeerPullerConfig{
		Peers:      cfg.Peers,
		Sink:       sink,
		Interval:   cfg.PollInterval,
		PageLimit:  cfg.PageLimit,
		HTTPClient: cfg.HTTPClient,
		Logger:     cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("gossipingest: peer puller: %w", err)
	}

	return &Pipeline{
		Puller:      puller,
		Verifier:    verifier,
		Reconciler:  reconciler,
		Heads:       heads,
		WitnessSets: registry,
		Throttler:   throttler,
	}, nil
}
