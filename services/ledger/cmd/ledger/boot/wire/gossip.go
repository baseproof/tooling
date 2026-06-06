// Gossip wiring.
//
// FILE PATH:
//
//	cmd/ledger/boot/wire/gossip.go
//
// DESCRIPTION:
//
//	wireGossip builds the gossipnet.Bundle, the STH publisher, and
//	the three async observers that ride on top of the bundle: the
//	anti-entropy puller, the equivocation monitor (peer STH
//	divergence), and the equivocation scanner (entry-level split-id
//	collisions).
//
//	All three observers join d.WG so teardown's
//	"background-goroutines" step waits on them once.
//
//	When d.GossipStore is nil (gossip disabled at alloc time) wireGossip
//	returns nil immediately — no Bundle / Publisher set.
package wire

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"

	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/deps"
	"github.com/baseproof/tooling/services/ledger/gossipnet"
	"github.com/baseproof/tooling/services/ledger/lifecycle"
	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/tessera"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// wireGossip builds the gossipnet.Bundle, STH publisher, and starts
// the three async observers. No-op when d.GossipStore is nil.
func wireGossip(ctx context.Context, cfg Config, d *deps.AppDeps) error {
	if d.GossipStore == nil {
		d.Logger.Info("gossip: not wired (no gossip store from alloc)")
		return nil
	}
	bundle, err := gossipnet.Build(gossipnet.Config{
		Store:         d.GossipStore,
		NetworkID:     cfg.NetworkID,
		PeerEndpoints: cfg.GossipPeerEndpoints,
		Meter:         d.GossipMeter,
		Logger:        d.Logger,
		// nil ⇒ SDK default per-peer gossip client. Non-nil ⇒ every
		// per-peer gossip client (sink, fan-out, verifier replay)
		// presents this binary's client cert.
		HTTPClient: d.OutboundHTTPClient,
		// v1.32.0 L5 backdoor closure + v1.33.0 Gap 2/3 adoption:
		// pass the on-log auditor registration + amendment sources
		// through to gossipnet.Build so the AuditorScopeGate is
		// constructed with both streams. Nil-tolerant — if boot did
		// not populate them (no schema env vars), the gate's wiring
		// branch in gossipnet/wiring.go reverts to fail-closed.
		AuditorRegistrySource:  gossipnet.AuditorRegistrySource(d.AuditorRegistrySource),
		AuditorAmendmentSource: gossipnet.AuditorAmendmentSource(d.AuditorAmendmentSource),
	})
	if err != nil {
		return fmt.Errorf("gossipnet build: %w", err)
	}
	d.GossipBundle = bundle

	// Register the bundle's Closeables onto the closeStack BEFORE the
	// gossip-store closer that alloc registered — so unwind closes
	// the bundle's Sink before the underlying Badger handle.
	for _, cl := range bundle.Closeables {
		clClose := cl.Close
		d.AppendCloser(deps.NamedCloser{
			Name:    "gossip-bundle-closeable",
			Timeout: 5 * time.Second,
			Close: func(ctx context.Context) error {
				return clClose(ctx)
			},
		})
	}

	// STH publisher: signs KindCosignedTreeHead under the ledger DID.
	pub, err := gossipnet.NewSTHPublisher(gossipnet.PublisherConfig{
		Store:          d.GossipStore,
		Sink:           bundle.Sink,
		Signer:         cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
		NetworkID:      cfg.NetworkID,
		Originator:     cfg.LedgerDID,
		LedgerEndpoint: cfg.ServerAddr,
		Logger:         d.Logger,
	})
	if err != nil {
		return fmt.Errorf("gossip STH publisher: %w", err)
	}
	d.GossipPublisher = pub

	d.Logger.Info("gossip endpoints mounted",
		"post_path", "/v1/gossip",
		"feed_path_prefix", "/v1/gossip/",
		"peers", len(cfg.GossipPeerEndpoints),
	)

	// Anti-entropy + equivocation monitor + equivocation scanner.
	startGossipObservers(ctx, cfg, d, bundle, pub)
	return nil
}

// startGossipObservers spawns the three async gossip goroutines. Each
// joins d.WG.
func startGossipObservers(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	bundle *gossipnet.Bundle,
	pub *gossipnet.STHPublisher,
) {
	// Anti-entropy.
	if len(cfg.GossipPeerDIDs) > 0 && len(cfg.GossipPeerDIDs) == len(cfg.GossipPeerEndpoints) {
		peers := make([]gossipnet.AntiEntropyPeer, 0, len(cfg.GossipPeerDIDs))
		for i, did := range cfg.GossipPeerDIDs {
			peers = append(peers, gossipnet.AntiEntropyPeer{
				DID:     did,
				BaseURL: cfg.GossipPeerEndpoints[i],
			})
		}
		ae, aerr := gossipnet.NewAntiEntropy(gossipnet.AntiEntropyConfig{
			Store:  d.GossipStore,
			Peers:  peers,
			Logger: d.Logger,
			// nil ⇒ sdklog.DefaultClient(20s). Non-nil ⇒ every peer
			// gossip-pull presents this binary's client cert.
			HTTPClient: d.OutboundHTTPClient,
		})
		if aerr == nil {
			lifecycle.SafeRunInWG(ctx, &d.WG, "anti-entropy", d.Logger, d.Fatal, func() error {
				if rerr := ae.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
					d.Logger.Warn("anti-entropy: exited with error", "error", rerr)
				}
				return nil
			})
			d.Logger.Info("anti-entropy: enabled", "peers", len(peers))
		} else {
			d.Logger.Warn("anti-entropy: construction failed", "error", aerr)
		}
	} else if len(cfg.GossipPeerDIDs) > 0 {
		d.Logger.Warn("anti-entropy: disabled (peer DID/endpoint length mismatch)",
			"dids", len(cfg.GossipPeerDIDs),
			"endpoints", len(cfg.GossipPeerEndpoints))
	}

	// Equivocation monitor.
	if len(cfg.GenesisWitnessSet) > 0 &&
		len(cfg.GossipPeerDIDs) > 0 &&
		len(cfg.GossipPeerDIDs) == len(cfg.GossipPeerEndpoints) &&
		pub != nil {
		startEquivocationMonitor(ctx, cfg, d, bundle)
	} else {
		d.Logger.Info("equivocation monitor: disabled (missing prerequisites)",
			"genesis_witness_set", len(cfg.GenesisWitnessSet),
			"peer_dids", len(cfg.GossipPeerDIDs),
			"peer_endpoints", len(cfg.GossipPeerEndpoints),
			"publisher_wired", pub != nil,
		)
	}

	// Equivocation scanner (entry-level).
	startEquivocationScanner(ctx, cfg, d, bundle)

	// Witness-rotation handler. Built when the genesis witness set
	// + NetworkID are configured; the SDK emitter is wired when the
	// gossip Sink is available, falling back to the logging emitter
	// otherwise. The handler stays nil if prerequisites are missing
	// — callers grep d.RotationHandler == nil to know they're in
	// a gossip-disabled deployment.
	wireRotationHandler(ctx, cfg, d, bundle)
}

// wireWitnessQuorum seeds the single shared witness-keyset Manager that
// the admission BLS-quorum verifier, the equivocation monitor, and the
// rotation handler all read. Source of truth: the latest set persisted
// in PG (a prior rotation already landed there), falling back to the
// genesis config on first boot. Leaves d.QuorumManager nil when the
// deployment has no genesis witness set or a zero NetworkID — every
// consumer treats nil as "quorum gate unavailable" and degrades
// accordingly.
//
// This is the ONE place the witness keyset is constructed (previously
// three sites built their own copies, which then went stale after a
// rotation). quorum.NewKeySet selects the cosign verifier from the
// network's signature policy (GenesisSignaturePolicy.AllowedCosignSchemeTags):
// a BLS-admitting policy wires the production BLS verifier so a BLS witness's
// cosignature (and its key's proof-of-possession) is fully verified; an
// ECDSA-only policy stays verifier-free (a stray BLS-tagged cosignature is
// rejected with cosign.ErrBLSVerifierRequired). No ripple into the consumers —
// they read the set via the shared Manager, and a BLS witness joins on-log via
// a verified rotation that inherits this verifier (cur.BLSVerifier()).
func wireWitnessQuorum(ctx context.Context, cfg Config, d *deps.AppDeps) error {
	if len(cfg.GenesisWitnessSet) == 0 || cfg.NetworkID == (cosign.NetworkID{}) {
		d.Logger.Info("witness quorum: disabled (missing genesis witness set or NetworkID)",
			"genesis_witness_set", len(cfg.GenesisWitnessSet),
			"network_id_zero", cfg.NetworkID == (cosign.NetworkID{}),
		)
		return nil
	}

	// Prefer the latest set persisted in PG (a prior rotation already
	// landed there); fall back to the genesis config on first boot.
	keys, schemeTag, err := witnessclient.LoadCurrentSet(ctx, d.PgPool.DB)
	if err != nil {
		keys, err = quorum.LoadWitnessKeys(cfg.GenesisWitnessSet)
		if err != nil {
			return fmt.Errorf("witness quorum: resolve genesis keys: %w", err)
		}
		schemeTag = 0x01 // bootstrap scheme: ECDSA
	}

	// Enforce the network's allowed cosign-scheme policy on the active witness
	// set BEFORE building the keyset: every witness's declared cosign scheme must
	// be admitted by GenesisSignaturePolicy.AllowedCosignSchemeTags, else its
	// cosignatures are inadmissible under the network's policy. A genesis (or a
	// PG-persisted rotation) that mixes a witness using a forbidden scheme with a
	// stricter policy is a self-inconsistent configuration and must fail boot, not
	// silently admit the forbidden scheme.
	if err = quorum.ValidateCosignSchemePolicy(
		keys, cfg.GenesisBootstrapDocument.GenesisSignaturePolicy.AllowedCosignSchemeTags,
	); err != nil {
		return fmt.Errorf("witness quorum: %w", err)
	}

	set, err := quorum.NewKeySet(keys, cfg.NetworkID, cfg.WitnessQuorumK,
		cfg.GenesisBootstrapDocument.GenesisSignaturePolicy.AllowedCosignSchemeTags)
	if err != nil {
		return fmt.Errorf("witness quorum: build key set: %w", err)
	}

	d.QuorumManager = quorum.NewManager(set)
	d.WitnessSchemeTag = schemeTag
	d.Logger.Info("witness quorum: seeded",
		"witness_set_size", set.Size(),
		"quorum_k", set.Quorum(),
		"scheme_tag", schemeTag,
	)
	return nil
}

// wireRotationHandler constructs the witnessclient.RotationHandler
// + SDK emitter and stores them on d.AppDeps. nil when the witness
// quorum manager wasn't seeded (no genesis set + NetworkID). The
// handler is the consumer-facing entrypoint that future admin /
// inbound-gossip paths call when a rotation message arrives; today
// it's instantiated but has no caller — that's intentional, the SDK
// v0.7.0 alignment shipping here exposes the surface for the upcoming
// inbound-rotation consumer to wire against. On rotation it calls
// d.QuorumManager.Update, so admission + the equivocation monitor
// observe the new set immediately.
func wireRotationHandler(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	bundle *gossipnet.Bundle,
) {
	if d.QuorumManager == nil {
		d.Logger.Info("rotation handler: disabled (no witness quorum manager)")
		return
	}

	handler := witnessclient.NewRotationHandler(
		d.PgPool.DB,
		d.QuorumManager,
		d.WitnessSchemeTag,
		cfg.ServerAddr, // mirrors the STHPublisher's LedgerEndpoint convention
		d.Logger,
	).WithCosignSchemePolicy(
		// Same allowed-cosign-scheme policy enforced on the genesis set at boot;
		// a rotation that introduces a witness using a disallowed scheme is
		// rejected before it is committed on-log.
		cfg.GenesisBootstrapDocument.GenesisSignaturePolicy.AllowedCosignSchemeTags,
	)

	// 1.2b: refresh the witness-rotation INDEX archive after each applied rotation, so
	// a PG-off read front reconstructs FetchWitnessRotationChain. Object-store
	// deployments only (PutObject — the S3/SeaweedFS standard interface).
	if s3, ok := d.ByteStore.(*bytestore.S3); ok {
		handler.WithRotationIndexArchiver(store.NewRotationIndexArchiveJob(d.PgPool.DB, s3))
	}

	// SDK gossip emitter when the Sink is available; logging
	// emitter when gossip is otherwise unwired (single-ledger
	// dev / integration tests).
	if bundle != nil && bundle.Sink != nil {
		emitter, eerr := gossipnet.NewSDKGossipWitnessRotationEmitter(
			gossipnet.SDKGossipWitnessRotationEmitterConfig{
				GossipStore: d.GossipStore,
				Sink:        bundle.Sink,
				Signer:      cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
				NetworkID:   cfg.NetworkID,
				Originator:  cfg.LedgerDID,
				Logger:      d.Logger,
			})
		if eerr != nil {
			d.Logger.Error("rotation handler: SDK emitter construction failed; "+
				"falling back to logging emitter",
				"error", eerr)
			handler.WithEmitter(witnessclient.NewLoggingWitnessRotationEmitter(d.Logger))
		} else {
			handler.WithEmitter(emitter)
		}
	} else {
		handler.WithEmitter(witnessclient.NewLoggingWitnessRotationEmitter(d.Logger))
	}

	// On-log appender: commits each rotation as a SEQUENCED, witness-cosigned
	// entry and returns its intrinsic position + inclusion proof (ZT-WIT-07).
	// Requires the full sequencing pipeline (WAL → sequencer → Tessera →
	// cosign) plus the ledger signer. When any piece is missing (degraded /
	// dev boot), the appender stays unwired and ProcessRotation fails closed
	// rather than persisting an unprovable position.
	if d.LedgerSignerPriv != nil && d.WALCommitter != nil && d.EntryStore != nil &&
		d.TreeHeadStore != nil && d.TesseraEmbedded != nil && d.TileReader != nil {
		proofs := tessera.NewTesseraAdapter(ctx, d.TesseraEmbedded, d.TileReader, d.Logger)
		handler.WithAppender(witnessclient.NewProductionRotationAppender(
			d.LedgerSignerPriv,
			cfg.LedgerDID, // ControlHeader.SignerDID
			cfg.LogDID,    // ControlHeader.Destination + LogPosition.LogDID
			d.QuorumManager,
			d.WALCommitter,
			d.EntryStore,
			d.TreeHeadStore,
			proofs,
			d.Logger,
		))
		d.Logger.Info("rotation handler: on-log appender wired (rotations commit on-log)")
	} else {
		d.Logger.Warn("rotation handler: on-log appender NOT wired (missing pipeline deps); " +
			"ProcessRotation fails closed until the sequencing pipeline + ledger signer are available")
	}

	d.RotationHandler = handler
	setSize, quorumK := 0, 0
	if cur := d.QuorumManager.Current(); cur != nil {
		setSize, quorumK = cur.Size(), cur.Quorum()
	}
	d.Logger.Info("rotation handler: wired",
		"current_set_size", setSize,
		"quorum_k", quorumK,
		"scheme_tag", d.WitnessSchemeTag,
		"gossip_emitter", bundle != nil && bundle.Sink != nil,
	)
}

func startEquivocationMonitor(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	bundle *gossipnet.Bundle,
) {
	if d.QuorumManager == nil {
		d.Logger.Info("equivocation monitor: disabled (no witness quorum manager)")
		return
	}
	equivPub, perr := gossipnet.NewEquivocationPublisher(gossipnet.EquivocationPublisherConfig{
		Store:      d.GossipStore,
		Sink:       bundle.Sink,
		Signer:     cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
		NetworkID:  cfg.NetworkID,
		Originator: cfg.LedgerDID,
		Logger:     d.Logger,
	})
	if perr != nil {
		d.Logger.Error("equivocation publisher", "error", perr)
		return
	}
	equivPeers := make([]gossipnet.AntiEntropyPeer, 0, len(cfg.GossipPeerDIDs))
	for i, did := range cfg.GossipPeerDIDs {
		equivPeers = append(equivPeers, gossipnet.AntiEntropyPeer{
			DID:     did,
			BaseURL: cfg.GossipPeerEndpoints[i],
		})
	}
	eqMon, eerr := gossipnet.NewEquivocationMonitor(gossipnet.EquivocationMonitorConfig{
		Store:       d.GossipStore,
		Peers:       equivPeers,
		WitnessKeys: d.QuorumManager,
		Publisher:   equivPub,
		Logger:      d.Logger,
		// nil ⇒ sdklog.DefaultClient(20s). Non-nil ⇒ every peer head
		// scan presents this binary's client cert.
		HTTPClient: d.OutboundHTTPClient,
	})
	if eerr != nil {
		d.Logger.Error("equivocation monitor", "error", eerr)
		return
	}
	lifecycle.SafeRunInWG(ctx, &d.WG, "equivocation-monitor", d.Logger, d.Fatal, func() error {
		if rerr := eqMon.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
			d.Logger.Warn("equivocation monitor: exited with error", "error", rerr)
		}
		return nil
	})
	setSize, quorumK := 0, 0
	if cur := d.QuorumManager.Current(); cur != nil {
		setSize, quorumK = cur.Size(), cur.Quorum()
	}
	d.Logger.Info("equivocation monitor: enabled",
		"peers", len(equivPeers),
		"quorum_k", quorumK,
		"witness_set_size", setSize,
	)
}

func startEquivocationScanner(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	bundle *gossipnet.Bundle,
) {
	if d.GossipStore == nil || bundle == nil {
		return
	}
	scanner, scerr := gossipnet.NewEquivocationScanner(
		gossipnet.EquivocationScannerConfig{
			Store:       d.GossipStore,
			GossipStore: d.GossipStore,
			Sink:        bundle.Sink,
			Signer:      cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
			NetworkID:   cfg.NetworkID,
			Originator:  cfg.LedgerDID,
			Logger:      d.Logger,
		})
	if scerr != nil {
		d.Logger.Error("equivocation scanner construction", "error", scerr)
		return
	}
	lifecycle.SafeRunInWG(ctx, &d.WG, "equivocation-scanner", d.Logger, d.Fatal, func() error {
		if rerr := scanner.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
			d.Logger.Warn("equivocation scanner: exited with error", "error", rerr)
		}
		return nil
	})
	d.Logger.Info("equivocation scanner: enabled (subscribed to splitid index 0x0A)")
}

// wireWitnessCosigner builds the HeadSync requester (witness cosigner)
// when EITHER the on-log endpoint resolver returns a non-empty witness
// set OR LEDGER_WITNESS_ENDPOINTS (legacy canary fallback) is set; nil
// otherwise. The returned *witnessclient.HeadSync satisfies
// builder.WitnessCosigner and is fed into the BuilderLoop.
//
// v1.32.0 backdoor closure (L1 in the SDK adoption plan): pre-v1.32.0
// the witness URL list came exclusively from LEDGER_WITNESS_ENDPOINTS
// (config — an operator-edit-and-reload away from the silent URL
// substitution attack the SDK's WitnessEndpointDeclarationV1 was
// designed to prevent). Post-v1.32.0 the authoritative source is the
// on-log resolver populated from WitnessEndpointDeclarationV1 records;
// the config slice remains as a CANARY FALLBACK for the bootstrap
// window before any declaration entry has been admitted + cosigned.
func wireWitnessCosigner(cfg Config, d *deps.AppDeps) (*witnessclient.HeadSync, error) {
	// "Disabled" detection is now two-state: neither the resolver
	// nor the config canary contributes — the operator chose to
	// run a pure read-only / test-rig posture.
	resolverAvailable := d.WitnessEndpointResolver != nil && cfg.LogDID != ""
	if !resolverAvailable && len(cfg.WitnessEndpoints) == 0 {
		d.Logger.Info("witness cosigner: disabled (no on-log resolver AND LEDGER_WITNESS_ENDPOINTS unset)")
		return nil, nil
	}
	var pub witnessclient.CosignedHeadPublisher
	if d.GossipPublisher != nil {
		pub = d.GossipPublisher
	}
	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		// v1.32.0: on-log resolver is the AUTHORITATIVE source.
		// WitnessEndpoints (below) is the canary fallback.
		EndpointResolver:        d.WitnessEndpointResolver,
		EndpointResolverLogDID:  cfg.LogDID,
		EndpointResolverTimeout: 5 * time.Second,
		WitnessEndpoints:        cfg.WitnessEndpoints,
		QuorumK:                 cfg.WitnessQuorumK,
		PerWitnessTimeout:       30 * time.Second,
		NetworkID:               cfg.NetworkID,
		GossipPublisher:         pub,
		// nil ⇒ HeadSync composes sdklog.DefaultClient. Non-nil ⇒
		// every cosign.WitnessClient presents this binary's client
		// cert when the witness enforces mTLS (TLS 1.3 floor).
		HTTPClient: d.OutboundHTTPClient,
	}, d.TreeHeadStore, d.Logger)
	if err != nil {
		return nil, err
	}
	d.Logger.Info("witness cosigner: HeadSync requester enabled",
		"resolver_wired", resolverAvailable,
		"canary_endpoint_count", len(cfg.WitnessEndpoints),
		"quorum_k", cfg.WitnessQuorumK,
		"gossip_publisher", d.GossipPublisher != nil,
		"log_did", cfg.LogDID,
	)
	return hs, nil
}

// wireEscrowOverride builds the /v1/escrow-override handler when both
// the witness cosigner and gossip bundle are wired. nil otherwise.
func wireEscrowOverride(cfg Config, cosigner *witnessclient.HeadSync, d *deps.AppDeps) http.HandlerFunc {
	if cosigner == nil || d.GossipBundle == nil || d.GossipPublisher == nil {
		return nil
	}
	if cosigner.Collector() == nil {
		d.Logger.Warn("escrow override: skipped (cosigner has no Collector exposure)")
		return nil
	}
	svc, err := gossipnet.NewEscrowOverrideService(gossipnet.EscrowOverrideServiceConfig{
		Collector:  cosigner.Collector(),
		Store:      d.GossipStore,
		Sink:       d.GossipBundle.Sink,
		Signer:     cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
		NetworkID:  cfg.NetworkID,
		Originator: cfg.LedgerDID,
		Logger:     d.Logger,
	})
	if err != nil {
		d.Logger.Error("escrow override service", "error", err)
		return nil
	}
	d.Logger.Info("escrow override endpoint mounted at POST /v1/escrow-override")
	return api.EscrowOverrideHandler(svc, d.Logger)
}
