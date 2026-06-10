// Package app composes the auditor's inbound anti-entropy pipeline + gossip feed
// from the agnostic libs, on the baseproof v1.15.0 finding-router surface.
//
// It is domain-free by construction: every input is a RESOLVED trust root or
// config value (witness sets, the DID verifier registry, network ID, peers),
// never a network package. The verify path runs the SDK router
// (gossipverify → findings.FromWire/Verify); the custodial gossip.Store is
// injected (the Postgres impl lives in services/auditor/internal/store and is
// never importable by an enforcer).
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/gossip"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/auditing/gossipverify"
	"github.com/baseproof/tooling/libs/auditing/peers"
	"github.com/baseproof/tooling/libs/crosslog"
	"github.com/baseproof/tooling/libs/gossipingest"
	"github.com/baseproof/tooling/libs/monitoring"
	"github.com/baseproof/tooling/services/auditor/internal/equivocation"
	"github.com/baseproof/tooling/services/auditor/internal/gossipfeed"
	"github.com/baseproof/tooling/services/auditor/internal/horizon"
)

// Deps are the RESOLVED trust roots + config the pipeline needs. The caller
// (main) resolves these from the network bootstrap + operational config; app
// parses nothing domain-specific.
type Deps struct {
	// Store is the auditor's durable evidence store — custody. Every verified
	// inbound finding persists here; the feed serves it. Injected so the impl
	// (internal/store Postgres) stays out of this domain-free package.
	Store gossip.Store
	// RotationJournal durably records each verified witness-set rotation as a
	// position-bearing record so witness.WitnessSetAt can reconstruct the set
	// authoritative at any asOf years later (ZT-SCN-02, AT-1). Optional; nil ⇒
	// rotations advance the live trust root but are not journaled. The auditor
	// wires *store.PostgresWitnessRotationJournal.
	RotationJournal monitoring.RotationJournal
	// WitnessSetResolver makes inbound CosignedTreeHeadFinding verification
	// POSITION-AWARE — a head is verified against the set that cosigned it
	// (reconstructed from the log), not the current-set snapshot (ZT-SCN-02).
	// Optional; nil ⇒ legacy snapshot behavior. The auditor wires
	// *store.HistoricalResolverRegistry.
	WitnessSetResolver gossipverify.HeadWitnessSetResolver
	// WitnessSets maps each source-log DID to its K-of-N trust root.
	WitnessSets map[string]*cosign.WitnessKeySet
	NetworkID   cosign.NetworkID
	// DIDRegistry resolves originator + signer DIDs (did:key/web/pkh).
	DIDRegistry *did.VerifierRegistry
	// Tiles is the optional cross-log tile source for ClassMerkle findings.
	Tiles gossipverify.TileFetcherSource
	// Peers are the /v1/gossip/since feeds to pull (logDID + base URL).
	Peers []peers.PeerFeed
	// HorizonPeers are the ledgers whose published cosigned checkpoint the
	// durability auditor verifies (originator did:key + base URL). Empty or
	// HorizonInterval<=0 disables the audit.
	HorizonPeers    []horizon.Peer
	HorizonSamples  int
	HorizonInterval time.Duration

	// PeerHTTPClient is the single *http.Client the binary built at boot
	// for ALL outbound peer-ledger traffic — the gossip feed pull, the
	// horizon durability audit, did:web peer-DID resolution, and peer-
	// originator discovery. Required. Mirror of the ledger binary's
	// d.OutboundHTTPClient: one client, one mTLS posture, threaded into
	// every outbound surface. v1.27.1 deleted the per-component plaintext
	// fallbacks that used to mask whether mTLS was actually in effect.
	PeerHTTPClient *http.Client

	SlashThreshold int
	PollInterval   time.Duration
	PageLimit      int
	// MaxInFlightVerify caps the concurrency of HandleSignedEvent calls
	// the puller delivers to the reconciler. 0 (default) disables the
	// throttle; >0 wraps the reconciler in a gossipingest.Throttler
	// with this capacity. See libs/gossipingest/throttle.go.
	//
	// Ladder 5 P9 (#21): operators set this via AUDITOR_VERIFY_MAX_INFLIGHT
	// (default 0 = disabled, preserving the pre-Ladder-5 unbounded
	// behavior). Sizing rule: 2 × (DB pool max) or 4 × (vCPU).
	MaxInFlightVerify int
	// RetentionDays gates the universal gossip_prune job: 0 (default) keeps all
	// evidence and the job is not registered; >0 prunes events older than the
	// window via the durable store. A custodian keeps everything by default.
	RetentionDays int
	PruneInterval time.Duration
	Logger        *slog.Logger

	// AuditorRegistry is the v1.32.0 on-log AuditorRegistrationV1 record
	// slice the inbound scope gate dispatches against. nil PRESERVES the
	// pre-v1.32 ingest behavior (the reconciler dispatches every verified
	// finding without consulting the registry). Non-nil enables the gate:
	// the reconciler rejects findings whose originator isn't registered
	// at AuditorScopeAsOf or whose Scope mask doesn't cover the event
	// Kind.
	//
	// Typically loaded via LoadAuditorRegistryFromFile(path) from an
	// operator-managed JSON manifest (Ladder 1 B1 sorts internally;
	// the slice handed to the reconciler is always SDK-contract-valid).
	// A future patch may replace this loader with an on-log walker
	// (crosslog.MaterializeFromEntries) — the Deps shape stays the same.
	AuditorRegistry network.AuditorRegistrationByPosition

	// AuditorAmendments is the v1.33.x on-log AuditorScopeAmendmentV1
	// record slice the inbound scope gate merges with AuditorRegistry
	// when resolving an auditor's effective scope at a position (SDK
	// Gap 2 — lightweight scope changes without re-issuing the full
	// AuditorRegistration). nil means "no amendments published yet",
	// equivalent to v1.32.0 registration-only behavior.
	//
	// Typically loaded via LoadAuditorAmendmentsFromFile(path) from an
	// operator-managed JSON manifest, symmetric to AuditorRegistry. A
	// future on-log walker populates it from
	// crosslog.MaterializeFromEntries; the Deps shape is stable.
	AuditorAmendments network.AuditorScopeAmendmentByPosition

	// AuditorScopeAsOf returns the LogPosition the scope gate uses for
	// its asOf walker argument. nil ⇒ zero LogPosition (every record in
	// AuditorRegistry treated as in-effect; appropriate when the registry
	// was assembled from a fully-walked snapshot). Production wirings tie
	// this to the latest cosigned tree head's position.
	AuditorScopeAsOf func(ctx context.Context) types.LogPosition

	// URLDriftResolver is the did.DIDResolver consulted by the periodic
	// url_drift audit job. Optional — when nil, the job is not
	// registered on the scheduler. When non-nil, the job runs every
	// URLDriftInterval and consults the resolver to cross-check the
	// MaterializedSource snapshot against did:web documents (each
	// mismatch becomes a monitoring.Alert with Severity=Warning).
	//
	// Typically populated from libs/clienttls.BuildDIDResolverWithMTLS
	// — the same did:web resolver the auditor's main.go constructs for
	// peer-DID resolution.
	URLDriftResolver did.DIDResolver

	// URLDriftMaterializedSource returns the latest MaterializedNetwork
	// snapshot for the url_drift audit cycle. Optional — required when
	// URLDriftResolver is non-nil. Returning an empty MaterializedNetwork
	// is valid (the audit then does nothing); a non-nil error surfaces
	// as a Critical audit-failure alert.
	//
	// Today's auditor doesn't run an on-log scan, so this closure
	// typically returns crosslog.MaterializedNetwork{} (empty) — the
	// job runs but emits no alerts. When the scan loop lands, swap to
	// a closure over the scanner's latest snapshot.
	URLDriftMaterializedSource func(ctx context.Context) (crosslog.MaterializedNetwork, error)

	// URLDriftInterval is the cadence the url_drift audit job runs at.
	// Required when URLDriftResolver is non-nil; ignored otherwise.
	// Typical production value: 5–15 minutes. Too aggressive (< 1m)
	// spams did:web resolution; too slack (> 1h) means a real drift
	// goes undetected for the full interval before the next pass.
	URLDriftInterval time.Duration

	// URLDriftLocalLogDID is the auditor's local network DID, surfaced
	// in url_drift alert details for cross-network triage. Required
	// when URLDriftResolver is non-nil. Typically the same exchangeDID
	// the resolver's MirrorManifest.LogDID was populated with.
	URLDriftLocalLogDID string

	// GovernanceSource returns the materialized on-log governance chains
	// (signature-policy, algorithm-policy, protocol-version) plus the
	// admitted entries / cosigned heads to check against them, at the
	// audited as-of. Optional — when nil (or GovernanceInterval <= 0) the
	// three governance-compliance jobs are not registered.
	//
	// Like URLDriftMaterializedSource, today's auditor has no live on-log
	// scan, so this closure typically returns a genesis-only snapshot (the
	// founding policy synthesized from the bootstrap document, no amendments
	// / entries yet): the jobs run and emit no alerts until a scan loop
	// populates the amendments + subjects, at which point detection goes
	// live with no other wiring change.
	GovernanceSource monitoring.GovernanceSource

	// GovernanceInterval is the cadence the three governance-compliance jobs
	// run at. Required when GovernanceSource is non-nil; ignored otherwise.
	GovernanceInterval time.Duration

	// DerivationCommitmentSource returns the discovered on-log SMT-derivation
	// commitment refs plus the verifier's inputs (content store, entry fetcher,
	// schema resolver). Optional — when nil (or DerivationCommitmentInterval
	// <= 0) the derivation-commitment job is not registered. Like the others,
	// today's auditor has no live on-log scan, so this typically returns no refs
	// (the job runs and no-ops) until a scan loop populates them.
	DerivationCommitmentSource monitoring.DerivationCommitmentSource

	// DerivationCommitmentInterval is the cadence the derivation-commitment job
	// runs at. Required when DerivationCommitmentSource is non-nil.
	DerivationCommitmentInterval time.Duration

	// CustodyChainSource returns the per-ContentDigest artifact custody chains
	// (ArtifactGenesis → CustodyTransfer → Destruction) plus the audited as-of.
	// Optional — when nil (or CustodyChainInterval <= 0) the custody-chain job
	// is not registered. Like the others, today's auditor has no live on-log
	// scan, so this typically returns no chains (the job runs and no-ops) until
	// a scan loop populates them.
	CustodyChainSource monitoring.CustodyChainSource

	// CustodyChainInterval is the cadence the custody-chain job runs at.
	// Required when CustodyChainSource is non-nil.
	CustodyChainInterval time.Duration

	// RotationScan runs ONE incremental witness-rotation log-scan pass across
	// every tracked log (the witnessrotation.ScanReconciler engine, composed in
	// main with per-log ledger clients + the rotation journal + the durable
	// cursor). The scan is the journal's tail-omission closure: a rotation a
	// ledger withheld from gossip is discovered within one interval of being
	// committed. Optional — when nil (or RotationScanInterval <= 0) the job is
	// not registered and the journal stays gossip-fed only (AT-1 behavior).
	RotationScan func(ctx context.Context) ([]sdkmonitoring.Alert, error)

	// RotationScanInterval is the cadence of the rotation scan job. Required
	// when RotationScan is non-nil; ignored otherwise.
	RotationScanInterval time.Duration

	// RotationConsistencySource returns the per-log inputs for the
	// witness-rotation consistency audit (safety: the journaled chain walks
	// clean and the latest verified head is cosigned by an on-chain set;
	// liveness: a journaled rotation is adopted within the grace window).
	// Optional — when nil (or RotationConsistencyInterval <= 0) the audit is
	// not registered.
	RotationConsistencySource monitoring.RotationConsistencySource

	// RotationConsistencyInterval is the cadence of the consistency audit.
	// Required when RotationConsistencySource is non-nil.
	RotationConsistencyInterval time.Duration
}

// Pipeline is the constructed auditor: a puller feeding a
// verify → reconcile → store chain, plus the feed handler that serves the
// (custodial) store to third-party watchers and peers.
type Pipeline struct {
	Puller *peers.PeerPuller
	Feed   http.Handler
	// Scheduler runs the periodic jobs (gossip_prune + horizon_audit). nil when
	// neither a retention window nor the horizon audit is configured.
	Scheduler *monitoring.Scheduler
	// HorizonAuditor verifies peers' published checkpoints (nil when disabled);
	// exposed for status/ops. Its AuditOnce is registered on Scheduler.
	HorizonAuditor *horizon.Verifier
}

// Build wires the inbound anti-entropy pipeline + feed from resolved deps. Trust
// is entirely local: witness sets + the DID registry are the roots, heads are
// recomputed on our own CPU, and peers contribute only bytes (Alignment 6).
func Build(d Deps) (*Pipeline, error) {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Store == nil {
		return nil, fmt.Errorf("auditor/app: nil evidence Store")
	}
	if d.DIDRegistry == nil {
		return nil, fmt.Errorf("auditor/app: nil DID verifier registry")
	}
	if d.PeerHTTPClient == nil {
		return nil, fmt.Errorf("auditor/app: nil PeerHTTPClient (the binary's outbound client must be threaded in; build it via libs/outbound.HoistFromEnv)")
	}

	// Equivocation slashing is gated on having witness sets to slash against;
	// without them findings are still verified + persisted, just not slashed.
	// The slasher + responder are AUDITOR-SPECIFIC policy (libs/gossipingest
	// only owns the verify+persist core), so they're constructed here and
	// passed in as the optional Equivocation field on the gossipingest Config.
	var responder *monitoring.EquivocationResponder
	if len(d.WitnessSets) > 0 {
		slasher, serr := equivocation.NewSlasher(equivocation.SlasherConfig{
			WitnessSets: d.WitnessSets,
			// Position-aware: the same per-log historical resolver wired into the
			// inbound verify path lets the slasher re-verify a HISTORICAL
			// equivocation against its reconstructed era set, so an offence by a
			// since-rotated ledger is slashed rather than silently dropped (the
			// static WitnessSets hold only current sets). nil ⇒ static-only.
			Resolver:  d.WitnessSetResolver,
			Threshold: d.SlashThreshold,
			Logger:    d.Logger,
		})
		if serr != nil {
			return nil, fmt.Errorf("auditor/app: slasher: %w", serr)
		}
		var rerr error
		responder, rerr = monitoring.NewEquivocationResponder(slasher, d.Logger)
		if rerr != nil {
			return nil, fmt.Errorf("auditor/app: equivocation responder: %w", rerr)
		}
	}

	// Inbound pipeline: pull → verify → reconcile → persist. The wiring
	// (verifier, reconciler, puller, trusted-head store, witness-set
	// registry) lives in libs/gossipingest; every required field is
	// validated at construction. The auditor adds the equivocation
	// responder and (below) the horizon audit + scheduler on top.
	//
	// v1.32.0: AuditorRegistry + AuditorScopeAsOf threaded through to
	// monitoring.NewReconciler which runs the scope check on every
	// verified finding before dispatch. nil for both preserves the
	// pre-v1.32 behavior.
	ingest, err := gossipingest.Build(gossipingest.Config{
		HTTPClient:         d.PeerHTTPClient,
		Peers:              d.Peers,
		NetworkID:          d.NetworkID,
		WitnessSets:        d.WitnessSets,
		DIDRegistry:        d.DIDRegistry,
		Store:              d.Store,
		RotationJournal:    d.RotationJournal,
		WitnessSetResolver: d.WitnessSetResolver,
		Tiles:              d.Tiles,
		Equivocation:       responder,
		PollInterval:       d.PollInterval,
		PageLimit:          d.PageLimit,
		MaxInFlightVerify:  d.MaxInFlightVerify,
		Logger:             d.Logger,
		AuditorRegistry:    d.AuditorRegistry,
		AuditorAmendments:  d.AuditorAmendments,
		AuditorScopeAsOf:   d.AuditorScopeAsOf,
	})
	if err != nil {
		return nil, fmt.Errorf("auditor/app: ingest pipeline: %w", err)
	}
	puller := ingest.Puller
	heads := ingest.Heads

	feed, err := gossipfeed.NewFeedMount(gossipfeed.FeedConfig{
		Store:  d.Store,
		Logger: d.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("auditor/app: feed: %w", err)
	}

	// Horizon durability audit (the C/D adoption): verify each peer's published
	// cosigned checkpoint (FetchVerifiedHorizon + sampled proofs) and cross-check
	// it against the gossip-trusted head. Disabled when no peers / interval<=0.
	var horizonAuditor *horizon.Verifier
	if d.HorizonInterval > 0 {
		horizonAuditor, err = horizon.NewVerifier(horizon.Config{
			Peers:      d.HorizonPeers,
			Sets:       d.WitnessSets,
			Heads:      heads,
			HTTPClient: d.PeerHTTPClient,
			Samples:    d.HorizonSamples,
			Logger:     d.Logger,
		})
		if err != nil {
			return nil, fmt.Errorf("auditor/app: horizon verifier: %w", err)
		}
	}

	// Periodic jobs run on one scheduler:
	//   * gossip_prune retention job (gated on a Pruner store + an
	//     operator-configured window — the custodian keeps ALL evidence
	//     by default)
	//   * horizon_audit job (peer-checkpoint durability verification)
	//   * Ladder 2 D6 (#21): url_drift_audit job (cross-checks the
	//     materialized walker output against did:web documents; alerts
	//     on drift)
	// The scheduler is created only when at least one job is registered.
	pruner, prunable := d.Store.(monitoring.Pruner)
	registerPrune := prunable && d.RetentionDays > 0
	registerURLDrift := d.URLDriftResolver != nil &&
		d.URLDriftMaterializedSource != nil &&
		d.URLDriftInterval > 0
	registerGovernance := d.GovernanceSource != nil && d.GovernanceInterval > 0
	registerCommitment := d.DerivationCommitmentSource != nil && d.DerivationCommitmentInterval > 0
	registerCustody := d.CustodyChainSource != nil && d.CustodyChainInterval > 0
	registerRotationScan := d.RotationScan != nil && d.RotationScanInterval > 0
	registerRotationConsistency := d.RotationConsistencySource != nil && d.RotationConsistencyInterval > 0
	var scheduler *monitoring.Scheduler
	if registerPrune || horizonAuditor != nil || registerURLDrift || registerGovernance || registerCommitment || registerCustody || registerRotationScan || registerRotationConsistency {
		scheduler = monitoring.NewScheduler(monitoring.SchedulerConfig{Logger: d.Logger})
		if registerPrune {
			interval := d.PruneInterval
			if interval <= 0 {
				interval = 24 * time.Hour
			}
			if err := scheduler.Register(monitoring.Job{
				Name:     "gossip_prune",
				Interval: interval,
				Run:      monitoring.PruneJob(pruner, d.RetentionDays, d.Logger),
			}); err != nil {
				return nil, fmt.Errorf("auditor/app: register gossip_prune: %w", err)
			}
		}
		if horizonAuditor != nil {
			if err := scheduler.Register(monitoring.Job{
				Name:     "horizon_audit",
				Interval: d.HorizonInterval,
				Run:      horizonAuditor.AuditOnce,
			}); err != nil {
				return nil, fmt.Errorf("auditor/app: register horizon_audit: %w", err)
			}
		}
		if registerURLDrift {
			driftCfg := monitoring.URLDriftAuditConfig{
				LocalLogDID:        d.URLDriftLocalLogDID,
				MaterializedSource: d.URLDriftMaterializedSource,
				Resolver:           d.URLDriftResolver,
			}
			if err := scheduler.Register(monitoring.Job{
				Name:     "url_drift_audit",
				Interval: d.URLDriftInterval,
				Run: func(ctx context.Context) ([]sdkmonitoring.Alert, error) {
					return monitoring.CheckURLDrift(ctx, driftCfg, d.Logger, time.Now())
				},
			}); err != nil {
				return nil, fmt.Errorf("auditor/app: register url_drift_audit: %w", err)
			}
		}
		if registerGovernance {
			// The three network-governance compliance jobs (issue #41): each
			// independently re-derives an on-log governance chain via its SDK
			// Resolve…At walker and checks the admitted entries/heads against
			// the policy in effect at their position. All three read one shared
			// snapshot from GovernanceSource.
			govSrc := d.GovernanceSource
			govJobs := []struct {
				name string
				run  func(context.Context, monitoring.GovernanceSnapshot) ([]sdkmonitoring.Alert, error)
			}{
				{"signature_policy_compliance", func(ctx context.Context, s monitoring.GovernanceSnapshot) ([]sdkmonitoring.Alert, error) {
					return monitoring.CheckSignaturePolicyCompliance(ctx, monitoring.SignaturePolicyComplianceConfig{
						Records: s.Governance.SignaturePolicies, Entries: s.Entries, Heads: s.Heads, AsOf: s.AsOf,
					}, time.Now())
				}},
				{"algorithm_policy_compliance", func(ctx context.Context, s monitoring.GovernanceSnapshot) ([]sdkmonitoring.Alert, error) {
					return monitoring.CheckAlgorithmPolicyCompliance(ctx, monitoring.AlgorithmPolicyComplianceConfig{
						Records: s.Governance.AlgorithmPolicies, Entries: s.Entries, AsOf: s.AsOf,
					}, time.Now())
				}},
				{"protocol_version_compliance", func(ctx context.Context, s monitoring.GovernanceSnapshot) ([]sdkmonitoring.Alert, error) {
					return monitoring.CheckProtocolVersionCompliance(ctx, monitoring.ProtocolVersionComplianceConfig{
						Records: s.Governance.ProtocolVersions, Entries: s.Entries, AsOf: s.AsOf,
					}, time.Now())
				}},
			}
			for _, gj := range govJobs {
				run := gj.run
				if err := scheduler.Register(monitoring.Job{
					Name:     gj.name,
					Interval: d.GovernanceInterval,
					Run: func(ctx context.Context) ([]sdkmonitoring.Alert, error) {
						snap, err := govSrc(ctx)
						if err != nil {
							return nil, fmt.Errorf("governance source: %w", err)
						}
						return run(ctx, snap)
					},
				}); err != nil {
					return nil, fmt.Errorf("auditor/app: register %s: %w", gj.name, err)
				}
			}
		}
		if registerCommitment {
			// #42: SMT-derivation commitment-ref verification. Replays every
			// published commitment ref against a chained, genesis-seeded prior
			// SMT state via the SDK verifier.
			commitSrc := d.DerivationCommitmentSource
			if err := scheduler.Register(monitoring.Job{
				Name:     "derivation_commitment_compliance",
				Interval: d.DerivationCommitmentInterval,
				Run: func(ctx context.Context) ([]sdkmonitoring.Alert, error) {
					cfg, err := commitSrc(ctx)
					if err != nil {
						return nil, fmt.Errorf("derivation-commitment source: %w", err)
					}
					return monitoring.CheckDerivationCommitmentCompliance(ctx, cfg, time.Now())
				},
			}); err != nil {
				return nil, fmt.Errorf("auditor/app: register derivation_commitment_compliance: %w", err)
			}
		}
		if registerRotationScan {
			// AT-2 write side: incremental log-scan reconciliation of the
			// rotation journal (tail-omission closure; see
			// libs/witnessrotation/reconcile.go for the async trust model).
			if err := scheduler.Register(monitoring.Job{
				Name:     "witness_rotation_scan",
				Interval: d.RotationScanInterval,
				Run:      d.RotationScan,
			}); err != nil {
				return nil, fmt.Errorf("auditor/app: register witness_rotation_scan: %w", err)
			}
		}
		if registerRotationConsistency {
			// AT-2 read-side audit: safety (chain integrity + on-chain head) is
			// Critical; liveness (rotation adopted within grace) is Warning.
			rotSrc := d.RotationConsistencySource
			if err := scheduler.Register(monitoring.Job{
				Name:     "witness_rotation_consistency",
				Interval: d.RotationConsistencyInterval,
				Run: func(ctx context.Context) ([]sdkmonitoring.Alert, error) {
					cfg, err := rotSrc(ctx)
					if err != nil {
						return nil, fmt.Errorf("rotation-consistency source: %w", err)
					}
					return monitoring.CheckWitnessRotationConsistency(ctx, cfg, time.Now())
				},
			}); err != nil {
				return nil, fmt.Errorf("auditor/app: register witness_rotation_consistency: %w", err)
			}
		}
		if registerCustody {
			// #43: artifact custody-chain auditing. Walks each artifact's on-log
			// custody chain (ArtifactGenesis → CustodyTransfer → Destruction) via
			// storage.ArtifactCustodyAt and flags a chain the ledger should never
			// have admitted (forged FromOwner, cross-content splice).
			custodySrc := d.CustodyChainSource
			if err := scheduler.Register(monitoring.Job{
				Name:     "custody_chain_compliance",
				Interval: d.CustodyChainInterval,
				Run: func(ctx context.Context) ([]sdkmonitoring.Alert, error) {
					cfg, err := custodySrc(ctx)
					if err != nil {
						return nil, fmt.Errorf("custody-chain source: %w", err)
					}
					return monitoring.CheckCustodyChainCompliance(ctx, cfg, time.Now())
				},
			}); err != nil {
				return nil, fmt.Errorf("auditor/app: register custody_chain_compliance: %w", err)
			}
		}
	}

	return &Pipeline{Puller: puller, Feed: feed, Scheduler: scheduler, HorizonAuditor: horizonAuditor}, nil
}
