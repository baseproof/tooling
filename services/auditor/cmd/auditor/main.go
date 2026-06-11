// Command auditor is the ClearCompass detective-control daemon — the Evidence
// Custodian. It audits transparency logs for ANY network (pull peer feeds →
// verify via the SDK finding router → reconcile → persist), serves the durable
// /v1/gossip evidence feed, and never participates in commit. It is
// domain-agnostic by construction: it imports zero network packages (CI's
// dependency law enforces this), and its evidence store lives in internal/store
// so no enforcer can link it (Separation of Duties, compiler-enforced).
//
// Wiring: env-driven config → parse the shared bootstrap (loadBootstrap) →
// resolve each peer's gossip-originator did:key and bind the genesis witness set
// to it (resolvePeers + buildWitnessSets, self-discovery via /v1/log-info) →
// compose the libs (internal/app.Build) → serve + run with two-phase graceful
// shutdown. With no gossip store configured it runs health-only.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/lib/pq" // postgres driver for the gossip evidence store

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/log/discover"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	sdknetwork "github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/anchorcache"
	"github.com/baseproof/tooling/libs/auditing/didregistry"
	"github.com/baseproof/tooling/libs/auditing/peers"
	"github.com/baseproof/tooling/libs/clitools"
	"github.com/baseproof/tooling/libs/crosslog"
	"github.com/baseproof/tooling/libs/monitoring"
	"github.com/baseproof/tooling/libs/outbound"
	"github.com/baseproof/tooling/libs/sdkguard"
	"github.com/baseproof/tooling/libs/tracing"
	"github.com/baseproof/tooling/libs/witnessrotation"
	"github.com/baseproof/tooling/services/auditor/internal/app"
	"github.com/baseproof/tooling/services/auditor/internal/horizon"
	"github.com/baseproof/tooling/services/auditor/internal/store"
)

// version is stamped at link time via -ldflags "-X main.version=...".
// Defaults to "dev" for un-stamped (local) builds.
var version = "dev"

// config is the daemon's fully env-driven configuration. The same binary runs
// under docker-compose or k8s; only the injected env differs.
type config struct {
	listenAddr   string
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
	shutdownWait time.Duration

	// otlpTracesEndpoint selects the OTel traces exporter: ""=off, "stdout", or
	// host:port for OTLP HTTP. Installs the W3C propagator regardless, so the
	// trace from a peer ledger flows through the auditor's outbound calls.
	otlpTracesEndpoint string

	// Custody + pipeline. gossipDSN empty ⇒ run health-only (no store, no feed):
	// the auditor IS the evidence custodian, so the inbound pipeline + feed are
	// gated on having a durable store.
	gossipDSN     string
	bootstrapFile string // shared network bootstrap → NetworkID + witness sets
	// quorumK is AUDITOR_WITNESS_QUORUM_K as read (0 = unset), then REPLACED at
	// boot with the constitutional doc.GenesisQuorumK after the env value passes
	// the reconcileWitnessQuorumK cross-check (unset adopts; equal honoured;
	// different fatal).
	quorumK      int
	peers        string // "logDID=baseURL,logDID=baseURL"
	pollInterval time.Duration
	pageLimit    int
	// Ladder 5 P9 (#21): bounded-concurrency for the puller→reconciler
	// hot path. 0 (default) disables the throttle — preserves
	// pre-Ladder-5 unbounded behavior. Operators set
	// AUDITOR_VERIFY_MAX_INFLIGHT > 0 to opt in once they've sized the
	// cap to their DB pool + vCPU budget.
	maxInFlightVerify int
	// discoverOriginator controls how the genesis witness set is bound to a
	// peer's gossip-originator DID. STH gossip is originated under a log's
	// OPERATIONAL did:key (the ledger's signer key), not its canonical
	// exchange_did, and the witness-set lookup keys on that originator
	// (gossip routes WitnessSets[ev.Originator]). When true (default), the
	// auditor resolves each peer's operational did:key from its public
	// GET /v1/log-info (the "ledger_did" field) and binds the genesis witness
	// set to it. When false, the DID configured in AUDITOR_PEERS is used
	// verbatim as the originator (an operator-pinned did:key).
	discoverOriginator bool
	// retentionDays gates the universal gossip_prune job. 0 (default) ⇒ the
	// custodian keeps ALL evidence; >0 enables a retention window.
	retentionDays int
	pruneInterval time.Duration
	// horizonInterval is the cadence of the durability audit (each peer's
	// published cosigned checkpoint). 0 disables it; default 60s. horizonSamples
	// is the random proof sample per peer per cycle.
	horizonInterval time.Duration
	horizonSamples  int
	// didwebTTL caches did:web → ledger-endpoint resolutions for bare did:web
	// entries in AUDITOR_PEERS (no =baseURL). The DID document is re-fetched
	// after this TTL so a rotated service endpoint is eventually picked up.
	didwebTTL time.Duration

	// Auditor-scope gate. Recognition is always-on and network-governed:
	// the recognized set is the bootstrap's genesis auditors merged with the
	// on-log AuditorRegistrationV1 chain — there is no enforce flag and no
	// registry file (authority comes from the log, not an operator manifest).
	//
	// auditorAmendmentFile (AUDITOR_AMENDMENT_FILE) is the path to the JSON
	// manifest of network.AuditorScopeAmendmentV1 entries that merge with the
	// registration stream at gate resolution. Optional — empty means "no
	// amendments yet". Sorted on load. (Like the registry, this is slated to
	// move on-log; until then it remains an optional operator manifest.)
	auditorAmendmentFile string

	// urlDriftInterval (AUDITOR_URL_DRIFT_INTERVAL, default 0 = disabled)
	// is the cadence the periodic url_drift audit runs at. Ladder 2 D6
	// (#21): the audit cross-checks the materialized walker output
	// against did:web documents; each mismatch becomes a Warning alert
	// via the existing scheduler sink. 0 = audit not registered.
	// Typical production value: 5–15 minutes.
	urlDriftInterval time.Duration

	// governanceInterval (AUDITOR_GOVERNANCE_INTERVAL, default 0 = disabled)
	// is the cadence the three network-governance compliance jobs (#41:
	// signature-policy / algorithm-policy / protocol-version) run at. Each
	// independently re-derives an on-log governance chain via its SDK
	// Resolve…At walker. 0 = jobs not registered. Like url_drift, the source
	// is genesis-only until a live on-log scan lands.
	governanceInterval time.Duration

	// commitmentInterval (AUDITOR_COMMITMENT_INTERVAL, default 0 = disabled)
	// is the cadence the SMT-derivation commitment-ref verification job (#42)
	// runs at. 0 = job not registered. The source discovers no refs until a
	// live on-log scan lands.
	commitmentInterval time.Duration

	// custodyInterval (AUDITOR_CUSTODY_INTERVAL, default 0 = disabled) is the
	// cadence the artifact custody-chain auditing job (#43) runs at. 0 = job
	// not registered. The source projects no chains until a live on-log scan
	// lands.
	custodyInterval time.Duration

	// rotationScanInterval (AUDITOR_ROTATION_SCAN_INTERVAL, default 10m;
	// set an explicit "0" to disable) is the cadence of the incremental
	// witness-rotation log scan (AT-2): each pass covers only
	// [cursor, cosigned target) per peer log, journaling any rotation gossip
	// missed. ON BY DEFAULT: tail-omission closure is a safety property of
	// the trust root, not optional telemetry — safety machinery that ships
	// dark is tech debt.
	rotationScanInterval time.Duration

	// rotationConsistencyInterval (AUDITOR_ROTATION_CONSISTENCY_INTERVAL,
	// default 10m; set an explicit "0" to disable) is the cadence of the
	// witness-rotation consistency audit: safety (journaled chain walks
	// clean; latest verified head is cosigned by an on-chain set) alerts
	// Critical; liveness (rotation adopted within the grace window; log not
	// frozen) alerts Warning. ON BY DEFAULT, same rationale as the scan.
	rotationConsistencyInterval time.Duration

	// rotationAdoptionGrace (AUDITOR_ROTATION_ADOPTION_GRACE, default 1h) is
	// the async tolerance window the consistency audit allows between a
	// journaled rotation and the first new-set-cosigned head before warning —
	// the cosign switch is operationally fuzzy and gossip delivery is
	// independent, so divergence INSIDE the window is expected and silent.
	rotationAdoptionGrace time.Duration

	// frozenLogMaxHeadAge (AUDITOR_MAX_HEAD_AGE; default = the SDK preset
	// witness.StalenessFrozenLog, 1h; "0" disables) bounds how old a log's
	// newest VERIFIED head may be before the consistency audit flags the log
	// FROZEN (Warning). head-age = LOG LIVENESS (the SDK's
	// witness.CheckHeadFreshness axis), distinct from fetch-age view
	// freshness; the default number lives in ONE home — the SDK preset.
	frozenLogMaxHeadAge time.Duration

	// equivScanInterval (AUDITOR_EQUIVOCATION_SCAN_INTERVAL, default 0 =
	// disabled) is the cadence the INDEPENDENT equivocation scanner polls each
	// peer's latest cosigned tree head at. 0 = the scanner is not started.
	// Requires gossipSigningKeyFile (emit needs a gossip identity).
	equivScanInterval time.Duration

	// gossipSigningKeyFile (AUDITOR_GOSSIP_SIGNING_KEY_FILE) is the path to the
	// auditor's secp256k1 gossip signing key (PEM). The emit-side originator
	// did:key is derived from it (no DID in config); empty disables the
	// equivocation scanner's push leg.
	gossipSigningKeyFile string

	// Ladder 5 P6 (#21): tree-size-keyed materialized-view cache.
	//
	//   AUDITOR_MATERIALIZED_CACHE_DIR — root directory for the cache.
	//     Empty (default) disables the cache; the resolver's walker
	//     fields start empty and stay empty until populated by some
	//     other path (future log-scan loop, CLI tool, etc.). When set,
	//     boot reads the latest snapshot and seeds the resolver fields.
	//
	//   AUDITOR_MATERIALIZED_KEEP_LAST — bounded-disk retention. The
	//     auditor prunes all but the last N tree-size subdirectories
	//     at boot. Default 5. Operators tune higher to keep an
	//     audit-trail of network-config evolution; lower to save disk.
	//
	// SCOPE NOTE: the auditor's job is gossip custody (Postgres-backed),
	// NOT network-config materialization. P6's cache is consumed by
	// the auditor on boot; the WRITER is whoever produces snapshots —
	// today that's not the auditor binary. A future log-scan loop or
	// CLI tool writes the cache; the auditor picks up whatever's there.
	materializedCacheDir string
	materializedKeepLast int

	// Peer-outbound mTLS material is read from env at boot via
	// libs/outbound.HoistFromEnv("AUDITOR_PEER_", ...) — the canonical
	// hoist used by every binary in the ecosystem. The four env vars are
	//   AUDITOR_PEER_CLIENT_CERT_FILE
	//   AUDITOR_PEER_CLIENT_KEY_FILE
	//   AUDITOR_PEER_CA_FILE
	//   AUDITOR_PEER_HTTP_TIMEOUT (Go duration string, default 10s)
	// Both cert+key set → mTLS; both empty → plaintext (legacy posture,
	// logged loudly at startup); half-config → startup-fatal. See
	// libs/clienttls and libs/outbound for the contract.
}

func loadConfig() config {
	return config{
		listenAddr:   envOr("AUDITOR_LISTEN_ADDR", portAddrOr(":8088")),
		readTimeout:  envDuration("AUDITOR_READ_TIMEOUT", 5*time.Second),
		writeTimeout: envDuration("AUDITOR_WRITE_TIMEOUT", 10*time.Second),
		idleTimeout:  envDuration("AUDITOR_IDLE_TIMEOUT", 60*time.Second),
		shutdownWait: envDuration("AUDITOR_SHUTDOWN_TIMEOUT", 15*time.Second),

		otlpTracesEndpoint: os.Getenv("AUDITOR_OTLP_TRACES_ENDPOINT"),

		gossipDSN: os.Getenv("AUDITOR_GOSSIP_DSN"),
		// The bootstrap is the one shared, byte-identical trust input every
		// component loads; honor the fleet's LEDGER_* var so one eval feeds all.
		bootstrapFile: resolveFile(envOr("AUDITOR_NETWORK_BOOTSTRAP_FILE", os.Getenv("LEDGER_NETWORK_BOOTSTRAP_FILE")), "/etc/auditor/bootstrap.json", "/etc/secrets/bootstrap.json"),
		// Cross-check only — the constitutional genesis_quorum_k is the source
		// of K; 0 (unset) adopts it (reconcileWitnessQuorumK).
		quorumK:            envInt("AUDITOR_WITNESS_QUORUM_K", 0),
		peers:              os.Getenv("AUDITOR_PEERS"),
		pollInterval:       envDuration("AUDITOR_POLL_INTERVAL", 30*time.Second),
		pageLimit:          1000,
		maxInFlightVerify:  envInt("AUDITOR_VERIFY_MAX_INFLIGHT", 0),
		discoverOriginator: envBool("AUDITOR_ORIGINATOR_DISCOVERY", true),
		retentionDays:      envInt("AUDITOR_GOSSIP_RETENTION_DAYS", 0),
		pruneInterval:      envDuration("AUDITOR_PRUNE_INTERVAL", 24*time.Hour),
		horizonInterval:    envDuration("AUDITOR_HORIZON_INTERVAL", 60*time.Second),
		horizonSamples:     envInt("AUDITOR_HORIZON_SAMPLES", 8),
		didwebTTL:          envDuration("AUDITOR_DIDWEB_TTL", 5*time.Minute),
		// Optional auditor scope-amendment manifest (slated to move on-log).
		auditorAmendmentFile: resolveFile(os.Getenv("AUDITOR_AMENDMENT_FILE"), "/etc/auditor/amendment.json", "/etc/secrets/amendment.json"),
		// Ladder 2 D6 (#21): url_drift audit cadence.
		urlDriftInterval:   envDuration("AUDITOR_URL_DRIFT_INTERVAL", 0),
		governanceInterval: envDuration("AUDITOR_GOVERNANCE_INTERVAL", 0),
		commitmentInterval: envDuration("AUDITOR_COMMITMENT_INTERVAL", 0),
		custodyInterval:    envDuration("AUDITOR_CUSTODY_INTERVAL", 0),
		// AT-2: witness-rotation scan reconciliation + consistency audit.
		// ON BY DEFAULT (explicit "0" disables): both are safety machinery.
		rotationScanInterval:        envDuration("AUDITOR_ROTATION_SCAN_INTERVAL", 10*time.Minute),
		rotationConsistencyInterval: envDuration("AUDITOR_ROTATION_CONSISTENCY_INTERVAL", 10*time.Minute),
		rotationAdoptionGrace:       envDuration("AUDITOR_ROTATION_ADOPTION_GRACE", time.Hour),
		frozenLogMaxHeadAge:         envDuration("AUDITOR_MAX_HEAD_AGE", witness.StalenessFrozenLog.MaxAge),
		// Independent equivocation scanner (push leg). Disabled unless both
		// the interval AND a gossip signing key are set.
		equivScanInterval:    envDuration("AUDITOR_EQUIVOCATION_SCAN_INTERVAL", 0),
		gossipSigningKeyFile: resolveFile(os.Getenv("AUDITOR_GOSSIP_SIGNING_KEY_FILE"), "/etc/auditor/keys/gossip-signing.pem", "/etc/secrets/gossip-signing.pem"),
		// Ladder 5 P6 (#21): materialized-view cache.
		materializedCacheDir: os.Getenv("AUDITOR_MATERIALIZED_CACHE_DIR"),
		materializedKeepLast: envInt("AUDITOR_MATERIALIZED_KEEP_LAST", 5),
	}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(context.Background(), loadConfig(), logger); err != nil {
		logger.Error("auditor: fatal", "err", err)
		os.Exit(1)
	}
}

// run boots the HTTP surface (+ the inbound pipeline + feed when a gossip store
// is configured) and blocks until SIGINT/SIGTERM, then drains within
// shutdownWait. Returns nil on a clean shutdown. Split from main for testability.
func run(ctx context.Context, cfg config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Tracing: global W3C propagator (so a peer ledger's trace continues through
	// the auditor's outbound audits) + the auditor's own spans when an endpoint
	// is configured.
	traceShutdown, err := tracing.Setup(tracing.Config{
		ServiceName: "auditor",
		Endpoint:    cfg.otlpTracesEndpoint,
	})
	if err != nil {
		return fmt.Errorf("auditor: tracing setup: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = traceShutdown(sctx)
	}()

	var ready atomic.Bool
	var feed http.Handler
	// Ladder 5 P10 (#21): done-channels for the background goroutines
	// the pipeline branch launches. Left nil in health-only mode; the
	// shutdown branch joins both ONLY when non-nil, so the health-only
	// path remains a no-op join (covered by TestRun_GracefulShutdown).
	var pullerDone, schedulerDone chan struct{}
	var scannerDone <-chan struct{}
	var scannerCleanup func(context.Context) error

	// Custody + pipeline: only when a durable store is configured. The store
	// impl is auditor-internal (services/auditor/internal/store) — no enforcer
	// can link it.
	if cfg.gossipDSN != "" {
		if cfg.bootstrapFile == "" {
			return fmt.Errorf("auditor: AUDITOR_GOSSIP_DSN set but AUDITOR_NETWORK_BOOTSTRAP_FILE empty — the verify pipeline needs the network's trust roots")
		}
		// Single outbound *http.Client for EVERY peer-ledger surface in this
		// binary — gossip pull, horizon audit, did:web peer-DID resolution,
		// peer originator discovery. mTLS posture chosen here and ONCE via
		// libs/outbound (the canonical hoist used by every binary in the
		// ecosystem); every downstream constructor consumes the embedded
		// *http.Client by reference. Fail-loud on bad TLS material; no
		// silent demotion. Env scheme: AUDITOR_PEER_CLIENT_CERT_FILE +
		// AUDITOR_PEER_CLIENT_KEY_FILE (both set → mTLS; both empty →
		// startup-fatal unless AUDITOR_PEER_ALLOW_PLAINTEXT=1 — the auditor
		// pulls from the mTLS ledger edge, so plaintext is refused by default;
		// half-config → startup-fatal), AUDITOR_PEER_CA_FILE (optional),
		// AUDITOR_PEER_HTTP_TIMEOUT (Go duration; default 10s).
		out, err := outbound.HoistFromEnvRequire("AUDITOR_PEER_", logger)
		if err != nil {
			return fmt.Errorf("auditor: peer http client: %w", err)
		}
		peerHTTPClient := out.Client
		// Trace every outbound peer hop: a client span per request + traceparent
		// injection so the auditor's audits stitch into the trace they belong to.
		peerHTTPClient.Transport = sdklog.WithOTel(peerHTTPClient.Transport)
		nid, exchangeDID, witnessDIDs, bootstrapDoc, err := loadBootstrap(cfg.bootstrapFile)
		if err != nil {
			return fmt.Errorf("auditor: trust roots: %w", err)
		}
		// rc4: GenesisQuorumK is the constitutional, NetworkID-bound quorum — the
		// single source of truth for K. Demote AUDITOR_WITNESS_QUORUM_K to a
		// cross-check (see reconcileWitnessQuorumK); cfg.quorumK carries the
		// reconciled value to every consumer below.
		quorumK, err := reconcileWitnessQuorumK(bootstrapDoc, cfg.quorumK, cfg.bootstrapFile)
		if err != nil {
			return fmt.Errorf("auditor: %w", err)
		}
		cfg.quorumK = quorumK
		// did:web fetch uses the SAME peer-outbound client as every other
		// outbound surface — one mTLS posture across the binary. did:web
		// docs are typically served over public HTTPS, but if an operator
		// runs a private did:web on an mTLS-required host, the same
		// material flows through (no per-component plaintext exception).
		webResolver, err := did.NewWebDIDResolver(did.WebDIDResolverConfig{
			Client: peerHTTPClient,
		})
		if err != nil {
			return fmt.Errorf("auditor: web did resolver: %w", err)
		}
		// did:web-native peer resolution: a bare did:web in AUDITOR_PEERS resolves
		// its ledger base URL from the DID document's BaseproofLedger service endpoint
		// (TTL-cached). Explicit logDID=baseURL entries bypass it. The adapter is the
		// SDK's EndpointResolver — the same resolution log.ResolvingCheckpointClient
		// uses — applied once at startup so gossip, originator discovery, and the
		// horizon audit all share one resolved URL.
		endpointResolver := &did.DIDEndpointAdapter{
			Resolver: did.NewCachingResolver(webResolver, cfg.didwebTTL),
		}
		// Bind the genesis witness set to the identity STHs actually arrive
		// under. Gossip routes the witness-set lookup by the envelope
		// originator (WitnessSets[ev.Originator]), which is a log's OPERATIONAL
		// did:key — not its canonical exchange_did. Resolve each peer's
		// originator (self-discovery via /v1/log-info, or the pinned DID) and
		// key the genesis witness set by it.
		resolvedPeers, err := resolvePeers(ctx, parsePeers(cfg.peers), cfg.discoverOriginator, nid, endpointResolver, peerHTTPClient, logger)
		if err != nil {
			return fmt.Errorf("auditor: resolve peers: %w", err)
		}
		cosignSchemeTags, err := crosslog.GenesisCosignSchemeTags(bootstrapDoc, [32]byte(nid))
		if err != nil {
			return fmt.Errorf("auditor: resolve cosign scheme policy: %w", err)
		}
		witnessSets, err := buildWitnessSets(resolvedPeers, witnessDIDs, cfg.quorumK, nid, cosignSchemeTags)
		if err != nil {
			return fmt.Errorf("auditor: build witness sets: %w", err)
		}

		// Ladder 2 D1 + D2 (#21): construct the SDK's authoritative
		// endpoint resolver from the same bootstrap-derived inputs the
		// witness-sets path already built. Today the resolver carries
		// an EMPTY Materialized snapshot (the auditor doesn't run an
		// on-log scan yet); the moment a scan loop lands the same
		// resolver instance picks up Endpoints / Labels / Auditors /
		// Amendments without changing any other wiring. sdkguard panics
		// in strict mode if a load-bearing field was left nil — surfaces
		// the misconfig at boot rather than at first lookup.
		// Ladder 5 P6 (#21): if a materialized-view cache is configured,
		// READ the latest snapshot now so the resolver's walker fields
		// are pre-seeded. The auditor itself does not write the cache —
		// gossip custody (its job) is Postgres-backed, separate from
		// network-config materialization (whoever publishes walker
		// snapshots: a future log-scan loop, a CLI tool, etc.). The
		// auditor PRUNES bounded-disk retention at boot regardless of
		// read success, so a stuck or runaway writer doesn't fill the
		// disk.
		var cachedSnapshot crosslog.MaterializedNetwork
		if cfg.materializedCacheDir != "" {
			cache, openErr := anchorcache.OpenAt(cfg.materializedCacheDir, exchangeDID)
			if openErr != nil {
				return fmt.Errorf("auditor: open materialized cache dir %q: %w",
					cfg.materializedCacheDir, openErr)
			}
			if pruned, perr := cache.PruneMaterializedTreesizesBelow(cfg.materializedKeepLast); perr != nil {
				logger.Warn("auditor: materialized cache prune failed",
					"err", perr.Error(),
					"keep_last", cfg.materializedKeepLast)
			} else if pruned > 0 {
				logger.Info("auditor: materialized cache pruned",
					"removed", pruned,
					"keep_last", cfg.materializedKeepLast)
			}
			snap, rerr := crosslog.ReadLatestSnapshot(cache)
			switch {
			case errors.Is(rerr, os.ErrNotExist):
				logger.Info("auditor: materialized cache empty (cold boot)")
			case rerr != nil:
				logger.Warn("auditor: materialized cache read failed; ignoring cache",
					"err", rerr.Error())
			default:
				cachedSnapshot = snap.Network
				logger.Info("auditor: materialized cache loaded",
					"tree_size", snap.Treesize,
					"endpoints", len(cachedSnapshot.Endpoints),
					"labels", len(cachedSnapshot.Labels),
					"auditors", len(cachedSnapshot.Auditors),
					"amendments", len(cachedSnapshot.Amendments))
			}
		}

		resolverInputs, err := buildResolverInputs(resolvedPeers, witnessDIDs,
			cfg.quorumK, nid, exchangeDID, webResolver, logger)
		if err != nil {
			return fmt.Errorf("auditor: build resolver inputs: %w", err)
		}
		// Seed the cached snapshot into the resolver inputs. When the
		// cache is unconfigured or empty, cachedSnapshot is its
		// zero-value MaterializedNetwork{} — equivalent to today's
		// "no log-scan, empty walker" path.
		resolverInputs.Materialized = cachedSnapshot
		authoritativeResolver, err := crosslog.NewDefaultAuthoritativeResolver(resolverInputs)
		if err != nil {
			return fmt.Errorf("auditor: authoritative resolver: %w", err)
		}
		sdkguard.AssertResolverPopulated(authoritativeResolver, "auditor-resolver")

		// Ladder 2 D6 (#21): URLDriftMaterializedSource closes over the
		// resolver's current Materialized state. Today the resolver's
		// Materialized is EMPTY (no on-log scan yet), so the closure
		// returns an empty MaterializedNetwork and the periodic audit
		// runs but emits zero alerts. When the scan loop lands and
		// populates resolver.WitnessEndpointRecords / etc., this same
		// closure starts surfacing per-record drift alerts without any
		// other wiring change.
		urlDriftSource := func(ctx context.Context) (crosslog.MaterializedNetwork, error) {
			return crosslog.MaterializedNetwork{
				Endpoints:  authoritativeResolver.WitnessEndpointRecords,
				Labels:     authoritativeResolver.WitnessLabelRecords,
				Auditors:   authoritativeResolver.AuditorRegistryRecords,
				Amendments: authoritativeResolver.AuditorScopeAmendmentRecords,
			}, nil
		}

		// #41: governance-compliance source. The genesis baselines are
		// synthesized from the bootstrap document (the SAME rule the ledger
		// applies); amendments + admitted entries + cosigned heads populate
		// when a live on-log scan lands (today, like urlDriftSource, the scan
		// is empty so the chains are genesis-only and the jobs emit no alerts).
		// AsOf is the genesis origin until a scan provides the latest tree
		// position; a genesis-only chain resolves cleanly there.
		governanceGenesis := crosslog.GovernanceGenesisFromBootstrap(bootstrapDoc, exchangeDID, [32]byte(nid))
		governanceSource := func(ctx context.Context) (monitoring.GovernanceSnapshot, error) {
			return monitoring.GovernanceSnapshot{
				Governance: crosslog.MaterializeGovernance(nil, governanceGenesis, logger),
				AsOf:       types.LogPosition{LogDID: exchangeDID, Sequence: 0},
			}, nil
		}

		// #42: SMT-derivation commitment-ref verification source. With no live
		// on-log scan yet, no refs are discovered (the job runs and no-ops);
		// when the scan + a content store land, populate Refs/BulkStore/Fetcher/
		// SchemaRes and verification goes live with no other wiring change.
		commitmentSource := func(ctx context.Context) (monitoring.DerivationCommitmentComplianceConfig, error) {
			return monitoring.DerivationCommitmentComplianceConfig{LogDID: exchangeDID}, nil
		}

		// #43: artifact custody-chain auditing source. With no live on-log scan
		// yet, no chains are projected (the job runs and no-ops); when the scan
		// lands, MaterializeCustody(scannedEntries) populates the per-artifact
		// chains and ArtifactCustodyAt verification goes live with no other
		// wiring change. AsOf is the latest audited position (the genesis origin
		// here; updated to the latest tree size when the scan lands).
		custodySource := func(ctx context.Context) (monitoring.CustodyChainComplianceConfig, error) {
			return monitoring.CustodyChainComplianceConfig{
				Custody: crosslog.MaterializeCustody(nil, logger),
				AsOf:    types.LogPosition{LogDID: exchangeDID, Sequence: 0},
			}, nil
		}

		// Always-on auditor recognition — network-governed, no admin flag or file.
		// The recognized set is the network's GENESIS auditors (declared in the
		// bootstrap and bound into the NetworkID) merged with any on-log
		// AuditorRegistrationV1 records the resolver has materialized. The gate is
		// ALWAYS on: an originator that is not a recognized auditor (or whose scope
		// does not cover the finding kind) has its claim-class findings dropped. A
		// network that declares no genesis auditors and has no on-log registrations
		// resolves to the empty set, so the gate fail-closes every claim-class
		// finding — the zero-trust default. Authority is the on-log
		// AuditorRegistrationChain rooted at the bootstrap, never an operator file.
		genesisAuditorRecords, gerr := bootstrapDoc.GenesisAuditorRecords(exchangeDID)
		if gerr != nil {
			return fmt.Errorf("auditor: genesis auditor records: %w", gerr)
		}
		auditorRegistry := make(sdknetwork.AuditorRegistrationByPosition, 0,
			len(genesisAuditorRecords)+len(authoritativeResolver.AuditorRegistryRecords))
		auditorRegistry = append(auditorRegistry, genesisAuditorRecords...)
		auditorRegistry = append(auditorRegistry, authoritativeResolver.AuditorRegistryRecords...)
		sort.Sort(auditorRegistry)
		// Resolve recognition as of the latest record held: genesis records sit at
		// sequence 0; on-log registrations advance this as the resolver
		// materializes them.
		auditorScopeAsOfSeq := uint64(0)
		for _, rec := range auditorRegistry {
			if rec.EffectivePos.Sequence > auditorScopeAsOfSeq {
				auditorScopeAsOfSeq = rec.EffectivePos.Sequence
			}
		}
		logger.Info("auditor: auditor-scope gate ENABLED (always-on, network-governed)",
			"genesis_auditors", len(genesisAuditorRecords),
			"onlog_auditors", len(authoritativeResolver.AuditorRegistryRecords),
			"recognized_total", len(auditorRegistry))

		// Ladder 2 D5: optional amendment manifest. When AUDITOR_AMENDMENT_FILE
		// is set, load + sort + thread through Deps; otherwise nil → reconciler
		// treats this as "no amendments yet" (equivalent to v1.32.0 registration-
		// only semantics). The file is independent of AUDITOR_ENFORCE_SCOPES:
		// amendments are meaningless without a registration stream, but loading
		// them when enforce=false is harmless — the reconciler simply ignores
		// AuditorAmendments when AuditorRegistry is nil.
		var auditorAmendments sdknetwork.AuditorScopeAmendmentByPosition
		if cfg.auditorAmendmentFile != "" {
			auditorAmendments, err = app.LoadAuditorAmendmentsFromFile(cfg.auditorAmendmentFile)
			if err != nil {
				return fmt.Errorf("auditor: load auditor amendments: %w", err)
			}
			logger.Info("auditor: amendment manifest loaded",
				"amendment_file", cfg.auditorAmendmentFile,
				"amendments", len(auditorAmendments))
		}

		db, err := sql.Open("postgres", cfg.gossipDSN)
		if err != nil {
			return fmt.Errorf("auditor: open gossip DSN: %w", err)
		}
		defer func() { _ = db.Close() }()
		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("auditor: ping gossip store: %w", err)
		}
		st, err := store.NewPostgresStore(db)
		if err != nil {
			return fmt.Errorf("auditor: gossip store: %w", err)
		}
		if err := st.Migrate(ctx); err != nil {
			return fmt.Errorf("auditor: migrate gossip store: %w", err)
		}
		// AT-1: the durable witness-rotation chain that powers historical
		// witness-set reconstruction (ZT-SCN-02). Shares the gossip-store db;
		// never pruned. Wired into the reconciler so every verified rotation is
		// journaled as it arrives.
		rotJournal, err := store.NewPostgresWitnessRotationJournal(db)
		if err != nil {
			return fmt.Errorf("auditor: rotation journal: %w", err)
		}
		if err := rotJournal.Migrate(ctx); err != nil {
			return fmt.Errorf("auditor: migrate rotation journal: %w", err)
		}

		// AT-2 trust roots: one per peer log. The canonical key is the log's
		// own DID (what rotation findings stamp into EffectivePos.LogDID and
		// the journal keys rows by); the gossip-originator DID — the name the
		// verify path queries — is its alias. The genesis seeds are snapshot
		// BEFORE the live map is re-seeded with reconstructed current sets.
		genesisByOriginator := make(map[string]*cosign.WitnessKeySet, len(witnessSets))
		for k, v := range witnessSets {
			genesisByOriginator[k] = v
		}
		var trustRoots []store.LogTrustRoot
		originatorByLog := make(map[string]string, len(resolvedPeers))
		baseURLByLog := make(map[string]string, len(resolvedPeers))
		for _, rp := range resolvedPeers {
			gen, ok := genesisByOriginator[rp.originatorDID]
			if !ok {
				continue // no genesis seed resolved for this peer
			}
			if _, dup := originatorByLog[rp.configuredDID]; dup {
				continue
			}
			trustRoots = append(trustRoots, store.LogTrustRoot{
				LogDID:  rp.configuredDID,
				Aliases: []string{rp.originatorDID},
				Genesis: gen,
			})
			originatorByLog[rp.configuredDID] = rp.originatorDID
			baseURLByLog[rp.configuredDID] = rp.baseURL
		}
		journalResolver, err := store.NewJournalWitnessSetResolver(rotJournal, trustRoots)
		if err != nil {
			return fmt.Errorf("auditor: journal witness-set resolver: %w", err)
		}

		// Boot-time anchor reconstruction (AT-2/B): re-seed the live trust map
		// with the journal-reconstructed CURRENT set per log. After any past
		// rotation the genesis seed can no longer verify the live horizon —
		// seeding it would silently re-open the stale-trust gap on every
		// restart. Fail-static per log: an unreadable chain keeps the genesis
		// seed (exactly correct for a never-rotated log; loudly logged
		// otherwise).
		reseedWitnessSets(ctx, trustRoots, journalResolver, witnessSets, originatorByLog, logger)

		sthHeads, err := store.NewSTHHeadSource(st, originatorByLog)
		if err != nil {
			return fmt.Errorf("auditor: STH head source: %w", err)
		}

		// AT-2 write side: the incremental log-scan reconciliation job
		// (tail-omission closure). One ScanReconciler per peer log; the
		// scheduler job runs them all each pass and surfaces outcomes as
		// alerts — a rotation discovered by SCAN that gossip never delivered
		// is itself a Warning (the omission evidence), and an unexplainable
		// cosigner set / broken chain / invalid on-log rotation is Critical.
		var rotationScan func(context.Context) ([]sdkmonitoring.Alert, error)
		if cfg.rotationScanInterval > 0 && len(trustRoots) > 0 {
			cursors, cerr := store.NewPostgresRotationScanCursor(db)
			if cerr != nil {
				return fmt.Errorf("auditor: rotation scan cursor: %w", cerr)
			}
			if cerr := cursors.Migrate(ctx); cerr != nil {
				return fmt.Errorf("auditor: migrate rotation scan cursor: %w", cerr)
			}
			var reconcilers []*witnessrotation.ScanReconciler
			for _, root := range trustRoots {
				client, lerr := clitools.NewLedgerClient(baseURLByLog[root.LogDID], root.LogDID)
				if lerr != nil {
					return fmt.Errorf("auditor: ledger client for %s: %w", root.LogDID, lerr)
				}
				src, serr := store.NewLedgerLogSource(client)
				if serr != nil {
					return fmt.Errorf("auditor: log source for %s: %w", root.LogDID, serr)
				}
				rec, rerr := witnessrotation.NewScanReconciler(witnessrotation.ScanReconcilerConfig{
					Src:      src,
					Journal:  rotJournal,
					Cursor:   cursors,
					Fallback: sthHeads,
					Genesis:  root.Genesis,
					LogDID:   root.LogDID,
					Logger:   logger,
				})
				if rerr != nil {
					return fmt.Errorf("auditor: scan reconciler for %s: %w", root.LogDID, rerr)
				}
				reconcilers = append(reconcilers, rec)
			}
			scanners := make([]rotationScanner, len(reconcilers))
			for i, rec := range reconcilers {
				scanners[i] = rec
			}
			rotationScan = buildRotationScanJob(scanners, time.Now)
		}

		// AT-2 read-side audit: assemble per-log inputs for the consistency
		// check from the journal (chain + journaling clock) and the durable
		// evidence store (latest verified head).
		var rotationConsistencySource monitoring.RotationConsistencySource
		if cfg.rotationConsistencyInterval > 0 && len(trustRoots) > 0 {
			roots := trustRoots
			rotationConsistencySource = func(jctx context.Context) (monitoring.WitnessRotationConsistencyConfig, error) {
				out := monitoring.WitnessRotationConsistencyConfig{
					Grace:      cfg.rotationAdoptionGrace,
					MaxHeadAge: cfg.frozenLogMaxHeadAge,
				}
				for _, root := range roots {
					records, rerr := rotJournal.RecordsFor(jctx, root.LogDID)
					if rerr != nil {
						return monitoring.WitnessRotationConsistencyConfig{}, fmt.Errorf("journal records for %s: %w", root.LogDID, rerr)
					}
					var recordedAt time.Time
					if at, ok, aerr := rotJournal.LatestRecordedAtFor(jctx, root.LogDID); aerr != nil {
						return monitoring.WitnessRotationConsistencyConfig{}, fmt.Errorf("journal recorded_at for %s: %w", root.LogDID, aerr)
					} else if ok {
						recordedAt = at
					}
					var (
						latestHead   *types.CosignedTreeHead
						latestHeadAt time.Time
					)
					if h, at, ok, herr := sthHeads.LatestVerifiedHeadWithTime(jctx, root.LogDID); herr != nil {
						return monitoring.WitnessRotationConsistencyConfig{}, fmt.Errorf("latest verified head for %s: %w", root.LogDID, herr)
					} else if ok {
						head := h
						latestHead = &head
						latestHeadAt = at
					}
					out.Logs = append(out.Logs, monitoring.RotationLogState{
						LogDID:                   root.LogDID,
						Genesis:                  root.Genesis,
						Records:                  records,
						LatestRotationRecordedAt: recordedAt,
						LatestHead:               latestHead,
						LatestHeadAt:             latestHeadAt,
					})
				}
				return out, nil
			}
		}

		didRegistry, err := buildDIDRegistry(peerHTTPClient)
		if err != nil {
			return fmt.Errorf("auditor: build DID registry: %w", err)
		}
		pipe, err := app.Build(app.Deps{
			Store:           st,
			RotationJournal: rotJournal,
			// Journal-first position-aware resolution (AT-2): inbound heads
			// verify against the set that COSIGNED them (era-correct across
			// rotations), and the slasher re-verifies historical equivocations
			// against their era set. Without this, verification is pinned to
			// the live snapshot and a transitional old-set head false-alarms
			// at every rotation boundary.
			WitnessSetResolver: journalResolver,
			WitnessSets:        witnessSets,
			NetworkID:          nid,
			DIDRegistry:        didRegistry,
			Peers:              peerFeeds(resolvedPeers),
			HorizonPeers:       horizonPeers(resolvedPeers),
			HorizonSamples:     cfg.horizonSamples,
			HorizonInterval:    cfg.horizonInterval,
			PeerHTTPClient:     peerHTTPClient,
			PollInterval:       cfg.pollInterval,
			PageLimit:          cfg.pageLimit,
			// Ladder 5 P9 (#21): operator-tunable bounded-concurrency for
			// the puller→reconciler hot path. 0 disables the throttle.
			MaxInFlightVerify: cfg.maxInFlightVerify,
			RetentionDays:     cfg.retentionDays,
			PruneInterval:     cfg.pruneInterval,
			Logger:            logger,
			// Always-on auditor-scope gate: the recognized set (genesis +
			// on-log) and the position it is resolved at. Never nil —
			// recognition is mandatory and network-governed.
			AuditorRegistry: auditorRegistry,
			// Optional scope-amendment stream merged with AuditorRegistry at
			// gate resolution; nil when AUDITOR_AMENDMENT_FILE is unset.
			AuditorAmendments: auditorAmendments,
			AuditorScopeAsOf: func(context.Context) types.LogPosition {
				return types.LogPosition{LogDID: exchangeDID, Sequence: auditorScopeAsOfSeq}
			},

			// Ladder 2 D6 (#21): periodic url_drift audit. Disabled by
			// default — gated on AUDITOR_URL_DRIFT_INTERVAL > 0. When
			// enabled, the scheduler runs CheckURLDrift every interval;
			// alerts surface via the existing scheduler→sink path.
			URLDriftResolver:           webResolver,
			URLDriftMaterializedSource: urlDriftSource,
			URLDriftInterval:           cfg.urlDriftInterval,
			URLDriftLocalLogDID:        exchangeDID,

			// #41: periodic governance-compliance audits (signature-policy /
			// algorithm-policy / protocol-version). Disabled by default —
			// gated on AUDITOR_GOVERNANCE_INTERVAL > 0.
			GovernanceSource:   governanceSource,
			GovernanceInterval: cfg.governanceInterval,

			// #42: periodic SMT-derivation commitment-ref verification.
			// Disabled by default — gated on AUDITOR_COMMITMENT_INTERVAL > 0.
			DerivationCommitmentSource:   commitmentSource,
			DerivationCommitmentInterval: cfg.commitmentInterval,

			// #43: periodic artifact custody-chain auditing.
			// Disabled by default — gated on AUDITOR_CUSTODY_INTERVAL > 0.
			CustodyChainSource:   custodySource,
			CustodyChainInterval: cfg.custodyInterval,

			// AT-2: incremental rotation log-scan (tail-omission closure) +
			// the safety/liveness consistency audit. Disabled by default —
			// gated on the respective AUDITOR_ROTATION_* intervals > 0.
			RotationScan:                rotationScan,
			RotationScanInterval:        cfg.rotationScanInterval,
			RotationConsistencySource:   rotationConsistencySource,
			RotationConsistencyInterval: cfg.rotationConsistencyInterval,
		})
		if err != nil {
			return fmt.Errorf("auditor: build pipeline: %w", err)
		}
		feed = pipe.Feed
		// Ladder 5 P10 (#21): capture done-channels so the shutdown
		// branch can JOIN both goroutines under shutdownWait — without
		// this, srv.Shutdown returns and main exits while the puller
		// and scheduler are still mid-iteration. They DO observe
		// ctx.Done() and unwind cleanly (PeerPuller.Run waits on a
		// WaitGroup of per-peer pollPeer loops each gated on ctx.Done;
		// monitoring.Scheduler.Run waits on a WaitGroup of per-job
		// loops with the same gate), but the join here ensures process
		// exit doesn't race ahead of them.
		pullerDone = make(chan struct{})
		go func() {
			defer close(pullerDone)
			_ = pipe.Puller.Run(ctx)
		}()
		if pipe.Scheduler != nil {
			schedulerDone = make(chan struct{})
			go func() {
				defer close(schedulerDone)
				pipe.Scheduler.Run(ctx)
			}()
		}
		// Activate the INDEPENDENT equivocation-detection leg. It reuses the
		// genesis-derived witness sets + resolver built above (so detection
		// stays zero-trust) and pushes self-certifying findings to the peer
		// gossip mesh. Disabled unless configured; a construction fault logs
		// loudly and we continue the (valuable) consume-side role.
		eqDone, eqCleanup, eqErr := startEquivocationScanner(ctx, equivScannerDeps{
			signingKeyFile: cfg.gossipSigningKeyFile,
			scanInterval:   cfg.equivScanInterval,
			networkID:      nid,
			peers:          resolvedPeers,
			witnessSets:    witnessSets,
			resolver:       endpointResolver,
			httpClient:     peerHTTPClient,
			logger:         logger,
		})
		if eqErr != nil {
			logger.Error("auditor: equivocation scanner failed to start; continuing without it",
				"error", eqErr.Error())
		} else {
			scannerDone, scannerCleanup = eqDone, eqCleanup
		}
		logger.Info("auditor: custody + inbound pipeline up",
			"exchange_did", exchangeDID, "witness_sets", len(witnessSets),
			"peers", len(resolvedPeers), "originator_discovery", cfg.discoverOriginator,
			"retention_days", cfg.retentionDays,
			// Proves which DID methods can resolve STH originators — an empty
			// list here is the "registers nothing" bug that rejected every event.
			"did_methods", didRegistry.RegisteredMethods(),
			"recognized_auditors", len(auditorRegistry))
	} else {
		logger.Warn("auditor: AUDITOR_GOSSIP_DSN unset — running health-only (no custody/feed)")
	}

	srv := &http.Server{
		Addr: cfg.listenAddr,
		// OTel SERVER span (outermost): extracts traceparent so any traced inbound
		// request continues its originating trace.
		Handler:      sdklog.NewOTelHandler(newMux(&ready, feed)),
		ReadTimeout:  cfg.readTimeout,
		WriteTimeout: cfg.writeTimeout,
		IdleTimeout:  cfg.idleTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("auditor: listening", "addr", cfg.listenAddr, "version", version)
		ready.Store(true)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("auditor: serve: %w", err)
	case <-ctx.Done():
		logger.Info("auditor: shutdown signal received, draining")
		ready.Store(false)
		shutCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownWait)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("auditor: graceful shutdown: %w", err)
		}
		// Ladder 5 P10 (#21): wait for the pipeline goroutines to
		// finish unwinding under the remaining shutdownWait budget.
		// Both goroutines already observe ctx.Done() (cancelled by
		// the SIGINT/SIGTERM that drove us into this branch); the
		// join here just ensures process exit doesn't race them.
		// In health-only mode both channels are nil and the joins
		// are no-ops.
		joinGoroutine(shutCtx, pullerDone, "puller", logger)
		joinGoroutine(shutCtx, schedulerDone, "scheduler", logger)
		joinGoroutine(shutCtx, scannerDone, "equivocation-scanner", logger)
		if scannerCleanup != nil {
			if err := scannerCleanup(shutCtx); err != nil {
				logger.Warn("auditor: equivocation publisher drain", "error", err.Error())
			}
		}
		logger.Info("auditor: stopped cleanly")
		return nil
	}
}

// joinGoroutine waits for done to close or shutCtx to expire. A nil
// done channel returns immediately — the health-only mode shape where
// no pipeline goroutine was launched. A deadline-exceeded wait surfaces
// a warn so an operator can see when shutdown was rough (a stuck
// per-peer HTTP fetch the puller couldn't cancel within the budget,
// etc.) vs. clean (every goroutine exited within shutdownWait).
//
// Split out for testability — main_test.go exercises both close-before-
// deadline and deadline-before-close paths.
func joinGoroutine(shutCtx context.Context, done <-chan struct{}, name string, logger *slog.Logger) {
	if done == nil {
		return
	}
	select {
	case <-done:
		logger.Info("auditor: background goroutine drained", "name", name)
	case <-shutCtx.Done():
		logger.Warn("auditor: shutdown deadline exceeded before goroutine exited", "name", name)
	}
}

// loadBootstrap parses the shared network bootstrap document — the same
// byte-identical doc the witness and ledger load — into the trust primitives
// the auditor needs: the NetworkID, the canonical exchange_did (diagnostic),
// and the genesis witness DIDs. doc.IDs() validates the constitutional
// genesis_quorum_k (1<=K<=N, 2K>N); the AUDITOR_WITNESS_QUORUM_K cross-check
// against it is the caller's job (reconcileWitnessQuorumK).
//
// It deliberately does NOT build the witness-set map: the map KEY is a log's
// gossip-originator did:key (resolved per-peer; see resolvePeers), which the
// bootstrap does not carry. Keying solely by exchange_did was the bug that left
// every STH unmatched ("no witness set for source_log_did <did:key…>").
func loadBootstrap(path string) (nid cosign.NetworkID, exchangeDID string, witnessDIDs []string, doc sdknetwork.BootstrapDocument, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nid, "", nil, doc, fmt.Errorf("read bootstrap %s: %w", path, err)
	}
	// #75 Phase B — fail-closed first contact with the auditor's OWN mounted
	// constitution, through the SDK's self-pin door (strict decode + the genesis
	// ceremony whenever the policy requires it; baseproof#52 owns the idiom and
	// documents why the self-pin equality is vacuous). An auditor must refuse to
	// audit AGAINST a require constitution it cannot verify.
	verified, err := sdknetwork.LoadSelfVerifiedBootstrap(raw)
	if err != nil {
		return nid, "", nil, sdknetwork.BootstrapDocument{}, fmt.Errorf(
			"bootstrap %s failed first-contact verification (stripped/incomplete genesis ceremony?): %w", path, err)
	}
	doc = *verified
	ids, err := doc.IDs()
	if err != nil {
		return nid, "", nil, sdknetwork.BootstrapDocument{}, fmt.Errorf("derive network identity from %s: %w", path, err)
	}
	if doc.ExchangeDID == "" || len(doc.GenesisWitnessSet) == 0 {
		return nid, "", nil, sdknetwork.BootstrapDocument{}, fmt.Errorf("bootstrap %s missing exchange_did / genesis_witness_set", path)
	}
	// doc is returned in full so callers can synthesize the genesis governance
	// baselines (GenesisSignaturePolicy → signature/algorithm/protocol genesis).
	return ids.NetworkID, doc.ExchangeDID, append([]string(nil), doc.GenesisWitnessSet...), doc, nil
}

// reconcileWitnessQuorumK derives the effective witness quorum K from the
// constitution and demotes AUDITOR_WITNESS_QUORUM_K to a cross-check. Since rc4,
// genesis_quorum_k is hashed into the NetworkID — the single source of truth
// for K — so an off-log env knob must never silently override it. The three
// arms of the demotion rule (envK is the already-parsed cfg.quorumK):
//
//	unset (0)        → adopt the constitutional value (doc.GenesisQuorumK)
//	set, == doc      → honoured (the operator's assertion agrees with the chain)
//	set, != doc      → fatal (the env disagrees with the identity-bound quorum)
//
// doc.IDs() (called by loadBootstrap before this) already enforced 1<=K<=N and
// the quorum-intersection invariant 2K>N, so the returned K is known-valid.
func reconcileWitnessQuorumK(doc sdknetwork.BootstrapDocument, envK int, bootstrapPath string) (int, error) {
	if envK != 0 && envK != doc.GenesisQuorumK {
		return 0, fmt.Errorf(
			"AUDITOR_WITNESS_QUORUM_K=%d disagrees with the constitutional genesis_quorum_k=%d in %s: "+
				"the quorum is bound into the NetworkID, so an env override cannot change it — "+
				"unset AUDITOR_WITNESS_QUORUM_K to adopt the constitutional value",
			envK, doc.GenesisQuorumK, bootstrapPath)
	}
	return doc.GenesisQuorumK, nil
}

// resolvedPeer pairs a configured peer feed with the gossip-originator DID the
// genesis witness set must be keyed by (the identity STHs arrive under).
type resolvedPeer struct {
	configuredDID string // AUDITOR_PEERS DID — the canonical/expected log DID (may be empty)
	baseURL       string
	originatorDID string // the operational did:key STHs are originated under (the witness-set key)
}

// resolvePeers turns the configured AUDITOR_PEERS feeds into resolvedPeers,
// determining each peer's gossip-originator DID.
//
//   - discover == true (default): fetch the peer's public GET /v1/log-info and
//     use "ledger_did" (its operational signer did:key — the gossip originator)
//     as the witness-set key. The configured DID is treated as the canonical
//     identity and cross-checked against the peer's advertised "log_did";
//     "network_id" is cross-checked against the bootstrap to refuse binding
//     trust across networks. Self-report is safe for ROUTING: the trust root is
//     the K-of-N witness cosignatures, which a peer cannot forge by lying about
//     its DID.
//   - discover == false: the configured DID is used verbatim as the originator
//     (an operator-pinned did:key — the production analogue of the ledger's
//     LEDGER_GOSSIP_PEER_DIDS).
func resolvePeers(ctx context.Context, feeds []peers.PeerFeed, discover bool, nid cosign.NetworkID, resolver sdklog.EndpointResolver, hc *http.Client, logger *slog.Logger) ([]resolvedPeer, error) {
	wantPrefix := networkIDHexPrefix(nid)
	out := make([]resolvedPeer, 0, len(feeds))
	for _, f := range feeds {
		baseURL := f.BaseURL
		if baseURL == "" {
			if resolver == nil {
				return nil, fmt.Errorf("peer %s has no base URL and no did:web resolver is configured", f.LogDID)
			}
			resolved, rErr := resolver.LedgerEndpoint(ctx, f.LogDID)
			if rErr != nil {
				return nil, fmt.Errorf("resolve did:web ledger endpoint for peer %s: %w", f.LogDID, rErr)
			}
			baseURL = resolved
			logger.Info("auditor: resolved did:web peer endpoint", "did", f.LogDID, "base_url", baseURL)
		}
		rp := resolvedPeer{configuredDID: f.LogDID, baseURL: baseURL, originatorDID: f.LogDID}
		if discover {
			info, err := discoverPeerOriginator(ctx, baseURL, hc, logger)
			if err != nil {
				return nil, fmt.Errorf("discover originator for peer %s: %w", baseURL, err)
			}
			if wantPrefix != "" && info.NetworkID != "" && info.NetworkID != wantPrefix {
				return nil, fmt.Errorf("peer %s network_id %q != bootstrap %q — refusing to bind trust across networks",
					baseURL, info.NetworkID, wantPrefix)
			}
			if f.LogDID != "" && info.LogDID != "" && f.LogDID != info.LogDID {
				logger.Warn("auditor: configured peer DID != peer's advertised log_did",
					"peer", baseURL, "configured", f.LogDID, "advertised", info.LogDID)
			}
			rp.originatorDID = info.LedgerDID
			logger.Info("auditor: bound genesis witness set to discovered gossip originator",
				"peer", baseURL, "canonical_did", info.LogDID, "originator_did", info.LedgerDID)
		}
		if rp.originatorDID == "" {
			return nil, fmt.Errorf("peer %s: no originator DID — set the DID in AUDITOR_PEERS or enable AUDITOR_ORIGINATOR_DISCOVERY", baseURL)
		}
		out = append(out, rp)
	}
	return out, nil
}

// buildResolverInputs assembles ResolverInputs for the SDK's
// authoritative endpoint resolver from the same bootstrap-derived inputs
// that buildWitnessSets consumes. Shared spec-extraction with that
// function (the WitnessSetSpec slice has the same shape, derived from
// the same resolved-peer + witness-DID inputs) — both call sites must
// agree on which logDIDs are tracked.
//
// Today the Materialized snapshot is empty (the auditor doesn't run an
// on-log scan); the resolver still satisfies sdkguard's load-bearing
// checks (MirrorManifest.LogDID + LogWitnessSets non-nil). When a scan
// loop lands, populate ResolverInputs.Materialized from
// crosslog.MaterializeFromEntries without touching the call site.
//
// DIDFallbackPolicy = FallbackAdvisory: every Resolve* call may
// optionally cross-check against the did:web fallback resolver, with
// mismatches surfaced via slog. Operators who want to PERMIT fallback
// (use DID-resolver URLs when the on-log walker has no record) override
// via an env var TBD; today FallbackAdvisory is the safe default for an
// auditor that has not yet wired on-log resolution.
func buildResolverInputs(
	rps []resolvedPeer,
	witnessDIDs []string,
	quorumK int,
	nid cosign.NetworkID,
	exchangeDID string,
	webResolver did.DIDResolver,
	logger *slog.Logger,
) (crosslog.ResolverInputs, error) {
	specs := make([]crosslog.WitnessSetSpec, 0, len(rps))
	seen := make(map[string]bool, len(rps))
	for _, rp := range rps {
		if seen[rp.originatorDID] {
			continue
		}
		seen[rp.originatorDID] = true
		specs = append(specs, crosslog.WitnessSetSpec{
			LogDID:      rp.originatorDID,
			WitnessDIDs: append([]string(nil), witnessDIDs...),
			QuorumK:     quorumK,
		})
	}
	logWitnessSets, err := crosslog.BuildLogWitnessSets(specs)
	if err != nil {
		return crosslog.ResolverInputs{}, fmt.Errorf("BuildLogWitnessSets: %w", err)
	}
	// Genesis witness keys → KnownWitnessKeys. The rotations slice is
	// nil because the auditor doesn't track on-log witness rotations
	// yet; when it does (clearcompass-ai/ledger#152 work), pass the
	// rotation chain here so previously-rotated-out PubKeyIDs remain
	// resolvable for historical lookups.
	genesisKeys, err := witness.KeysFromDIDs(witnessDIDs)
	if err != nil {
		return crosslog.ResolverInputs{}, fmt.Errorf("witness.KeysFromDIDs: %w", err)
	}
	knownKeys, err := crosslog.BuildKnownWitnessKeys(genesisKeys, nil)
	if err != nil {
		return crosslog.ResolverInputs{}, fmt.Errorf("BuildKnownWitnessKeys: %w", err)
	}
	_ = nid // unused today; reserved for future per-network resolver scoping
	return crosslog.ResolverInputs{
		MirrorManifest: discover.MirrorManifest{
			LogDID: exchangeDID,
		},
		Materialized:      crosslog.MaterializedNetwork{}, // empty until log-scan lands
		LogWitnessSets:    logWitnessSets,
		KnownWitnessKeys:  knownKeys,
		DIDFallback:       webResolver,
		DIDFallbackPolicy: discover.FallbackAdvisory,
		Logger:            logger,
	}, nil
}

// buildWitnessSets keys the genesis K-of-N witness set by each peer's
// gossip-originator DID — the value gossip looks up as
// WitnessSets[ev.Originator]. Distinct peers that resolve to the same
// originator collapse to one set.
//
// The cosignature verifier is selected from the network's SIGNATURE POLICY
// (allowedCosignSchemeTags, from the bootstrap's GenesisSignaturePolicy) via
// crosslog.BuildWitnessSetsForPolicy — not hardcoded. Every network today
// admits ECDSA only (init-network sets AllowedCosignSchemeTags=[0x01]), so
// this resolves to the exact ECDSA-only construction; the moment a network's
// policy admits BLS, the production BLS verifier is threaded automatically,
// and a policy admitting a scheme the auditor cannot verify fails the build
// loudly rather than silently under-counting it (#47).
//
// On-log BLS witnesses (SDK v1.54.0's WitnessEndpointDeclaration key/PoP
// fields) are projected into specs[].BLSWitnesses via
// crosslog.BLSWitnessesFromDeclarations at this SAME boot/hot-reload boundary
// once a materialized declaration snapshot is available — no standing scan;
// populate when the snapshot lands, exactly as buildResolverInputs documents
// for ResolverInputs.Materialized. Today that snapshot is empty, so no BLS
// witnesses are projected and behavior is byte-identical to before.
func buildWitnessSets(rps []resolvedPeer, witnessDIDs []string, quorumK int, nid cosign.NetworkID, allowedCosignSchemeTags []uint8) (map[string]*cosign.WitnessKeySet, error) {
	if len(rps) == 0 {
		return map[string]*cosign.WitnessKeySet{}, nil
	}
	specs := make([]crosslog.WitnessSetSpec, 0, len(rps))
	seen := make(map[string]bool, len(rps))
	for _, rp := range rps {
		if seen[rp.originatorDID] {
			continue
		}
		seen[rp.originatorDID] = true
		specs = append(specs, crosslog.WitnessSetSpec{
			LogDID:      rp.originatorDID,
			WitnessDIDs: append([]string(nil), witnessDIDs...),
			QuorumK:     quorumK,
		})
	}
	return crosslog.BuildWitnessSetsForPolicy(specs, nid, allowedCosignSchemeTags)
}

// horizonPeers maps resolved peers to the durability auditor's input: the
// gossip-originator did:key (the witness-set key) + the peer's base URL.
// Unlike peerFeeds (which labels by the canonical configured DID for the
// gossip feed), the horizon audit MUST key on the originator so
// witnessSets[originator] resolves.
func horizonPeers(rps []resolvedPeer) []horizon.Peer {
	out := make([]horizon.Peer, 0, len(rps))
	for _, rp := range rps {
		out = append(out, horizon.Peer{OriginatorDID: rp.originatorDID, BaseURL: rp.baseURL})
	}
	return out
}

// peerFeeds projects resolvedPeers back into the puller's PeerFeed list. The
// puller uses LogDID only for diagnostics + cursor identity (it verifies every
// event on its own envelope), so the canonical DID is the friendlier label;
// it falls back to the originator when no canonical DID was configured.
func peerFeeds(rps []resolvedPeer) []peers.PeerFeed {
	out := make([]peers.PeerFeed, 0, len(rps))
	for _, rp := range rps {
		label := rp.configuredDID
		if label == "" {
			label = rp.originatorDID
		}
		out = append(out, peers.PeerFeed{LogDID: label, BaseURL: rp.baseURL})
	}
	return out
}

// peerLogInfo is the subset of a peer ledger's GET /v1/log-info the auditor
// needs to bind trust: the operational gossip-originator did:key (LedgerDID),
// the canonical log DID, and the network_id prefix (for the cross-network guard).
type peerLogInfo struct {
	LogDID    string `json:"log_did"`
	LedgerDID string `json:"ledger_did"`
	NetworkID string `json:"network_id"`
}

// discoverPeerOriginator fetches GET {baseURL}/v1/log-info, retrying with
// bounded exponential backoff because the peer ledger may still be starting
// when the auditor boots. It returns once the peer advertises a non-empty
// ledger_did (its gossip originator) or ctx is cancelled / retries are spent.
func discoverPeerOriginator(ctx context.Context, baseURL string, hc *http.Client, logger *slog.Logger) (peerLogInfo, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/log-info"
	const maxAttempts = 6
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return peerLogInfo{}, ctx.Err()
		}
		info, err := fetchLogInfo(ctx, url, hc)
		switch {
		case err != nil:
			lastErr = err
		case info.LedgerDID == "":
			lastErr = fmt.Errorf("%s advertised empty ledger_did", url)
		default:
			return info, nil
		}
		logger.Warn("auditor: peer /v1/log-info not ready, retrying",
			"peer", baseURL, "attempt", attempt, "max", maxAttempts, "error", lastErr.Error())
		select {
		case <-ctx.Done():
			return peerLogInfo{}, ctx.Err()
		case <-time.After(retryBackoff(attempt)):
		}
	}
	return peerLogInfo{}, lastErr
}

// fetchLogInfo performs one GET /v1/log-info and decodes the fields we need.
func fetchLogInfo(ctx context.Context, url string, hc *http.Client) (peerLogInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return peerLogInfo{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return peerLogInfo{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return peerLogInfo{}, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var info peerLogInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info); err != nil {
		return peerLogInfo{}, fmt.Errorf("decode %s: %w", url, err)
	}
	return info, nil
}

// retryBackoff is exponential (1s,2s,4s,…) capped at 16s.
func retryBackoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > 16*time.Second {
		return 16 * time.Second
	}
	return d
}

// networkIDHexPrefix renders the first-8-bytes hex of the NetworkID, matching
// the ledger's /v1/log-info "network_id" format (cmd/ledger networkIDHex) so the
// cross-network guard in resolvePeers compares like for like. Empty for the
// zero NetworkID.
func networkIDHexPrefix(nid cosign.NetworkID) string {
	if nid == (cosign.NetworkID{}) {
		return ""
	}
	return fmt.Sprintf("%x", nid[:8])
}

// buildDIDRegistry constructs the DID verifier registry the gossip pipeline
// uses to resolve STH originators (and their envelope signers). Delegates to the
// canonical libs/auditing/didregistry.NewStandard, which registers BOTH did:key
// and did:web — covering ECDSA-secp256k1, Ed25519, and the SDK's three PQ
// algorithms (ML-DSA-65, ML-DSA-87, SLH-DSA-128s) automatically through the SDK's
// multicodec / verification-method-string dispatch.
//
// Registering did:web alongside did:key is required for PQ coverage: the SDK
// wires the post-quantum verifiers through the did:web verifier too, so without
// the "web" registration the auditor would silently reject every PQ-signed
// did:web event with "method not registered".
//
// peerHTTPClient threads the boot-hoisted outbound mTLS posture
// (libs/outbound.HoistFromEnv("AUDITOR_PEER_", ...)) into the did:web resolver,
// so every DID Document fetch presents the same client material the gossip
// puller uses.
func buildDIDRegistry(peerHTTPClient *http.Client) (*did.VerifierRegistry, error) {
	return didregistry.NewStandard(didregistry.Config{
		HTTPClient: peerHTTPClient,
	})
}

// envInt reads an int env var, falling back to def on empty/invalid.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envBool reads a bool env var (strconv.ParseBool grammar: 1/t/true/0/f/false),
// falling back to def on empty/invalid.
func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// parsePeers parses AUDITOR_PEERS. Each comma-separated entry is either an
// explicit "logDID=baseURL" pair, or — in did:web-native mode — a BARE did:web
// (no "=") whose ledger base URL is resolved from its DID document at startup
// (see resolvePeers). A bare entry must be a DID; other bare tokens are ignored.
func parsePeers(s string) []peers.PeerFeed {
	var out []peers.PeerFeed
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		didStr, url, ok := strings.Cut(p, "=")
		if !ok {
			if strings.HasPrefix(p, "did:") { // bare did:web — URL resolved from the DID doc
				out = append(out, peers.PeerFeed{LogDID: p, BaseURL: ""})
			}
			continue
		}
		if didStr == "" || url == "" {
			continue
		}
		out = append(out, peers.PeerFeed{LogDID: didStr, BaseURL: url})
	}
	return out
}

// newMux builds the operational surface. It is plain HTTP, not mTLS: the
// auditor exposes public transparency endpoints and scrape targets, so liveness
// probes present no client cert (unlike the JN API). Readiness flips false on
// shutdown so an orchestrator drains traffic before the process exits.
func newMux(ready *atomic.Bool, feed http.Handler) http.Handler {
	mux := http.NewServeMux()
	// The custodial evidence feed — the auditor's defining external surface.
	// Mounted only when a store is configured; third-party watchers + peers pull
	// /v1/gossip/since from here (the enforcer never serves this).
	if feed != nil {
		mux.Handle("/v1/gossip/", feed)
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, "{\"service\":\"auditor\",\"version\":%q}\n", version)
	})
	return mux
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// resolveFile implements the orchestrator-agnostic cert/key/bootstrap injection
// convention: an explicitly-configured path (AUDITOR_* env, already resolved by
// the caller) wins; otherwise the first existing file among the conventional
// candidates is used, in order: the standard mount path (/etc/auditor/… — k8s
// Secret volume / compose bind mount), then the PaaS secret-file path
// (/etc/secrets/<name>, where Render-class platforms place uploaded secret
// files). No candidate ⇒ "" — byte-identical to the pre-convention behavior.
// Boot-only stats.
func resolveFile(explicit string, candidates ...string) string {
	if explicit != "" {
		return explicit
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// portAddrOr returns ":$PORT" when the platform injects PORT (the Render /
// Cloud Run / Heroku contract), else the baked fallback. Consulted only after
// AUDITOR_LISTEN_ADDR, so it never overrides an operator-set address.
func portAddrOr(fallback string) string {
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		return ":" + p
	}
	return fallback
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
