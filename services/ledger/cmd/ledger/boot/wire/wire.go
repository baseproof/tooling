// Package wire implements Phase B of the ledger binary's lifecycle:
// compose the in-memory graph from the resources allocated in Phase A
// (deps.AppDeps), install OTel instruments on the existing
// MeterProvider, and start every long-running goroutine.
//
// FILE PATH:
//
//	cmd/ledger/boot/wire/wire.go
//
// DESCRIPTION:
//
//	Wire is the single entry point. It does NOT open new I/O
//	resources — those are alloc.Allocate's job. Wire reads handles
//	from *deps.AppDeps, constructs in-memory components (stores,
//	fetchers, sequencer, shipper, builder loop, gossip bundle, HTTP
//	server), and launches goroutines via lifecycle.SafeRunInWG that
//	join on AppDeps.WG.
//
//	When Wire returns successfully every goroutine is running and
//	the HTTP server is listening; the supervisor can immediately
//	enter its select on ctx.Done() / fatal.
//
// KEY ARCHITECTURAL DECISIONS:
//
//   - Wire is split across several files inside this package so each
//     file is small and cohesive (stores.go, instruments.go,
//     gossip.go, handlers.go, runtime.go). The package boundary is
//     wire/; the file boundaries are organizational.
//
//   - WireConfig is the alloc-relevant + wire-relevant projection of
//     cmd/ledger.Config — passed by value so the boot package never
//     imports the binary's full config struct.
//
//   - Every goroutine joins AppDeps.WG so teardown's
//     "background-goroutines" step can wait once and have all
//     workers drain before the I/O closers fire.
//
//   - Errors during wire abort cleanly: wire returns; main calls
//     deps.UnwindReverse to release the resources alloc opened.
package wire

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/netutil"

	"github.com/baseproof/baseproof/authz"
	sdkbuilder "github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/artifact"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/exchange/policy"
	sdklog "github.com/baseproof/baseproof/log"

	"github.com/baseproof/baseproof/log/discover"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/tooling/libs/anchorfeed"

	"go.opentelemetry.io/otel"

	"github.com/baseproof/tooling/services/ledger/admission"
	"github.com/baseproof/tooling/services/ledger/anchor"
	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/api/middleware"
	"github.com/baseproof/tooling/services/ledger/apitypes"
	"github.com/baseproof/tooling/services/ledger/artifactstore"
	"github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/deps"
	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/schemareg"
	"github.com/baseproof/tooling/services/ledger/contentvalidation"
	"github.com/baseproof/tooling/services/ledger/gossipnet"
	"github.com/baseproof/tooling/services/ledger/gossipstore"
	"github.com/baseproof/tooling/services/ledger/integrity"
	"github.com/baseproof/tooling/services/ledger/internal/auditorregistry"
	"github.com/baseproof/tooling/services/ledger/internal/clienttls"
	"github.com/baseproof/tooling/services/ledger/lifecycle"
	"github.com/baseproof/tooling/services/ledger/observability"
	"github.com/baseproof/tooling/services/ledger/recovery"
	"github.com/baseproof/tooling/services/ledger/reservation"
	"github.com/baseproof/tooling/services/ledger/sequencer"
	"github.com/baseproof/tooling/services/ledger/shipper"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/store/indexes"
	"github.com/baseproof/tooling/services/ledger/tessera"
	"github.com/baseproof/tooling/services/ledger/wal"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// Config is the projection of cmd/ledger.Config relevant to Phase B
// wiring. main.go converts its full Config to this struct before
// calling Wire.
type Config struct {
	LogDID    string
	LedgerDID string
	NetworkID cosign.NetworkID

	BatchSize            int
	PollInterval         time.Duration
	DeltaWindow          int
	MMD                  time.Duration
	SequencerInterval    time.Duration
	SequencerMaxInFlight int
	ShipperPollInterval  time.Duration
	ShipperMaxInFlight   int
	ShipperMaxAttempts   int
	ShipperBackoffBase   time.Duration
	ShipperBackoffMax    time.Duration
	ShipperHealthyWindow time.Duration
	ShipperAIMDStep      float64
	CheckpointInterval   time.Duration
	SMTNodeCacheSize     int

	RecentEntryCacheSize     int
	RecentEntryCacheMaxBytes int64

	ArchiveShardIndexSource string

	AnchorInterval time.Duration
	AnchorSources  []anchor.AnchorSource

	ParentLogDID         string
	ParentAdmissionURL   string
	ParentAnchorInterval time.Duration

	EpochWindowSeconds    int
	EpochAcceptanceWindow int
	MaxEntrySize          int64

	GossipPeerEndpoints []string
	GossipPeerDIDs      []string
	WitnessQuorumK      int
	GenesisWitnessSet   []string

	GenesisAdmissionAuthorities [][20]byte
	GenesisAdmissionPolicy      authz.AdmissionPolicy

	GenesisBootstrapDocument network.BootstrapDocument

	ServerAddr          string
	TLSCertFile         string
	TLSKeyFile          string
	InboundClientCAFile string
	MaxConcurrentConns  int
	PprofAddr           string

	PeerClientCertFile string
	PeerClientKeyFile  string
	PeerCAFile         string

	TileServeDisable bool
	TileBackend      string
	TileBucketPrefix string
	TileCacheSize    int

	ByteStoreBackend       string
	ByteStorePublicBaseURL string

	MetricsEnable bool
	Version       string
	Commit        string
	BuildTime     string
	SDKVersion    string

	LogInfo api.LogInfo

	NetworkPeers   api.WireFederationGraph
	NetworkMirrors api.WireMirrorManifest

	// PublicURL + ManifestAnchor feed the GET /v1/network/bundle composer
	// (see cmd/ledger Config for the operator contract).
	PublicURL      string
	ManifestAnchor string
}

// walEntryTrace adapts the WAL committer to builder.EntryTraceReader: it resolves
// an entry's admission traceparent at a committed seq (seq → hash → Meta.TraceContext)
// so the checkpoint.cycle span can LINK to the entries it commits.
type walEntryTrace struct{ wal *wal.Committer }

func (w walEntryTrace) TraceContextAt(ctx context.Context, seq uint64) (string, error) {
	hash, err := w.wal.HashAt(ctx, seq)
	if err != nil {
		return "", err
	}
	meta, err := w.wal.MetaState(ctx, hash)
	if err != nil {
		return "", err
	}
	return meta.TraceContext, nil
}

// Wire is the Phase B orchestrator.
func Wire(ctx context.Context, cfg Config, d *deps.AppDeps) error {
	// buildPeerHTTPClient ALWAYS returns a non-nil *http.Client (see
	// its doc). Assign unconditionally so every downstream consumer
	// (gossip, cosign, head-sync, anti-entropy, equivocation
	// monitor) receives a live client — the v1.34 SDK contract is
	// "no silent fallback to a plaintext default", and the ledger
	// matches that posture in its own boot.
	client, err := buildPeerHTTPClient(cfg)
	if err != nil {
		return fmt.Errorf("wire: peer mTLS config: %w", err)
	}
	// Trace every outbound hop: wrap the shared transport so each request emits a
	// client span AND injects the W3C traceparent. The cosign→witness, gossip,
	// and anchor-publish calls then stitch into the SAME trace as the work that
	// triggered them — completing the cross-component picture.
	client.Transport = sdklog.WithOTel(client.Transport)
	d.OutboundHTTPClient = client
	if cfg.PeerClientCertFile != "" {
		d.Logger.Info("peer mTLS client configured",
			"cert", cfg.PeerClientCertFile,
			"ca", cfg.PeerCAFile)
	} else {
		d.Logger.Info("peer HTTP client configured (plaintext; no PeerClientCertFile)",
			"ca", cfg.PeerCAFile)
	}

	tesseraAdapter := composeStores(ctx, cfg, d)

	if cfg.RecentEntryCacheSize > 0 || cfg.RecentEntryCacheMaxBytes > 0 {
		cache, cerr := store.NewBoundedRecentEntryCache(store.CacheConfig{
			MaxEntries: cfg.RecentEntryCacheSize,
			MaxBytes:   cfg.RecentEntryCacheMaxBytes,
			LogDID:     cfg.LogDID,
		})
		if cerr != nil {
			return fmt.Errorf("wire: recent-entry cache: %w", cerr)
		}
		d.RecentEntryCache = cache
		d.Logger.Info("recent-entry cache enabled",
			"max_entries", cfg.RecentEntryCacheSize,
			"max_bytes", cfg.RecentEntryCacheMaxBytes,
			"log_did", cfg.LogDID)
	} else {
		d.Logger.Info("recent-entry cache disabled (both LEDGER_RECENT_ENTRY_CACHE_SIZE and LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES are 0)")
	}

	if cfg.ArchiveShardIndexSource != "" {
		shards, lserr := lifecycle.LoadShardIndex(ctx, cfg.ArchiveShardIndexSource, d.OutboundHTTPClient)
		if lserr != nil {
			return fmt.Errorf("wire: archive shard index %q: %w", cfg.ArchiveShardIndexSource, lserr)
		}
		d.ArchiveReader = lifecycle.NewArchiveReader(shards, d.OutboundHTTPClient)
		d.Logger.Info("archive reader enabled",
			"source", cfg.ArchiveShardIndexSource,
			"shards", len(shards))
	}

	d.DiffController = middleware.NewDifficultyController(
		store.NewSequenceCursor(d.PgPool.DB),
		middleware.DefaultDifficultyConfig(),
		d.Logger,
	)

	installPrebuilderInstruments(d)

	if err = wireWitnessQuorum(ctx, cfg, d); err != nil {
		return fmt.Errorf("wire: %w", err)
	}

	if err = wireGossip(ctx, cfg, d); err != nil {
		return fmt.Errorf("wire: gossip: %w", err)
	}

	cosigner, err := wireWitnessCosigner(cfg, d)
	if err != nil {
		return fmt.Errorf("wire: witness cosigner: %w", err)
	}

	escrowOverrideHandler := wireEscrowOverride(cfg, cosigner, d)

	// Artifact content store — ONE content-addressed store shared by the
	// derivation-commitment publisher (the #190 off-log mutation blobs) and the
	// reservation manager (docket-artifact uploads). Built once here so the
	// in-memory dev/test fallback doesn't diverge between the two paths.
	d.ArtifactContentStore = commitmentContentStore(d.Logger)

	// FINISH-gate content-type validator (verification code, not an on-log fact):
	// the SDK crypto/artifact mechanism — reference validators for the deployment's
	// accepted MIME types (LEDGER_ARTIFACT_ACCEPTED_MIME_TYPES), any custom
	// validators a network registered via contentvalidation.Register, and a
	// deny-unknown stance (LEDGER_ARTIFACT_DENY_UNKNOWN_MIME). nil => no validation.
	contentValidator := buildContentValidator(d.Logger)

	// Reservation manager (ledger#193): the RESERVE -> token -> UPLOAD -> FINISH
	// lifecycle for docket artifacts, backed by Postgres with a CAS-safe FINISH.
	// Constructed before composeHandlers (it serves the FINISH route) and before
	// composeBuilderLoop (which reuses ArtifactContentStore). The REAP goroutine
	// is launched in startGoroutines.
	d.ReservationManager = reservation.NewManager(reservation.Config{
		Store:     reservation.NewPostgresStore(d.PgPool.DB),
		Content:   d.ArtifactContentStore,
		Validator: contentValidator,
		SignKey:   uploadTokenKey(d.Logger),
		NetworkID: fmt.Sprintf("%x", cfg.NetworkID),
		TTL:       reservationTTL(),
	})

	bl, anchorPub := composeBuilderLoop(ctx, cfg, d, tesseraAdapter)
	d.BuilderLoop = bl
	d.AnchorPublisher = anchorPub

	// The CheckpointLoop is the single authoritative position of the log: it
	// tiles the latest committed root durable, then cosigns + publishes THAT root
	// as the horizon, lagging the commit cursor (builder/checkpoint_loop.go). It
	// replaces both the legacy reconciler→publisher seam AND the
	// builder's pre-commit cosign. Enabled when SMT tile emission is configured
	// (the substrate the horizon is served from) — the same boundary the legacy
	// reconciler used.
	var checkpointLoop *builder.CheckpointLoop
	if tileDir := strings.TrimSpace(os.Getenv("LEDGER_SMT_TILE_EMIT_DIR")); tileDir != "" {
		var checkpointPub builder.CheckpointPublisher = tesseraAdapter
		if s3, ok := d.ByteStore.(*bytestore.S3); ok {
			checkpointPub = store.NewS3CheckpointPublisher(s3)
			// Ship tessera log tiles + entry bundles to the shared object store
			// BEFORE each cosigned checkpoint is published, so PG-free read-front
			// pods reconstruct inclusion proofs and /raw seq→hash from S3 alone —
			// no filesystem shared with the writer. d.TileBackend is the writer's
			// POSIX tile source; the shipper is incremental (durable size cursor),
			// a handful of objects per publish, never a tree walk (scales to the
			// 10B-entry / 500-TPS target). Fail-closed: a ship error withholds the
			// horizon, so a reader never sees a head whose tiles aren't durable.
			shipper, serr := tessera.NewTileShipper(ctx, d.TileBackend, s3, d.Logger)
			if serr != nil {
				return fmt.Errorf("tessera tile shipper: %w", serr)
			}
			checkpointPub = tessera.NewShippingPublisher(checkpointPub, shipper)
		}
		emitter := store.NewBuildTilesEmitter(d.NodeStore, smtTileStore(d.ByteStore, tileDir))
		if nodeIndexEnabled() {
			// The SAME durable node index as the builder read-through: the emitter
			// both POPULATES it (every interior it makes durable, before the tail is
			// pruned) and consults it on its per-emit read-through — closing the
			// emitter face of the leaf-loss fault.
			emitter.SetNodeIndex(store.NewPGNodeIndex(ctx, d.PgPool.DB))
		}
		checkpointLoop = builder.NewCheckpointLoop(
			store.NewSMTCommitCursor(store.NewSMTRootStateStore(d.PgPool.DB)),
			store.NewPgTileFrontier(d.PgPool.DB),
			emitter,
			tesseraAdapter, // CheckpointRooter — RootAtSize from durable Merkle tiles
			checkpointPub,  // CheckpointPublisher — POSIX (tessera) or shared S3
			cosigner,       // WitnessCosigner — K-of-N over the durable head
			// ReceiptRoot from entry_index metadata only — never the Badger WAL
			// bytes, so a shipped+pruned delta entry can't stall the horizon.
			store.NewEntryIndexReceiptRanger(d.PgPool.DB, cfg.LogDID),
			cfg.CheckpointInterval, // LEDGER_CHECKPOINT_INTERVAL (0 ⇒ 1s default)
			d.Logger,
		)
		// Witness-quorum SRE signal (Backpressure-Stall trigger). The core loop
		// stays gossip/metrics-agnostic and fires an injected hook on each
		// "witness_quorum_unavailable" hold; bind it here to the canonical counter
		// baseproof_witness_quorum_failures_total, labelled with the deployment's
		// NetworkID hex prefix (cardinality 1). The counter no-ops until
		// installPrebuilderInstruments wires the gossip meter.
		networkIDHex := lifecycle.NetworkIDHex(cfg.NetworkID[:])
		checkpointLoop.OnWitnessQuorumFailure(func(ctx context.Context) {
			gossipnet.IncWitnessQuorumFailure(ctx, networkIDHex)
		})
		// Link the checkpoint.cycle span to a bounded sample of the entries it
		// commits, resolving each entry's admission traceparent from the WAL Meta
		// (seq → hash → Meta.TraceContext) — checkpoint ⇄ entry trace navigability.
		if d.WALCommitter != nil {
			checkpointLoop.SetEntryTraceReader(walEntryTrace{wal: d.WALCommitter})
		}
		// 1.2a: archive each published checkpoint's dense receipt-commitment set to the
		// shared object store (PutObject — the S3/SeaweedFS standard interface) so receipt
		// proofs reconstruct PG-free. Re-gathers the SAME set the cosigned ReceiptRoot was
		// computed from. Fail-closed: the loop writes it BEFORE the horizon and an
		// object-store write error WITHHOLDS the horizon (Step 9a), since a PG-off reader
		// has no PG fallback. Object-store deployments only (POSIX single-node co-locates PG).
		if s3, ok := d.ByteStore.(*bytestore.S3); ok {
			checkpointLoop.SetReceiptArchiver(store.NewReceiptArchiveWriter(
				store.NewEntryIndexReceiptRanger(d.PgPool.DB, cfg.LogDID), s3))
		}
		// Bound the in-memory SMT node tail: after each frontier advance the loop
		// evicts the nodes it just made durable (store.TailedNodeStore.PruneTiled).
		// Load-bearing — without it the tail accumulates every committed node
		// (O(history)) and the writer OOMs (the node DAG is de-polluted out of PG and
		// lives only in the tail until tiled).
		checkpointLoop.SetTailPruner(d.NodeStore)
		// Temporary tail-GC safety audit (LEDGER_TAIL_GC_AUDIT=1): NON-destructive.
		// Before enabling the orphan-prune, prove its assumption holds in a real soak
		// — that no PUBLISHED root still reaches a non-durable node the prune would
		// drop (published ⇒ durable). A non-zero violation count is logged at ERROR
		// (the assumption is FALSE — do NOT enable the prune); zero confirms safety.
		if os.Getenv("LEDGER_TAIL_GC_AUDIT") == "1" {
			checkpointLoop.OnTailGCAudit(func(ctx context.Context, candidates, violations int, sample [32]byte) {
				if violations > 0 {
					d.Logger.ErrorContext(ctx, "tail-gc audit VIOLATION: a published root reaches a non-durable tail node the orphan-prune would drop — published⇒durable does NOT hold; do not enable the prune",
						"violations", violations, "candidates", candidates, "sample_node", fmt.Sprintf("%x", sample[:8]))
					return
				}
				d.Logger.DebugContext(ctx, "tail-gc audit ok (orphan-prune safe)", "risky_candidates", candidates)
			})
			d.Logger.Info("tail-gc safety audit enabled (LEDGER_TAIL_GC_AUDIT=1, non-destructive)")
		}
		// Tail orphan prune (LEDGER_TAIL_GC_PRUNE=1): the O(history)→O(gap) fix —
		// evict cross-batch orphans each checkpoint so the in-memory tail stays flat.
		// Opt-in; keep LEDGER_TAIL_GC_AUDIT=1 on alongside as a live safety net.
		if os.Getenv("LEDGER_TAIL_GC_PRUNE") == "1" {
			checkpointLoop.EnableTailOrphanPrune()
			d.Logger.Info("tail orphan prune enabled (LEDGER_TAIL_GC_PRUNE=1): tail bounded to the un-tiled gap")
		}
		d.Logger.Info("checkpoint loop enabled", "tile_dir", tileDir, "quorum_k", cfg.WitnessQuorumK)
	}

	// Operator one-shot (G1): when LEDGER_ARCHIVE_BACKFILL_ON_BOOT is set, regenerate the
	// cold-read archives (checkpoints/<n> + the size index, receipts/<n>, the rotation
	// index) for ALL published history from the Postgres cosigned ladder, BEFORE serving.
	// This gives history that PREDATES the forward archivers a cold form in the object
	// store — the precondition for bounding Postgres, since a bounded PG must reconstruct
	// below its window from the object store alone. Idempotent + best-effort per item; a
	// ladder (Postgres) fault fails boot loudly so the operator's explicit request is never
	// silently skipped. Object-store deployments only: a POSIX single-node co-locates PG
	// and serves no cold reads, so there is nothing to backfill.
	if archiveBackfillOnBoot() {
		s3, ok := d.ByteStore.(*bytestore.S3)
		if !ok {
			d.Logger.Warn("LEDGER_ARCHIVE_BACKFILL_ON_BOOT set but byte store is not an object store — skipping (cold archives are object-store only)")
		} else {
			d.Logger.Info("archive backfill on boot: regenerating cold archives from the cosigned ladder")
			rep, abErr := recovery.ArchiveBackfill(ctx, recovery.ArchiveBackfillDeps{
				Pool:        d.PgPool.DB,
				ObjectStore: s3,
				LogDID:      cfg.LogDID,
				MinSigs:     cfg.WitnessQuorumK,
				Logger:      d.Logger,
			})
			if abErr != nil {
				return fmt.Errorf("wire: archive backfill on boot: %w", abErr)
			}
			d.Logger.Info("archive backfill on boot complete",
				"checkpoints", rep.Checkpoints, "checkpoint_errs", rep.CheckpointErrs,
				"receipt_errs", rep.ReceiptErrs, "rotation_err", rep.RotationErr)
		}
	}

	reg, err := schemareg.BuildLedgerSchemaRegistry()
	if err != nil {
		return fmt.Errorf("wire: schemareg.BuildLedgerSchemaRegistry: %w", err)
	}
	d.SchemaRegistry = reg

	handlers, err := composeHandlers(ctx, cfg, d, tesseraAdapter, escrowOverrideHandler, bl.Tree())
	if err != nil {
		return fmt.Errorf("wire: handlers: %w", err)
	}

	seq := composeSequencer(cfg, d)
	d.Sequencer = seq
	ship := composeShipper(cfg, d)
	d.Shipper = ship
	detector := composeIntegrityDetector(d)
	smtDetector := composeSMTDetector(d)

	installLateBoundGauges(cfg, d, seq, ship, checkpointLoop)

	if err := composeServers(cfg, d, handlers); err != nil {
		return fmt.Errorf("wire: servers: %w", err)
	}

	if err := recoverTailOnBoot(ctx, d); err != nil {
		return fmt.Errorf("wire: tail recovery: %w", err)
	}

	startGoroutines(ctx, d, cfg, bl, checkpointLoop, seq, ship, detector, smtDetector)

	return nil
}

// archiveBackfillOnBoot reports whether the operator requested a one-shot cold-archive
// backfill at boot (LEDGER_ARCHIVE_BACKFILL_ON_BOOT). Off by default — the live writer
// archives forward, so this is only for history that predates the archivers and is run
// once (the operator clears the flag after).
func archiveBackfillOnBoot() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LEDGER_ARCHIVE_BACKFILL_ON_BOOT"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// buildPeerHTTPClient always returns a non-nil *http.Client. When
// the deployment configures peer mTLS material (PeerClientCertFile +
// PeerClientKeyFile, optionally PeerCAFile), the returned client
// presents that material on every outbound peer connection. When no
// mTLS material is configured, it returns a plaintext client with
// the same RetryAfterRoundTripper posture — appropriate for
// dev/test and for deployments that terminate mTLS at an upstream
// proxy.
//
// As of the v1.34 SDK contract, downstream constructors (gossip,
// cosign, head-sync, anti-entropy, equivocation monitor) reject a
// nil *http.Client at construction time — see baseproof CHANGELOG
// 1.34.0. This function consequently never returns nil; callers can
// always assign the result to d.OutboundHTTPClient unconditionally.
func buildPeerHTTPClient(cfg Config) (*http.Client, error) {
	tlsCfg, err := (&clienttls.Flags{
		CertFile: cfg.PeerClientCertFile,
		KeyFile:  cfg.PeerClientKeyFile,
		CAFile:   cfg.PeerCAFile,
	}).TLSConfig()
	if err != nil {
		return nil, err
	}
	// sdklog.DefaultClient accepts a nil *tls.Config and produces a
	// plaintext transport; the resulting client still carries the
	// RetryAfterRoundTripper for 503 backpressure handling, which
	// matters as much for plaintext fan-out as it does for mTLS.
	return sdklog.DefaultClient(30*time.Second, tlsCfg), nil
}

func recoverTailOnBoot(ctx context.Context, d *deps.AppDeps) error {
	committed, err := d.SMTRootState.Read(ctx)
	if err != nil {
		return fmt.Errorf("read committed root: %w", err)
	}
	_, fRoot, err := store.NewPgTileFrontier(d.PgPool.DB).ReadFrontier(ctx)
	if err != nil {
		return fmt.Errorf("read tile frontier: %w", err)
	}
	if committed.CurrentRoot == fRoot {
		return nil
	}
	leaves, err := d.LeafStore.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list leaves: %w", err)
	}
	d.Logger.Warn("tail recovery: tile frontier behind committed root; replaying smt_leaves to rebuild the node tail",
		"committed_seq", committed.CommittedThroughSeq, "leaves", len(leaves))
	if err := store.RecoverTail(ctx, leaves, d.NodeStore, committed.CurrentRoot); err != nil {
		return err
	}
	d.Logger.Info("tail recovery complete",
		"leaves_replayed", len(leaves),
		"committed_root", fmt.Sprintf("%x", committed.CurrentRoot[:8]))
	return nil
}

func composeStores(ctx context.Context, cfg Config, d *deps.AppDeps) *tessera.TesseraAdapter {
	pool := d.PgPool.DB
	d.EntryStore = store.NewEntryStore(pool)
	d.CreditStore = store.NewCreditStore(pool)
	d.CommitStore = store.NewCommitmentStore(pool)
	d.LeafStore = store.NewPostgresLeafStore(pool)
	cacheSize := cfg.SMTNodeCacheSize
	if cacheSize <= 0 {
		cacheSize = 4096
	}
	tileDir := strings.TrimSpace(os.Getenv("LEDGER_SMT_TILE_EMIT_DIR"))
	if tileDir == "" {
		tileDir = "/var/lib/ledger/tiles"
	}
	smtTiles := smtTileStore(d.ByteStore, tileDir)
	tiled := smt.NewTiledNodeStore(ctx, smtTiles, smt.NewTileCache(cacheSize))
	if nodeIndexEnabled() {
		// Make the durable read-through COMPLETE: a band-interior reached by a
		// compressed pointer resolves via its owning tile top (the node index)
		// instead of faulting "missing node (referenced by ancestor)" → PathD →
		// lost leaf. The emitter populates this same index at emit time.
		tiled.SetNodeIndex(store.NewPGNodeIndex(ctx, pool))
	}
	d.NodeStore = store.NewTailedNodeStore(tiled)
	d.NodeStore.SetMissProbe(smtTiles) // leaf-loss trace: classify Get misses (tile-top vs interior)
	d.TreeHeadStore = store.NewTreeHeadStore(pool)
	d.SMTRootState = store.NewSMTRootStateStore(pool)
	return tessera.NewTesseraAdapter(ctx, d.TesseraEmbedded, d.TileReader, d.Logger)
}

// nodeIndexEnabled reports whether the durable SMT node→tile-top index is active
// (LEDGER_NODE_INDEX; default ON). It is the completeness backstop that makes any
// emitted node resolvable by hash, regardless of walk order — the fix for the
// leaf-loss / tiling-stall fault. Set LEDGER_NODE_INDEX=0 only to roll back the
// added emit-time index writes in an emergency; with it off, the node store
// reverts to top-only resolution (the prior behavior) and a compressed top-skip
// can again fault — caught loudly by the builder's MissingNodeError halt.
func nodeIndexEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LEDGER_NODE_INDEX"))) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

func smtTileStore(bs bytestore.Backend, tileDir string) store.SMTTileStore {
	if s3, ok := bs.(*bytestore.S3); ok {
		return store.NewS3SMTTileStore(s3)
	}
	return store.NewPosixSMTTileStore(tileDir)
}

func smtMaxTileLag() uint64 {
	if v := strings.TrimSpace(os.Getenv("LEDGER_SMT_MAX_TILE_LAG")); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 100000
}

// commitmentContentStore builds the off-log store for derivation-commitment
// mutation blobs (the #190 path). The commitment sidecar is PUBLIC content
// fetched by CID, so a posix-backed artifact store at LEDGER_ARTIFACT_STORE_DIR
// is the simple in-process backing. With the dir unset it falls back to an
// in-memory store (dev / tests) — durable enough for a single process, with a
// warning that the blobs won't survive restart.
func commitmentContentStore(logger *slog.Logger) storage.ContentStore {
	// Service mode: when LEDGER_ARTIFACT_STORE_URL is set, talk to a standalone
	// artifact-store (cmd/artifact-store) over the SDK HTTPContentStore client —
	// the in-process<->service flip is this config choice, not a code change.
	if url := strings.TrimSpace(os.Getenv("LEDGER_ARTIFACT_STORE_URL")); url != "" {
		cs, err := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
			BaseURL: url,
			Client:  &http.Client{Timeout: 30 * time.Second},
		})
		if err != nil {
			logger.Error("artifact store: http mode init failed; falling back to local", "url", url, "error", err)
		} else {
			logger.Info("artifact store: http (service) mode", "url", url)
			return cs
		}
	}
	dir := strings.TrimSpace(os.Getenv("LEDGER_ARTIFACT_STORE_DIR"))
	if dir == "" {
		logger.Warn("artifact store: LEDGER_ARTIFACT_STORE_DIR unset; using in-memory store " +
			"(commitment mutation blobs are not durable across restart)")
		return artifactstore.NewStore(artifactstore.NewMemoryBackend())
	}
	b, err := artifactstore.NewPosixBackend(dir)
	if err != nil {
		logger.Error("artifact store: posix backend init failed; falling back to in-memory",
			"dir", dir, "error", err)
		return artifactstore.NewStore(artifactstore.NewMemoryBackend())
	}
	logger.Info("artifact store: posix backend wired", "dir", dir)
	return artifactstore.NewStore(b)
}

// uploadTokenKey returns the ed25519 signing key for artifact upload tokens
// (the relay-defense seal on RESERVE -> UPLOAD). It loads a base64 std-encoded
// 32-byte seed from LEDGER_UPLOAD_TOKEN_KEY when set; otherwise it generates an
// ephemeral key and warns. An ephemeral key is safe within a single process
// lifetime — tokens are short-lived (reservation TTL) — but tokens minted
// before a restart won't verify after it, and in a multi-replica deployment
// every replica must share the SAME seed or a token minted by one replica
// won't verify at another. Set LEDGER_UPLOAD_TOKEN_KEY in production.
func uploadTokenKey(logger *slog.Logger) ed25519.PrivateKey {
	if raw := strings.TrimSpace(os.Getenv("LEDGER_UPLOAD_TOKEN_KEY")); raw != "" {
		seed, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			logger.Error("LEDGER_UPLOAD_TOKEN_KEY is not valid base64; generating an ephemeral key", "error", err)
		} else if len(seed) != ed25519.SeedSize {
			logger.Error("LEDGER_UPLOAD_TOKEN_KEY wrong length; generating an ephemeral key",
				"want_bytes", ed25519.SeedSize, "got_bytes", len(seed))
		} else {
			logger.Info("artifact upload token key loaded from LEDGER_UPLOAD_TOKEN_KEY")
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		// crypto/rand failure is fatal-class; the manager would be unusable.
		panic(fmt.Sprintf("wire: ed25519 upload-token key generation failed: %v", err))
	}
	logger.Warn("artifact upload token key is EPHEMERAL (LEDGER_UPLOAD_TOKEN_KEY unset); " +
		"upload tokens won't survive a restart and won't verify across replicas")
	return priv
}

// reservationTTL is the window between RESERVE and FINISH before the reaper
// expires an un-finished reservation. Overridable via LEDGER_RESERVATION_TTL
// (any time.ParseDuration string); defaults to 15m.
func reservationTTL() time.Duration {
	if v := strings.TrimSpace(os.Getenv("LEDGER_RESERVATION_TTL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 15 * time.Minute
}

// reservationFinishHandler returns the POST /v1/artifacts/{cid}/finish handler,
// or nil when the reservation manager is unwired (the route is then simply not
// mounted by api.NewServer).
func reservationFinishHandler(d *deps.AppDeps) http.HandlerFunc {
	if d.ReservationManager == nil {
		return nil
	}
	return reservation.NewFinishHandler(d.ReservationManager)
}

// artifactReserveHandler builds the POST /v1/artifacts/reserve handler over the
// shared submission deps + the reservation Manager, or nil when the manager is
// unwired (the route is then simply not mounted).
func artifactReserveHandler(deps *api.SubmissionDeps, mgr *reservation.Manager) http.HandlerFunc {
	if mgr == nil {
		return nil
	}
	return api.NewArtifactReserveHandler(deps, mgr)
}

// buildContentValidator builds the FINISH-gate content-type validator from
// deployment config — verification code, not an on-log policy. The accepted MIME
// set is a gating knob (LEDGER_ARTIFACT_ACCEPTED_MIME_TYPES, comma-separated) and
// the unknown-type stance is LEDGER_ARTIFACT_DENY_UNKNOWN_MIME. Custom validators
// registered by a network via contentvalidation.Register (an init() hook) are
// folded in automatically. Returns nil — no validation — when nothing is to be
// enforced.
func buildContentValidator(logger *slog.Logger) artifact.ContentValidator {
	accepted := splitAndTrim(os.Getenv("LEDGER_ARTIFACT_ACCEPTED_MIME_TYPES"))
	denyUnknown := strings.EqualFold(strings.TrimSpace(os.Getenv("LEDGER_ARTIFACT_DENY_UNKNOWN_MIME")), "true")
	v := contentvalidation.BuildValidator(accepted, denyUnknown)
	if v == nil {
		logger.Info("artifact content-type validation disabled (no accepted MIME types, no custom validators, not deny-unknown)")
		return nil
	}
	logger.Info("artifact content-type validation enabled",
		"accepted_mime_types", accepted, "deny_unknown", denyUnknown, "custom_validators", contentvalidation.Registered())
	return v
}

// splitAndTrim splits a comma-separated env value into a trimmed, empty-free slice.
func splitAndTrim(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func composeBuilderLoop(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	tesseraAdapter *tessera.TesseraAdapter,
) (*builder.BuilderLoop, *anchor.Publisher) {
	pool := d.PgPool.DB

	compositeReader := store.NewCompositeByteReader(d.WALCommitter, d.ByteStore, d.Logger)

	fetcher := store.NewPostgresEntryFetcher(pool, compositeReader, cfg.LogDID).
		WithCache(d.RecentEntryCache)
	bufferStore := builder.NewDeltaBufferStore(pool, cfg.DeltaWindow, d.Logger)
	sequenceCursor := store.NewSequenceCursor(pool)
	reader := builder.NewCursorReader(sequenceCursor)
	tree := smt.NewTree(d.LeafStore, d.NodeStore)
	if rs, rsErr := store.NewSMTRootStateStore(pool).Read(ctx); rsErr == nil {
		tree.SetRoot(rs.CurrentRoot)
	} else {
		d.Logger.Warn("smt tree boot-seed: smt_root_state read failed; starting at EmptyHash", "error", rsErr)
	}

	buffer, loadErr := bufferStore.Load(ctx)
	if loadErr != nil {
		d.Logger.Warn("delta buffer load — starting cold", "error", loadErr)
		buffer = sdkbuilder.NewDeltaWindowBuffer(cfg.DeltaWindow)
	}

	signedSelfSubmit := anchor.SignAndSubmit(
		d.LedgerSignerPriv,
		d.LedgerDID,
		anchor.SubmitInProcess(func() http.Handler { return d.SubmitHandler }),
	)

	commitPub := builder.NewCommitmentPublisher(
		cfg.LedgerDID,
		cfg.LogDID,
		builder.CommitmentPublisherConfig{
			IntervalEntries: 1000,
			IntervalTime:    1 * time.Hour,
		},
		signedSelfSubmit,
		d.Logger,
	).WithCommitmentStore(d.CommitStore).
		WithContentStore(d.ArtifactContentStore)

	loopCfg := builder.DefaultLoopConfig(cfg.LogDID)
	loopCfg.BatchSize = cfg.BatchSize
	loopCfg.PollInterval = cfg.PollInterval
	loopCfg.DeltaWindow = cfg.DeltaWindow

	bl := builder.NewBuilderLoop(
		loopCfg, pool, tree, d.LeafStore, d.NodeStore,
		reader, fetcher,
		nil,
		buffer, bufferStore,
		commitPub,
		tesseraAdapter,
		d.Logger,
	).WithRootStore(store.NewSMTRootStateStore(pool)).
		WithTileFrontierGate(store.NewPgTileFrontier(pool), smtMaxTileLag())

	// Part II.9 parent-target submit composition.
	//
	// v1.32.0 L5 backdoor closure: the parent admission URL is
	// resolved through the on-log FederationGraph via
	// d.PeerAdmissionURLResolver (a thin closure over
	// *discover.DefaultAuthoritativeResolver.ResolvePeer) when the
	// resolver is wired. cfg.ParentAdmissionURL remains as the
	// CANARY FALLBACK for the bootstrap window before a
	// FederationGraph entry has been admitted.
	var parentSubmitFn func(entry *envelope.Entry) error
	resolverAvailable := d.PeerAdmissionURLResolver != nil
	if cfg.ParentLogDID != "" && (resolverAvailable || cfg.ParentAdmissionURL != "") {
		parentSubmitFn = anchor.SignAndSubmit(
			d.LedgerSignerPriv,
			d.LedgerDID,
			anchor.SubmitToResolvedHTTPEndpoint(
				d.OutboundHTTPClient,
				d.PeerAdmissionURLResolver,
				cfg.ParentLogDID,
				cfg.ParentAdmissionURL, // canary fallback
				d.Logger,
			),
		)
	}

	var parentTargets []anchor.ParentTarget
	// PR-4d — the derivation chain for the publisher's parent target:
	// WHICH from the constitution; WHERE from the on-log declaration
	// projection; env only as the pre-first-declaration canary, cross-checked
	// fatal once a declaration exists; a constitutional target with no
	// endpoint anywhere refuses boot. (Pre-targets constitutions skip all of
	// this — the legacy env path is untouched.) Publish fan-out beyond the
	// first derived target rides the multi-parent publisher extension; the
	// chain itself — and its fatals — are fully in force here.
	if cfg.GenesisBootstrapDocument.GenesisAnchoring != nil && len(cfg.GenesisBootstrapDocument.GenesisAnchoring.Targets) > 0 {
		// PRE-11 Phase B: derive the parent anchoring target by-kind from the
		// on-log AnchorTargetDeclaration projection, DEFAULT-ON (no schema-env
		// proxy). The parent ADMISSION URL dial keeps its canary (PRE-12).
		{
			derivationQuery := indexes.NewPostgresQueryAPI(ctx, pool, compositeReader, cfg.LogDID)
			recs, srcErr := buildAnchorTargetDeclarationSource(derivationQuery)(ctx)
			if srcErr != nil {
				recs = nil // walk unavailable: derivation proceeds on canary-only terms
			}
			asOf := types.LogPosition{LogDID: cfg.LogDID, Sequence: ^uint64(0)}
			_, declared, _ := projectAnchorTargetGraph(cfg.GenesisBootstrapDocument, cfg.LogDID, recs, asOf)
			eps, depErr := deriveParentEndpoints(cfg.GenesisBootstrapDocument, declared, cfg.ParentLogDID, cfg.ParentAdmissionURL)
			if depErr != nil {
				panic(fmt.Sprintf("anchoring WHERE derivation refused boot: %v", depErr))
			}
			confirmStore := store.NewAnchorConfirmationStore(d.PgPool.DB)
			for _, ep := range eps {
				ep := ep
				submit := anchor.SignAndSubmit(d.LedgerSignerPriv, d.LedgerDID,
					anchor.SubmitToHTTPEndpoint(d.OutboundHTTPClient, ep.AdmissionURL))
				var confirm func(ctx context.Context, head types.CosignedTreeHead) error
				if ep.ReadBaseURL != "" {
					if pf, pfErr := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
						BaseURL: ep.ReadBaseURL, LogDID: ep.LogDID, Client: d.OutboundHTTPClient,
					}); pfErr == nil {
						confirm, _ = anchor.NewParentAnchorConfirmer(anchor.ParentReadBackConfig{
							ParentLogDID: ep.LogDID,
							OwnLogDID:    cfg.LogDID,
							OwnNetworkID: cfg.NetworkID,
							FetchSeqs: func(fctx context.Context) ([]uint64, error) {
								return anchorfeed.FetchBySourceSeqs(fctx, d.OutboundHTTPClient, ep.ReadBaseURL, cfg.LogDID, 256)
							},
							ParentFetcher: pf,
							Recorder:      confirmStore,
						})
					}
				}
				parentTargets = append(parentTargets, anchor.ParentTarget{
					LogDID:       ep.LogDID,
					AdmissionURL: ep.AdmissionURL,
					SubmitFn:     submit,
					Confirm:      confirm,
				})
				d.Logger.Info("anchoring WHERE: publisher parent derived",
					"target", ep.TargetNetworkID[:16],
					"parent_log_did", ep.LogDID,
					"from_declaration", ep.FromDeclaration)
			}
		}
	}

	// PR-4b read-back: close the parent submit's 202-and-forget. The
	// confirmer pages the parent's by-source discovery for OUR anchors,
	// reads them back through the parent log handle (SDK MultiLog), and
	// records the durable first-seen confirmation. Wired only when the
	// parent's read base is knowable (the admission URL's origin) — the 4d
	// derivation chain replaces this env-derived base with the on-log
	// declaration's read endpoint.
	var confirmParent func(ctx context.Context, head types.CosignedTreeHead) error
	if parentSubmitFn != nil && cfg.ParentAdmissionURL != "" {
		parentReadBase := strings.TrimSuffix(cfg.ParentAdmissionURL, "/v1/entries")
		parentFetcher, pfErr := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
			BaseURL: parentReadBase,
			LogDID:  cfg.ParentLogDID,
			Client:  d.OutboundHTTPClient,
		})
		if pfErr != nil {
			return nil, nil // unreachable: all three fields are non-empty here
		}
		confirmParent, _ = anchor.NewParentAnchorConfirmer(anchor.ParentReadBackConfig{
			ParentLogDID: cfg.ParentLogDID,
			OwnLogDID:    cfg.LogDID,
			OwnNetworkID: cfg.NetworkID,
			FetchSeqs: func(fctx context.Context) ([]uint64, error) {
				return anchorfeed.FetchBySourceSeqs(fctx, d.OutboundHTTPClient, parentReadBase, cfg.LogDID, 256)
			},
			ParentFetcher: parentFetcher,
			Recorder:      store.NewAnchorConfirmationStore(d.PgPool.DB),
		})
	}

	anchorPub := anchor.NewPublisher(
		anchor.PublisherConfig{
			LedgerDID:     cfg.LedgerDID,
			LogDID:        cfg.LogDID,
			NetworkID:     cfg.NetworkID,
			Interval:      cfg.AnchorInterval,
			AnchorSources: cfg.AnchorSources,
			HTTPClient:    d.OutboundHTTPClient,

			ParentLogDID:         cfg.ParentLogDID,
			ParentAdmissionURL:   cfg.ParentAdmissionURL,
			ParentAnchorInterval: cfg.ParentAnchorInterval,
			ParentSubmitFn:       parentSubmitFn,
			ConfirmParentAnchor:  confirmParent,
			ParentTargets:        parentTargets,
		},
		tesseraAdapter,
		treeHeadStoreCosignedAdapter{store: d.TreeHeadStore},
		signedSelfSubmit,
		d.Logger,
	)

	return bl, anchorPub
}

type treeHeadStoreCosignedAdapter struct {
	store *store.TreeHeadStore
}

func (a treeHeadStoreCosignedAdapter) LatestCosigned(ctx context.Context) (*types.CosignedTreeHead, error) {
	head, err := a.store.Latest(ctx)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, nil
	}
	sigs := make([]types.WitnessSignature, 0, len(head.Signatures))
	for _, s := range head.Signatures {
		var ws types.WitnessSignature
		if err := json.Unmarshal(s.Signature, &ws); err != nil {
			continue
		}
		sigs = append(sigs, ws)
	}
	out := &types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash:    head.RootHash,
			SMTRoot:     head.SMTRoot,
			ReceiptRoot: head.ReceiptRoot,
			TreeSize:    head.TreeSize,
		},
		Signatures: sigs,
	}
	return out, nil
}

func composeHandlers(
	ctx context.Context,
	cfg Config,
	d *deps.AppDeps,
	tesseraAdapter *tessera.TesseraAdapter,
	escrowOverrideHandler http.HandlerFunc,
	smtTree *smt.Tree,
) (api.Handlers, error) {
	pool := d.PgPool.DB
	witnessHistoryFetcher := witnessclient.NewHistoryFetcher(pool)
	compositeReader := store.NewCompositeByteReader(d.WALCommitter, d.ByteStore, d.Logger)
	fetcher := store.NewPostgresEntryFetcher(pool, compositeReader, cfg.LogDID).
		WithCache(d.RecentEntryCache)
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool, compositeReader, cfg.LogDID)

	// v1.32.0 SDK adoption — Tier B: construct
	// *discover.DefaultAuthoritativeResolver from on-log walker sources
	// and populate the four resolver-backed AppDeps fields.
	treeSizer := treeSizeProviderFunc(func(ctx context.Context) (uint64, error) {
		head, err := d.TreeHeadStore.Latest(ctx)
		if err != nil || head == nil {
			return 0, err
		}
		return head.TreeSize, nil
	})
	if err := wireV1_32Resolver(ctx, queryAPI, cfg.GenesisBootstrapDocument, cfg.LogDID, treeSizer, d); err != nil {
		d.Logger.Warn("v1.32.0: AuthoritativeResolver wire-up failed; legacy canary-fallback paths remain active",
			"error", err,
		)
	}

	var blsQuorumVerifier *admission.BLSQuorumVerifier
	if d.QuorumManager != nil {
		blsQuorumVerifier = admission.NewBLSQuorumVerifier(d.QuorumManager)
		if set := d.QuorumManager.Current(); set != nil {
			d.Logger.Info("admission: embedded-tree-head BLS verifier enabled",
				"witness_set_size", set.Size(),
				"quorum_k", set.Quorum(),
			)
		}
	}

	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: d.EntryStore,
			WAL:        d.WALCommitter,
			Tessera:    d.TesseraEmbedded,
		},
		Admission: api.AdmissionConfig{
			DiffController:        d.DiffController,
			EpochWindowSeconds:    cfg.EpochWindowSeconds,
			EpochAcceptanceWindow: cfg.EpochAcceptanceWindow,
		},
		Identity:            buildIdentityDeps(d),
		AuthorizedWitnesses: authorizedWitnessProvider(pool, cfg.GenesisWitnessSet, d.Logger),
		LedgerDID:           cfg.LedgerDID,
		LogDID:              cfg.LogDID,
		LedgerSignerPriv:    d.LedgerSignerPriv,
		MaxEntrySize:        cfg.MaxEntrySize,
		Logger:              d.Logger,
		FreshnessTolerance:  policy.FreshnessInteractive,
		BLSQuorumVerifier:   blsQuorumVerifier,
		SchemaRegistry:      d.SchemaRegistry,
		Gates:               admission.LoadGatesFromEnv(),
		AdmissionAuthorities: admission.NewOnLogAdmissionKeyset(
			buildAdmissionAuthoritySource(queryAPI), cfg.GenesisAdmissionAuthorities, 30*time.Second),
		AdmissionPolicy: admission.NewOnLogAdmissionPolicy(
			buildAdmissionPolicySource(queryAPI), cfg.GenesisAdmissionPolicy, 30*time.Second),
		EvidenceChainFetcher: fetcher,
		SignaturePolicyResolver: buildSignaturePolicyResolver(
			cfg.GenesisBootstrapDocument, queryAPI, d.TreeHeadStore,
			cfg.LogDID, cfg.NetworkID, d.Logger),
		AlgorithmPolicyResolver: buildAlgorithmPolicyResolver(
			cfg.GenesisBootstrapDocument, queryAPI, d.TreeHeadStore,
			cfg.LogDID, cfg.NetworkID, d.Logger),
		ProtocolVersionResolver: buildProtocolVersionResolver(
			queryAPI, d.TreeHeadStore, cfg.LogDID, cfg.NetworkID, d.Logger),
		DifficultyResolver: buildDifficultyResolver(d.DiffController, d.Logger),
	}

	queryDeps := &api.QueryDeps{
		EntryStore:     d.EntryStore,
		QueryAPI:       queryAPI,
		DiffController: d.DiffController,
		Logger:         d.Logger,
		WAL:            d.WALCommitter,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: d.TreeHeadStore,
		Inclusion:     tesseraAdapter,
		Consistency:   tesseraAdapter,
		Logger:        d.Logger,
	}
	smtDeps := &api.SMTDeps{
		Tree:      smtTree,
		LeafStore: d.LeafStore,
		RootState: store.NewSMTRootStateStore(pool),
		Logger:    d.Logger,
	}
	smtDeps.ProofSource = store.ParseSMTProofSource(os.Getenv("LEDGER_SMT_PROOF_SOURCE"))
	if tileDir := strings.TrimSpace(os.Getenv("LEDGER_SMT_TILE_EMIT_DIR")); tileDir != "" {
		smtDeps.Tiles = smtTileStore(d.ByteStore, tileDir)
		smtDeps.TileCache = smt.NewTileCache(1 << 16)
	}
	var horizonHandler http.HandlerFunc
	var horizonReader api.HorizonReader
	if s3, ok := d.ByteStore.(*bytestore.S3); ok {
		horizonReader = store.NewS3HorizonReader(s3)
	} else if d.TileBackend != nil {
		horizonReader = api.NewTileBackendHorizon(d.TileBackend)
	}
	if horizonReader != nil {
		smtDeps.Horizon = horizonReader
		horizonHandler = api.NewCosignedCheckpointHandler(horizonReader, d.Logger)
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher:     fetcher,
		QueryAPI:    queryAPI,
		EntryStore:  d.EntryStore,
		WAL:         d.WALCommitter,
		PublicURLer: d.ByteStore.(api.PublicURLer),
		LogDID:      cfg.LogDID,
		Logger:      d.Logger,
	}
	commitDeps := &api.DerivationCommitmentDeps{CommitmentStore: d.CommitStore, Logger: d.Logger}

	d.Logger.Info("bytestore: routing configured",
		"backend", cfg.ByteStoreBackend,
		"public_base_url", cfg.ByteStorePublicBaseURL,
	)

	var commitmentLookupHandler http.HandlerFunc
	if d.GossipStore != nil {
		commitmentLookupHandler = api.NewCommitmentLookupHandler(
			&api.CryptographicCommitmentDeps{
				Fetcher: gossipstore.NewBadgerCommitmentFetcher(d.GossipStore),
				Logger:  d.Logger,
			})
	}

	checkpointHandler, tileHandler, err := composeTileHandlers(cfg, d)
	if err != nil {
		return api.Handlers{}, err
	}

	mmdHandler := api.NewMMDHandler(cfg.MMD)
	submitHandler := api.NewSubmissionHandler(submissionDeps)
	batchSubmitHandler := api.NewBatchSubmissionHandler(submissionDeps)

	d.SubmitHandler = submitHandler

	gossipPostH, gossipFeedH := http.Handler(nil), http.Handler(nil)
	if d.GossipBundle != nil {
		gossipPostH = d.GossipBundle.PostHandler
		gossipFeedH = d.GossipBundle.FeedHandler
	}

	// 1.2a: receipt proofs default to the PG ranger (entry_index). When the
	// object-store archive is available (same horizon reader the cold-seq checkpoint
	// archive uses, now also exposing ReadReceiptCommits), wrap it so receipts serve
	// PG-free as a graceful fallback — entry_index GC / PG-off — without masking a
	// genuine "no receipt for this seq".
	pgReceipts := store.NewEntryIndexReceiptRanger(d.PgPool.DB, cfg.LogDID)
	var receiptProver api.ReceiptProver = pgReceipts
	if rcr, ok := horizonReader.(store.ReceiptCommitReader); ok {
		receiptProver = &api.FallbackReceiptProver{
			Primary:  pgReceipts,
			Fallback: store.NewArchiveReceiptRanger(rcr, cfg.LogDID),
			Logger:   d.Logger,
		}
	}

	// #75 Phase C: the serve form is computed (and ceremony-checked) at boot —
	// a require constitution that cannot emit its endorsed form FAILS BOOT.
	networkBootstrapHandler, err := buildNetworkBootstrapHandler(cfg.GenesisBootstrapDocument)
	if err != nil {
		return api.Handlers{}, err
	}

	networkBundleHandler, err := buildNetworkBundleHandler(cfg, d.Logger)
	if err != nil {
		return api.Handlers{}, err
	}

	return api.Handlers{
		Submission:      submitHandler,
		BatchSubmission: batchSubmitHandler,
		TreeHead:        api.NewTreeHeadHandler(treeDeps),
		TreeInclusion:   api.NewTreeInclusionHandler(treeDeps),
		TreeConsistency: api.NewTreeConsistencyHandler(treeDeps),
		SMTProof:        api.NewSMTProofHandler(smtDeps),
		SMTBatchProof:   api.NewSMTBatchProofHandler(smtDeps),
		SMTRoot:         api.NewSMTRootHandler(smtDeps),
		ReceiptProof: api.NewReceiptProofHandler(&api.ReceiptDeps{
			Heads:    d.TreeHeadStore,
			Receipts: receiptProver,
			MinSigs:  cfg.WitnessQuorumK,
			Logger:   d.Logger,
		}),
		// Burn status from observed gossip equivocation findings (nil GossipStore ⇒
		// is_burned=false). For the v2 proof's burn_attestation (a fetched fact).
		Burn:              api.NewBurnHandlerWithDeclared(api.NewGossipBurnSource(d.GossipStore), burnDeclaredSource(d), cfg.LogDID, d.Logger),
		CosignatureOf:     api.NewQueryCosignatureOfHandler(queryDeps),
		TargetRoot:        api.NewQueryTargetRootHandler(queryDeps),
		SignerDID:         api.NewQuerySignerDIDHandler(queryDeps),
		SchemaRef:         api.NewQuerySchemaRefHandler(queryDeps),
		DelegateDID:       api.NewQueryDelegateDIDHandler(queryDeps),
		Scan:              api.NewQueryScanHandler(queryDeps),
		Difficulty:        api.NewDifficultyHandler(queryDeps),
		AdmissionPolicy:   api.NewAdmissionPolicyHandler(submissionDeps.AdmissionPolicy),
		MMD:               mmdHandler,
		EntryByHash:       api.NewHashLookupHandler(queryDeps),
		EntryHashBatch:    api.NewBatchHashLookupHandler(queryDeps),
		GossipPost:        gossipPostH,
		GossipFeed:        gossipFeedH,
		EscrowOverride:    escrowOverrideHandler,
		Metrics:           d.MetricsHandler,
		EntryBySequence:   api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:        api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:          api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:           api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:      api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery:   api.NewDerivationCommitmentQueryHandler(commitDeps),
		CommitmentLookup:  commitmentLookupHandler,
		ArtifactReserve:   artifactReserveHandler(submissionDeps, d.ReservationManager),
		ReservationFinish: reservationFinishHandler(d),
		Checkpoint:        checkpointHandler,
		Tile:              tileHandler,
		Horizon:           horizonHandler,
		LogInfo:           api.NewLogInfoHandler(cfg.LogInfo),
		Version: api.NewVersionHandler(api.VersionInfo{
			Version:    cfg.Version,
			Commit:     cfg.Commit,
			BuildTime:  cfg.BuildTime,
			SDKVersion: cfg.SDKVersion,
		}),
		NetworkPeers:       api.NewNetworkPeersHandler(cfg.NetworkPeers),
		NetworkBootstrap:   networkBootstrapHandler,
		NetworkIdentity:    buildNetworkIdentityHandler(cfg.GenesisBootstrapDocument, d.Logger),
		NetworkMirrors:     api.NewNetworkMirrorsHandler(cfg.NetworkMirrors),
		NetworkBundle:      networkBundleHandler,
		NetworkRotation:    rotationDoorHandler(d),
		NetworkBurn:        burnDoorHandler(d),
		WitnessesCurrent:   api.NewWitnessesCurrentHandler(witnessHistoryFetcher),
		WitnessesBySetHash: api.NewWitnessesBySetHashHandler(witnessHistoryFetcher),
		WitnessesAtSeq:     api.NewWitnessesAtSeqHandler(witnessHistoryFetcher),
		// PR-4b: the anchor chain is DERIVED from the publisher read-back's
		// durable confirmations — never an operator file (the hand-curated
		// LEDGER_NETWORK_ANCHORS_FILE is deleted). Empty chain = valid
		// (a log that has never anchored anywhere).
		NetworkAnchors:  api.NewNetworkAnchorsHandler(anchorChainProvider(store.NewAnchorConfirmationStore(d.PgPool.DB), cfg.LogDID)),
		AnchorsBySource: api.NewAnchorsBySourceHandler(queryDeps),

		// v1.32.0 L3 — materialized walker-projection endpoints.
		NetworkLabels:           api.NewNetworkLabelsHandler(d.WitnessLabelsFetcher),
		NetworkAuditors:         api.NewNetworkAuditorsHandler(d.AuditorRegistryFetcher),
		NetworkWitnessEndpoints: api.NewNetworkWitnessEndpointsHandler(d.WitnessEndpointsFetcher),

		Bundle: api.NewBundleHandler(buildBundleDeps(
			cfg.GenesisBootstrapDocument,
			fetcher,
			treeHeadStoreCosignedAdapter{store: d.TreeHeadStore},
			tesseraAdapter,
			smtTree,
			witnessHistoryFetcher,
			cfg.LogDID,
		)),
	}, nil
}

// buildNetworkBootstrapHandler serves the constitution in its SERVED form —
// network.EndorsedBootstrapBytes (#75 Phase C): the full document including its
// genesis endorsements. The emitter itself refuses a require-policy
// constitution whose ceremony does not verify, and that refusal is a BOOT
// FAILURE here — a network that demands endorsements must never quietly serve
// a stripped constitution (the strip attack would otherwise be indistinguishable
// from an honest legacy network at first contact).
func buildNetworkBootstrapHandler(doc network.BootstrapDocument) (http.HandlerFunc, error) {
	if doc.NetworkName == "" {
		return api.NewNetworkBootstrapHandler(nil), nil
	}
	served, err := network.EndorsedBootstrapBytes(doc)
	if err != nil {
		return nil, fmt.Errorf("/v1/network/bootstrap serve form (endorsed bootstrap bytes): %w", err)
	}
	return api.NewNetworkBootstrapHandler(served), nil
}

// buildNetworkBundleHandler composes GET /v1/network/bundle from the SAME
// boot sources the sibling /v1/network/* handlers serve: identity + quorum +
// name from the bootstrap document, the destination log DID, the federation
// graph's siblings, and the admission posture. nil on a pre-bootstrap node
// (route unmounted); a compose/validate failure — including a ManifestAnchor
// configured without a PublicURL to resolve it from — is boot-fatal.
// rotationDoorHandler mounts POST /v1/network/rotation onto the single
// ProcessRotation chokepoint. d.RotationHandler is nil when the rotation
// pipeline is unwired (dev/integration) — the door is then simply not
// served, matching the fail-closed posture of the rest of the surface.
func rotationDoorHandler(d *deps.AppDeps) http.Handler {
	if d.RotationHandler == nil {
		return nil
	}
	return api.NewRotationHandler(d.RotationHandler)
}

// burnDoorHandler mounts POST /v1/network/burn onto the single BurnProcessor
// chokepoint (tooling#110). nil when the burn pipeline is unwired (dev/
// integration) — the door is then not served, the same fail-closed posture
// as the rotation door.
func burnDoorHandler(d *deps.AppDeps) http.Handler {
	if d.BurnProcessor == nil {
		return nil
	}
	return api.NewBurnDoorHandler(d.BurnProcessor, d.Logger)
}

// burnDeclaredSource yields the AUTHORITATIVE declared-burn leg for
// GET /v1/burn's OR-semantics, or nil (observed-only) when the burn pipeline
// is unwired. Returning a nil interface (not a nil-pointer-in-interface) so
// the read handler's nil check is honest.
func burnDeclaredSource(d *deps.AppDeps) api.DeclaredBurnSource {
	if d.BurnProcessor == nil {
		return nil
	}
	return d.BurnProcessor
}

func buildNetworkBundleHandler(cfg Config, logger *slog.Logger) (http.Handler, error) {
	epoch := uint64(0)
	if cfg.EpochWindowSeconds > 0 {
		epoch = uint64(cfg.EpochWindowSeconds)
	}
	h, err := api.NewNetworkBundleHandler(api.NetworkBundleSources{
		Doc:       cfg.GenesisBootstrapDocument,
		LogDID:    cfg.LogDID,
		PublicURL: cfg.PublicURL,
		// Both admission payment modes the /v1/entries forward supports
		// (Mode A credit token, Mode B PoW).
		Payment:        []string{"credit", "pow"},
		EpochWindowSec: epoch,
		Federation:     cfg.NetworkPeers,
		Anchor:         cfg.ManifestAnchor,
		LedgerBaseURL:  cfg.PublicURL,
		Logger:         logger,
	})
	if err != nil {
		return nil, fmt.Errorf("/v1/network/bundle composer: %w", err)
	}
	return h, nil
}

func buildNetworkIdentityHandler(doc network.BootstrapDocument, logger *slog.Logger) http.HandlerFunc {
	id, err := api.BuildNetworkIdentity(doc)
	if err != nil {
		logger.Error("Part II.1: BuildNetworkIdentity failed; "+
			"/v1/network/identity will 404", "error", err)
		return api.NewNetworkIdentityHandler(api.NetworkIdentity{})
	}
	return api.NewNetworkIdentityHandler(id)
}

func buildAdmissionAuthoritySource(q *indexes.PostgresQueryAPI) admission.KeysetSource {
	empty := func(context.Context) ([]authz.EOAKeysetRecord, error) { return nil, nil }
	schemaPos, ok := parseSchemaEnv("LEDGER_ADMISSION_AUTHORITY_SCHEMA")
	if !ok {
		return empty
	}
	return func(ctx context.Context) ([]authz.EOAKeysetRecord, error) {
		entries, err := q.QueryBySchemaRef(schemaPos)
		if err != nil {
			return nil, err
		}
		recs := make([]authz.EOAKeysetRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := authz.DecodeAdmissionAuthorityPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			id, err := envelope.EntryIdentity(e)
			if err != nil {
				continue
			}
			recs = append(recs, p.ToRecord(entries[i].Position, id))
		}
		return recs, nil
	}
}

func buildAdmissionPolicySource(q *indexes.PostgresQueryAPI) admission.PolicySource {
	empty := func(context.Context) ([]authz.AdmissionPolicyRecord, error) { return nil, nil }
	schemaPos, ok := parseSchemaEnv("LEDGER_ADMISSION_POLICY_SCHEMA")
	if !ok {
		return empty
	}
	return func(ctx context.Context) ([]authz.AdmissionPolicyRecord, error) {
		entries, err := q.QueryBySchemaRef(schemaPos)
		if err != nil {
			return nil, err
		}
		recs := make([]authz.AdmissionPolicyRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := authz.DecodeAdmissionPolicyPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			id, err := envelope.EntryIdentity(e)
			if err != nil {
				continue
			}
			recs = append(recs, p.ToRecord(entries[i].Position, id))
		}
		return recs, nil
	}
}

func buildDifficultyResolver(
	dc *middleware.DifficultyController,
	logger *slog.Logger,
) admission.DifficultyResolver {
	if dc == nil {
		logger.Warn("Post-II #3: DiffController not wired; Mode-B PoW gate inert")
		return nil
	}
	r, err := admission.NewStaticDifficultyResolver(dc)
	if err != nil {
		logger.Error("Post-II #3: NewStaticDifficultyResolver failed; "+
			"Mode-B PoW gate inert", "error", err)
		return nil
	}
	logger.Info("Post-II #3: Mode-B PoW gate resolver wired (StaticDifficultyResolver)")
	return r
}

func buildSignaturePolicyResolver(
	doc network.BootstrapDocument,
	queryAPI *indexes.PostgresQueryAPI,
	heads *store.TreeHeadStore,
	logDID string,
	networkID cosign.NetworkID,
	logger *slog.Logger,
) admission.SignaturePolicyResolver {
	if len(doc.GenesisSignaturePolicy.AllowedEntrySigSchemes) == 0 {
		return nil
	}

	if schemaPos, ok := parseSchemaEnv("LEDGER_SIGNATURE_POLICY_SCHEMA"); ok {
		source := buildSignaturePolicyAmendmentSource(queryAPI, schemaPos)
		sizes := treeSizeProviderFunc(func(ctx context.Context) (uint64, error) {
			head, err := heads.Latest(ctx)
			if err != nil {
				return 0, err
			}
			if head == nil {
				return 0, nil
			}
			return head.TreeSize, nil
		})
		resolver, err := admission.NewOnLogSignaturePolicyResolver(
			source, sizes, doc, logDID, [32]byte(networkID), 30*time.Second)
		if err != nil {
			logger.Error("Part II.6 part 2: OnLogSignaturePolicyResolver invalid; "+
				"SignaturePolicy gate stays disabled",
				"error", err)
			return nil
		}
		logger.Info("Part II.6 part 2: amendment-aware SignaturePolicy gate resolver wired",
			"schema_ref", schemaPos.LogDID+"@"+strconv.FormatUint(schemaPos.Sequence, 10),
			"min_valid_sigs", doc.GenesisSignaturePolicy.MinSignaturesPerEntry,
			"allowed_algos", len(doc.GenesisSignaturePolicy.AllowedEntrySigSchemes))
		return resolver
	}

	resolver, err := admission.NewGenesisSignaturePolicyResolver(doc)
	if err != nil {
		logger.Error("Part II.6: GenesisSignaturePolicy invalid; "+
			"SignaturePolicy gate stays disabled",
			"error", err)
		return nil
	}
	logger.Info("Part II.6: SignaturePolicy gate resolver wired (genesis-only)",
		"min_valid_sigs", doc.GenesisSignaturePolicy.MinSignaturesPerEntry,
		"allowed_algos", len(doc.GenesisSignaturePolicy.AllowedEntrySigSchemes))
	return resolver
}

func buildSignaturePolicyAmendmentSource(
	q *indexes.PostgresQueryAPI,
	schemaPos types.LogPosition,
) admission.SignaturePolicyAmendmentSource {
	return func(ctx context.Context) ([]network.SignaturePolicyRecord, error) {
		entries, err := q.QueryBySchemaRef(schemaPos)
		if err != nil {
			return nil, err
		}
		recs := make([]network.SignaturePolicyRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := network.DecodeSignaturePolicyAmendmentPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			id, err := envelope.EntryIdentity(e)
			if err != nil {
				continue
			}
			recs = append(recs, network.ToSignaturePolicyRecord(p, entries[i].Position, id))
		}
		return recs, nil
	}
}

// ── issue #201: on-log algorithm-policy + protocol-version resolvers ──
// Crypto-agility: govern signature-algorithm lifecycle + admitted protocol
// versions post-genesis on-log. Both mirror buildSignaturePolicyResolver —
// amendment-aware when the schema env is set, genesis-only baseline otherwise.
// The genesis baselines are SYNTHESIZED (no bootstrap-doc field): algorithm =
// the genesis allow-list, all active; protocol-version = CurrentProtocolVersion,
// read_write. The gates stay disabled (default-OFF flags) unless the operator
// opts in; a nil resolver also disables them.

func buildAlgorithmPolicyResolver(
	doc network.BootstrapDocument,
	queryAPI *indexes.PostgresQueryAPI,
	heads *store.TreeHeadStore,
	logDID string,
	networkID cosign.NetworkID,
	logger *slog.Logger,
) admission.AlgorithmPolicyResolver {
	if len(doc.GenesisSignaturePolicy.AllowedEntrySigSchemes) == 0 {
		return nil
	}
	if schemaPos, ok := parseSchemaEnv("LEDGER_ALGORITHM_POLICY_SCHEMA"); ok {
		source := buildAlgorithmPolicyAmendmentSource(queryAPI, schemaPos)
		sizes := treeSizeProviderFunc(func(ctx context.Context) (uint64, error) {
			head, err := heads.Latest(ctx)
			if err != nil {
				return 0, err
			}
			if head == nil {
				return 0, nil
			}
			return head.TreeSize, nil
		})
		resolver, err := admission.NewOnLogAlgorithmPolicyResolver(
			source, sizes, doc, logDID, [32]byte(networkID), 30*time.Second)
		if err != nil {
			logger.Error("issue #201: OnLogAlgorithmPolicyResolver invalid; "+
				"algorithm-policy gate stays disabled", "error", err)
			return nil
		}
		logger.Info("issue #201: amendment-aware algorithm-policy gate resolver wired",
			"schema_ref", schemaPos.LogDID+"@"+strconv.FormatUint(schemaPos.Sequence, 10))
		return resolver
	}
	resolver, err := admission.NewGenesisAlgorithmPolicyResolver(doc)
	if err != nil {
		logger.Error("issue #201: genesis algorithm policy invalid; "+
			"algorithm-policy gate stays disabled", "error", err)
		return nil
	}
	logger.Info("issue #201: algorithm-policy gate resolver wired (genesis-only)")
	return resolver
}

func buildAlgorithmPolicyAmendmentSource(
	q *indexes.PostgresQueryAPI,
	schemaPos types.LogPosition,
) admission.AlgorithmPolicyAmendmentSource {
	return func(ctx context.Context) ([]authz.AlgorithmPolicyRecord, error) {
		entries, err := q.QueryBySchemaRef(schemaPos)
		if err != nil {
			return nil, err
		}
		recs := make([]authz.AlgorithmPolicyRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := authz.DecodeAlgorithmPolicyPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			id, err := envelope.EntryIdentity(e)
			if err != nil {
				continue
			}
			recs = append(recs, p.ToRecord(entries[i].Position, id))
		}
		return recs, nil
	}
}

func buildProtocolVersionResolver(
	queryAPI *indexes.PostgresQueryAPI,
	heads *store.TreeHeadStore,
	logDID string,
	networkID cosign.NetworkID,
	logger *slog.Logger,
) admission.ProtocolVersionResolver {
	if schemaPos, ok := parseSchemaEnv("LEDGER_PROTOCOL_VERSION_SCHEMA"); ok {
		source := buildProtocolVersionAmendmentSource(queryAPI, schemaPos)
		sizes := treeSizeProviderFunc(func(ctx context.Context) (uint64, error) {
			head, err := heads.Latest(ctx)
			if err != nil {
				return 0, err
			}
			if head == nil {
				return 0, nil
			}
			return head.TreeSize, nil
		})
		resolver, err := admission.NewOnLogProtocolVersionResolver(
			source, sizes, logDID, [32]byte(networkID), 30*time.Second)
		if err != nil {
			logger.Error("issue #201: OnLogProtocolVersionResolver invalid; "+
				"protocol-version gate stays disabled", "error", err)
			return nil
		}
		logger.Info("issue #201: amendment-aware protocol-version gate resolver wired",
			"schema_ref", schemaPos.LogDID+"@"+strconv.FormatUint(schemaPos.Sequence, 10))
		return resolver
	}
	resolver, err := admission.NewGenesisProtocolVersionResolver()
	if err != nil {
		logger.Error("issue #201: genesis protocol-version policy invalid; "+
			"protocol-version gate stays disabled", "error", err)
		return nil
	}
	logger.Info("issue #201: protocol-version gate resolver wired (genesis-only)")
	return resolver
}

func buildProtocolVersionAmendmentSource(
	q *indexes.PostgresQueryAPI,
	schemaPos types.LogPosition,
) admission.ProtocolVersionAmendmentSource {
	return func(ctx context.Context) ([]authz.ProtocolVersionAdmissionRecord, error) {
		entries, err := q.QueryBySchemaRef(schemaPos)
		if err != nil {
			return nil, err
		}
		recs := make([]authz.ProtocolVersionAdmissionRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := authz.DecodeProtocolVersionAdmissionPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			id, err := envelope.EntryIdentity(e)
			if err != nil {
				continue
			}
			recs = append(recs, p.ToRecord(entries[i].Position, id))
		}
		return recs, nil
	}
}

// ────────────────────────────────────────────────────────────────
// v1.32.0 SDK adoption — Tier B: walker sources, resolver constructor,
// L3 fetcher adapters.
// ────────────────────────────────────────────────────────────────

// buildAnchorTargetDeclarationSource walks BP-ENTRY-ANCHOR-TARGET-V1
// declarations (PR-4d / Tier 1.5): the on-log WHERE for each constitutional
// anchor target. Same schema-position discipline as its sibling walkers.
// collectByKind pages idx_entry_kind (Phase A, #117) to the full set of
// entries of a payload kind. Platform-family declarations are admission-gated
// (only the network authority mints them), so the set is governance-bounded;
// paging caps each round-trip. DISCOVERY, not authority — the records are
// still cryptographically verified by the resolver downstream.
func collectByKind(q *indexes.PostgresQueryAPI, kind string) ([]types.EntryWithMetadata, error) {
	const page = 512
	var out []types.EntryWithMetadata
	var start uint64
	for {
		batch, err := q.QueryByKind(kind, start, page)
		if err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < page {
			return out, nil
		}
		start = batch[len(batch)-1].Position.Sequence + 1
	}
}

func buildAnchorTargetDeclarationSource(
	q *indexes.PostgresQueryAPI,
) func(ctx context.Context) ([]network.AnchorTargetDeclarationRecord, error) {
	return func(ctx context.Context) ([]network.AnchorTargetDeclarationRecord, error) {
		entries, err := collectByKind(q, network.AnchorTargetDeclarationKindV1)
		if err != nil {
			return nil, err
		}
		recs := make([]network.AnchorTargetDeclarationRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := network.DecodeAnchorTargetDeclarationPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			recs = append(recs, network.AnchorTargetDeclarationRecord{
				EffectivePos: entries[i].Position,
				Payload:      p,
			})
		}
		return recs, nil
	}
}

func buildWitnessEndpointDeclarationSource(
	q *indexes.PostgresQueryAPI,
) func(ctx context.Context) (network.WitnessEndpointDeclarationByPosition, error) {
	return func(ctx context.Context) (network.WitnessEndpointDeclarationByPosition, error) {
		entries, err := collectByKind(q, network.WitnessEndpointDeclarationKindV1)
		if err != nil {
			return nil, err
		}
		recs := make(network.WitnessEndpointDeclarationByPosition, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := network.DecodeWitnessEndpointDeclarationPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			recs = append(recs, network.WitnessEndpointDeclarationRecord{
				EffectivePos: entries[i].Position,
				Payload:      p,
			})
		}
		return recs, nil
	}
}

func buildWitnessIdentityLabelSource(
	q *indexes.PostgresQueryAPI,
) func(ctx context.Context) (network.WitnessIdentityLabelByPosition, error) {
	return func(ctx context.Context) (network.WitnessIdentityLabelByPosition, error) {
		entries, err := collectByKind(q, network.WitnessIdentityLabelKindV1)
		if err != nil {
			return nil, err
		}
		recs := make(network.WitnessIdentityLabelByPosition, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := network.DecodeWitnessIdentityLabelPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			recs = append(recs, network.WitnessIdentityLabelRecord{
				EffectivePos: entries[i].Position,
				Payload:      p,
			})
		}
		return recs, nil
	}
}

func buildAuditorRegistrationSource(
	q *indexes.PostgresQueryAPI,
) func(ctx context.Context) ([]network.AuditorRegistrationRecord, error) {
	return func(ctx context.Context) ([]network.AuditorRegistrationRecord, error) {
		entries, err := collectByKind(q, network.AuditorRegistrationKindV1)
		if err != nil {
			return nil, err
		}
		recs := make([]network.AuditorRegistrationRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := network.DecodeAuditorRegistrationPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			recs = append(recs, network.AuditorRegistrationRecord{
				EffectivePos: entries[i].Position,
				Payload:      p,
			})
		}
		return recs, nil
	}
}

// buildAuditorScopeAmendmentSource walks the on-log stream of
// AuditorScopeAmendmentV1 entries (v1.33.0 Gap 2). Schema position is
// supplied via LEDGER_AUDITOR_SCOPE_AMENDMENT_SCHEMA; nil schemaPos
// means "no amendment schema bound" — the walker still runs but
// returns an empty slice (the network has not yet published any
// amendments).
func buildAuditorScopeAmendmentSource(
	q *indexes.PostgresQueryAPI,
) func(ctx context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
	return func(ctx context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
		entries, err := collectByKind(q, network.AuditorScopeAmendmentKindV1)
		if err != nil {
			return nil, err
		}
		recs := make([]network.AuditorScopeAmendmentRecord, 0, len(entries))
		for i := range entries {
			e, err := envelope.Deserialize(entries[i].CanonicalBytes)
			if err != nil {
				continue
			}
			p, err := network.DecodeAuditorScopeAmendmentPayload(e.DomainPayload)
			if err != nil {
				continue
			}
			recs = append(recs, network.AuditorScopeAmendmentRecord{
				EffectivePos: entries[i].Position,
				Payload:      p,
			})
		}
		return recs, nil
	}
}

// authorizedWitnessProvider returns the PRE-12 witness-endpoint enrollment
// authorization set: the witness PubKeyIDs the network trusts to self-declare
// endpoints (admission step 4h).
//
// Authority is the LIVE on-log witness membership, read each call (never
// cached): the active witness_sets row is the reconciled current set — the
// constitution's GenesisWitnessSet baseline ∪ rotations, with retired witnesses
// removed — so a rotated-in witness can enroll immediately and a retired one
// cannot. The constitution's GenesisWitnessSet (did:key ECDSA, resolved once)
// is the fallback for the bootstrap window before witness_sets is seeded, and
// the fail-safe if the projection read ever fails: enrollment falls back to the
// constitutional baseline, never opens up.
func authorizedWitnessProvider(pool *pgxpool.Pool, genesisDIDs []string, logger *slog.Logger) func() map[[32]byte]struct{} {
	genesis := make(map[[32]byte]struct{})
	if keys, err := witness.KeysFromDIDs(genesisDIDs); err != nil {
		logger.Error("PRE-12: KeysFromDIDs on GenesisWitnessSet failed — witness-endpoint "+
			"declarations are refused until the constitution's witness DIDs resolve", "error", err)
	} else {
		for _, k := range keys {
			genesis[k.ID] = struct{}{}
		}
	}
	return func() map[[32]byte]struct{} {
		if pool != nil {
			row, err := witnessclient.LoadCurrentSetRow(context.Background(), pool)
			if err != nil {
				logger.Warn("PRE-12: witness_sets current-set read failed; enrollment "+
					"authorization falls back to the genesis baseline", "error", err)
			} else if ids, perr := witnessSetPubKeyIDs(row.KeysJSON); perr != nil {
				logger.Warn("PRE-12: witness_sets keys_json malformed; enrollment "+
					"authorization falls back to the genesis baseline", "error", perr)
			} else if len(ids) > 0 {
				return ids
			}
		}
		return genesis
	}
}

// witnessSetPubKeyIDs extracts the PubKeyID set from a witness_sets row's
// canonical keys_json ([]types.WitnessPublicKey). The .ID is the canonical
// PubKeyID — the SAME value witness.KeysFromDIDs derives — so the resulting set
// matches what the admission authorizer computes from a declaration's signer.
func witnessSetPubKeyIDs(keysJSON []byte) (map[[32]byte]struct{}, error) {
	var keys []types.WitnessPublicKey
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		return nil, err
	}
	out := make(map[[32]byte]struct{}, len(keys))
	for i := range keys {
		out[keys[i].ID] = struct{}{}
	}
	return out, nil
}

func buildAuthoritativeResolver(
	ctx context.Context,
	q *indexes.PostgresQueryAPI,
	doc network.BootstrapDocument,
	ourLogDID string,
	logger *slog.Logger,
) (*discover.DefaultAuthoritativeResolver, error) {
	// PRE-11 Phase B (#114, M7 closure): all five platform families resolve
	// BY-KIND from the log's idx_entry_kind index (Phase A, #117), DEFAULT-ON.
	// The LEDGER_*_SCHEMA position proxies are gone — discovery is no longer
	// dormant behind operator config, and no config path can fail toward forgery.
	resolver := &discover.DefaultAuthoritativeResolver{
		LogWitnessSets:    map[string][][32]byte{},
		DIDFallbackPolicy: discover.FallbackDisabled,
		Logger:            logger,
	}

	if len(doc.GenesisWitnessSet) > 0 && ourLogDID != "" {
		keys, err := witness.KeysFromDIDs(doc.GenesisWitnessSet)
		if err != nil {
			logger.Warn("v1.32.0: KeysFromDIDs on GenesisWitnessSet",
				"error", err)
		} else {
			pubKeyIDs := make([][32]byte, 0, len(keys))
			for _, k := range keys {
				pubKeyIDs = append(pubKeyIDs, k.ID)
			}
			resolver.LogWitnessSets[ourLogDID] = pubKeyIDs
		}
	}

	if recs, err := buildWitnessEndpointDeclarationSource(q)(ctx); err != nil {
		logger.Warn("PRE-11: WitnessEndpointDeclaration by-kind fetch failed", "error", err)
	} else {
		resolver.WitnessEndpointRecords = recs
		logger.Info("PRE-11: WitnessEndpointDeclaration records loaded", "count", len(recs))
	}
	if recs, err := buildWitnessIdentityLabelSource(q)(ctx); err != nil {
		logger.Warn("PRE-11: WitnessIdentityLabel by-kind fetch failed", "error", err)
	} else {
		resolver.WitnessLabelRecords = recs
		logger.Info("PRE-11: WitnessIdentityLabel records loaded", "count", len(recs))
	}
	if recs, err := buildAuditorRegistrationSource(q)(ctx); err != nil {
		logger.Warn("PRE-11: AuditorRegistration by-kind fetch failed", "error", err)
	} else {
		resolver.AuditorRegistryRecords = recs
		logger.Info("PRE-11: AuditorRegistration records loaded", "count", len(recs))
	}
	if recs, err := buildAuditorScopeAmendmentSource(q)(ctx); err != nil {
		logger.Warn("PRE-11: AuditorScopeAmendment by-kind fetch failed", "error", err)
	} else {
		resolver.AuditorScopeAmendmentRecords = recs
		logger.Info("PRE-11: AuditorScopeAmendment records loaded", "count", len(recs))
	}
	// PR-4d (#94): the FederationGraph's producer is the on-log
	// AnchorTargetDeclaration, resolved by-kind. LEDGER_PARENT_ADMISSION_URL
	// remains the cross-log (peer/parent) canary — retired in PRE-12 with the
	// rest of the foreign-log resolution, not here.
	if recs, err := buildAnchorTargetDeclarationSource(q)(ctx); err != nil {
		logger.Warn("PRE-11: AnchorTargetDeclaration by-kind fetch failed", "error", err)
	} else {
		asOf := types.LogPosition{LogDID: ourLogDID, Sequence: ^uint64(0)}
		graph, declared, undeclared := projectAnchorTargetGraph(doc, ourLogDID, recs, asOf)
		if graph != nil {
			resolver.FederationGraph = *graph
		}
		logAnchorTargetPosture(logger, graph, declared, undeclared,
			os.Getenv("LEDGER_PARENT_ADMISSION_URL"), time.Now())
	}

	return resolver, nil
}

// witnessLabelFetcher implements api.WitnessLabelFetcher.
type witnessLabelFetcher struct {
	source    func(ctx context.Context) (network.WitnessIdentityLabelByPosition, error)
	treeSizer admission.TreeSizeProvider
}

func (f *witnessLabelFetcher) LoadCurrentLabels(ctx context.Context) (*api.WitnessLabelsView, error) {
	recs, err := f.source(ctx)
	if err != nil {
		return nil, err
	}
	asOf, _ := f.treeSizer.LatestTreeSize(ctx)
	current := map[[32]byte]network.WitnessIdentityLabel{}
	for _, r := range recs {
		current[r.Payload.PubKeyID] = r.Payload
	}
	out := make([]api.WitnessLabelEntry, 0, len(current))
	for pk, p := range current {
		if p.Label == "" {
			continue
		}
		out = append(out, api.WitnessLabelEntry{
			PubKeyID: fmt.Sprintf("%x", pk),
			Label:    p.Label,
			DIDHint:  p.DIDHint,
		})
	}
	return &api.WitnessLabelsView{AsOfSeq: asOf, Labels: out}, nil
}

// auditorRegistryFetcher is now implemented by the
// internal/auditorregistry package — amendment-aware. wireV1_32Resolver
// constructs it via auditorregistry.New(registry, amendments, treeSizer)
// and assigns to d.AuditorRegistryFetcher. The previous inline
// implementation ignored amendments, producing silent disagreement
// between the enforced gate scope and the materialized projection.

type witnessEndpointsFetcher struct {
	source    func(ctx context.Context) (network.WitnessEndpointDeclarationByPosition, error)
	treeSizer admission.TreeSizeProvider
}

func (f *witnessEndpointsFetcher) LoadCurrentWitnessEndpoints(ctx context.Context) (*api.WitnessEndpointsView, error) {
	recs, err := f.source(ctx)
	if err != nil {
		return nil, err
	}
	asOf, _ := f.treeSizer.LatestTreeSize(ctx)
	current := map[[32]byte]network.WitnessEndpointDeclaration{}
	for _, r := range recs {
		current[r.Payload.PubKeyID] = r.Payload
	}
	out := make([]api.WitnessEndpointEntry, 0, len(current))
	for pk, p := range current {
		if p.RetiredAt != nil {
			continue
		}
		out = append(out, api.WitnessEndpointEntry{
			PubKeyID:  fmt.Sprintf("%x", pk),
			Endpoints: p.Endpoints,
		})
	}
	return &api.WitnessEndpointsView{AsOfSeq: asOf, Witnesses: out}, nil
}

func wireV1_32Resolver(
	ctx context.Context,
	q *indexes.PostgresQueryAPI,
	doc network.BootstrapDocument,
	ourLogDID string,
	treeSizer admission.TreeSizeProvider,
	d *deps.AppDeps,
) error {
	resolver, err := buildAuthoritativeResolver(ctx, q, doc, ourLogDID, d.Logger)
	if err != nil {
		return fmt.Errorf("wireV1_32Resolver: %w", err)
	}
	if resolver == nil {
		return nil
	}

	d.WitnessEndpointResolver = resolver

	// PRE-12 item 5: the did:web consistency monitor (advisory tripwire). Wired +
	// opt-in via LEDGER_WITNESS_DIDWEB_MONITOR_INTERVAL — a no-op for the did:key
	// genesis topology (no did:web document to diff), so it stays off by default
	// and an operator enables it once did:web-addressed witnesses appear.
	if ivStr := os.Getenv("LEDGER_WITNESS_DIDWEB_MONITOR_INTERVAL"); ivStr != "" {
		if iv, perr := time.ParseDuration(ivStr); perr == nil && iv > 0 {
			mon := &witnessclient.WitnessEndpointMonitor{
				Records:  func() network.WitnessEndpointDeclarationByPosition { return resolver.WitnessEndpointRecords },
				Fetch:    witnessclient.HTTPDIDDocFetcher(d.OutboundHTTPClient),
				Interval: iv,
				Logger:   d.Logger,
			}
			lifecycle.SafeRunInWG(ctx, &d.WG, "witness-endpoint-didweb-monitor", d.Logger, nil, func() error {
				return mon.Loop(ctx)
			})
		} else if perr != nil {
			d.Logger.Warn("PRE-12: LEDGER_WITNESS_DIDWEB_MONITOR_INTERVAL ignored (unparseable duration)",
				"value", ivStr, "error", perr)
		}
	}

	d.AuditorRegistrySource = func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		return resolver.AuditorRegistryRecords, nil
	}

	d.AuditorAmendmentSource = func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
		return resolver.AuditorScopeAmendmentRecords, nil
	}

	d.PeerAdmissionURLResolver = func(ctx context.Context, peerLogDID string) (string, error) {
		res, resErr := resolver.ResolvePeer(ctx, peerLogDID, types.LogPosition{})
		if resErr != nil {
			return "", resErr
		}
		return res.URL, nil
	}

	d.WitnessLabelsFetcher = &witnessLabelFetcher{
		source: func(ctx context.Context) (network.WitnessIdentityLabelByPosition, error) {
			return resolver.WitnessLabelRecords, nil
		},
		treeSizer: treeSizer,
	}
	auditorFetcher, err := auditorregistry.New(
		func(ctx context.Context) ([]network.AuditorRegistrationRecord, error) {
			return resolver.AuditorRegistryRecords, nil
		},
		func(ctx context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
			return resolver.AuditorScopeAmendmentRecords, nil
		},
		treeSizer,
	)
	if err != nil {
		return fmt.Errorf("wireV1_32Resolver: auditor registry fetcher: %w", err)
	}
	d.AuditorRegistryFetcher = auditorFetcher
	d.WitnessEndpointsFetcher = &witnessEndpointsFetcher{
		source: func(ctx context.Context) (network.WitnessEndpointDeclarationByPosition, error) {
			return resolver.WitnessEndpointRecords, nil
		},
		treeSizer: treeSizer,
	}

	d.Logger.Info("v1.32.0: AuthoritativeResolver wired",
		"witness_endpoint_records", len(resolver.WitnessEndpointRecords),
		"witness_label_records", len(resolver.WitnessLabelRecords),
		"auditor_registry_records", len(resolver.AuditorRegistryRecords),
		"log_witness_sets", len(resolver.LogWitnessSets),
	)
	return nil
}

type treeSizeProviderFunc func(ctx context.Context) (uint64, error)

func (f treeSizeProviderFunc) LatestTreeSize(ctx context.Context) (uint64, error) {
	return f(ctx)
}

func parseSchemaEnv(name string) (types.LogPosition, bool) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return types.LogPosition{}, false
	}
	at := strings.LastIndex(raw, "@")
	if at <= 0 || at == len(raw)-1 {
		return types.LogPosition{}, false
	}
	seq, err := strconv.ParseUint(raw[at+1:], 10, 64)
	if err != nil {
		return types.LogPosition{}, false
	}
	return types.LogPosition{LogDID: raw[:at], Sequence: seq}, true
}

func composeTileHandlers(cfg Config, d *deps.AppDeps) (http.HandlerFunc, http.HandlerFunc, error) {
	if cfg.TileServeDisable {
		d.Logger.Info("static-ct tile serving disabled (LEDGER_TILE_SERVE_DISABLE=true)")
		return nil, nil, nil
	}
	var serving bytestore.TileBackend
	switch cfg.TileBackend {
	case "", "posix":
		serving = d.TileBackend
	case "gcs":
		gcsBackend, ok := d.ByteStore.(*bytestore.GCS)
		if !ok {
			return nil, nil, fmt.Errorf(
				"LEDGER_TILE_BACKEND=gcs requires LEDGER_BYTE_STORE_BACKEND=gcs (have %q)",
				cfg.ByteStoreBackend)
		}
		serving = bytestore.NewGCSTiles(gcsBackend, cfg.TileBucketPrefix, 30*time.Second)
	default:
		return nil, nil, fmt.Errorf("LEDGER_TILE_BACKEND must be one of posix|gcs (got %q)", cfg.TileBackend)
	}
	d.Logger.Info("static-ct tile serving enabled",
		"backend", cfg.TileBackend,
		"prefix", cfg.TileBucketPrefix,
	)
	return api.NewCheckpointHandler(serving, d.Logger), api.NewTileHandler(serving, d.Logger), nil
}

func composeSequencer(cfg Config, d *deps.AppDeps) *sequencer.Sequencer {
	pool := d.PgPool.DB
	seq := sequencer.NewSequencer(d.WALCommitter, d.TesseraEmbedded, pool, d.EntryStore, sequencer.Config{
		PollInterval: cfg.SequencerInterval,
		MaxInFlight:  cfg.SequencerMaxInFlight,
		Logger:       d.Logger,
	})
	seq = seq.WithLagReader(store.NewSequenceCursor(pool))

	if d.RecentEntryCache != nil {
		seq = seq.WithRecentEntryCache(d.RecentEntryCache)
	}

	if d.Fatal != nil {
		seq = seq.WithFatalChannel(d.Fatal)
	}

	if d.GossipStore != nil && d.GossipBundle != nil {
		emitter, ferr := gossipnet.NewSDKGossipGhostLeafEmitter(
			gossipnet.SDKGossipGhostLeafEmitterConfig{
				GossipStore: d.GossipStore,
				Sink:        d.GossipBundle.Sink,
				Signer:      cosign.NewECDSAWitnessSigner(d.LedgerSignerPriv),
				NetworkID:   cfg.NetworkID,
				Originator:  cfg.LedgerDID,
				Logger:      d.Logger,
			})
		if ferr != nil {
			d.Logger.Error("ghost-leaf SDK emitter construction; falling back to logging-only",
				"error", ferr)
			seq = seq.WithGhostLeafEmitter(gossipnet.NewLoggingGhostLeafEmitter(d.Logger))
		} else {
			seq = seq.WithGhostLeafEmitter(emitter)
			d.Logger.Info("ghost-leaf emitter: SDK gossip path wired (KindGhostLeaf publication enabled)")
		}
	} else {
		seq = seq.WithGhostLeafEmitter(gossipnet.NewLoggingGhostLeafEmitter(d.Logger))
		d.Logger.Info("ghost-leaf emitter: logging-only (gossip disabled — ghost rows recorded in PG, not broadcast)")
	}

	if d.SchemaRegistry != nil {
		seq = seq.WithSchemaRegistry(d.SchemaRegistry)
	}
	if d.GossipStore != nil {
		seq = seq.WithSplitIDIndex(
			gossipnet.NewSequencerSplitIDAdapter(d.GossipStore))
		seq = seq.WithEntryLookup(
			gossipnet.NewSequencerEntryLookupAdapter(d.GossipStore),
			cfg.LogDID)
		replayer, rerr := sequencer.NewReplayer(sequencer.ReplayConfig{
			DB:           pool,
			Reader:       d.ByteStore,
			SplitIDIndex: gossipnet.NewSequencerSplitIDAdapter(d.GossipStore),
			EntryLookup:  gossipnet.NewSequencerEntryLookupAdapter(d.GossipStore),
			Cursor:       gossipnet.NewSequencerReplayCursorAdapter(d.GossipStore),
			LogDID:       cfg.LogDID,
			Logger:       d.Logger,
		})
		if rerr == nil {
			seq = seq.WithReplayer(replayer)
		} else {
			d.Logger.Warn("sequencer replayer construct failed; continuing without", "error", rerr)
		}
	}
	d.Logger.Info("sequencer ready",
		"poll_interval", cfg.SequencerInterval,
		"max_in_flight", cfg.SequencerMaxInFlight,
		"mmd", cfg.MMD,
		"splitid_index", d.GossipStore != nil,
		"entry_lookup_projection", d.GossipStore != nil,
		"boot_replayer", d.GossipStore != nil,
	)
	return seq
}

func composeShipper(cfg Config, d *deps.AppDeps) *shipper.Shipper {
	ship := shipper.NewShipper(d.WALCommitter, d.ByteStore, shipper.Config{
		PollInterval:  cfg.ShipperPollInterval,
		MaxInFlight:   cfg.ShipperMaxInFlight,
		MaxAttempts:   uint32(cfg.ShipperMaxAttempts),
		BackoffBase:   cfg.ShipperBackoffBase,
		BackoffMax:    cfg.ShipperBackoffMax,
		HealthyWindow: cfg.ShipperHealthyWindow,
		AIMDStep:      cfg.ShipperAIMDStep,
		Logger:        d.Logger,
	})
	d.Logger.Info("shipper: configured",
		"max_in_flight", cfg.ShipperMaxInFlight,
		"poll_interval", cfg.ShipperPollInterval)
	return ship
}

func composeIntegrityDetector(d *deps.AppDeps) *integrity.Detector {
	return integrity.NewDetector(
		d.WALCommitter,
		integrity.NewVerifier(d.TileReader.Fetch),
		integrity.DetectorConfig{Logger: d.Logger},
	)
}

func composeSMTDetector(d *deps.AppDeps) *integrity.SMTDetector {
	return integrity.NewSMTDetector(
		smtRootStateAdapter{store: d.SMTRootState},
		treeHeadStoreAdapter{store: d.TreeHeadStore},
		integrity.SMTDetectorConfig{Logger: d.Logger},
	)
}

type smtRootStateAdapter struct {
	store *store.SMTRootStateStore
}

func (a smtRootStateAdapter) Read(ctx context.Context) (integrity.SMTRootSnapshot, error) {
	st, err := a.store.Read(ctx)
	if err != nil {
		return integrity.SMTRootSnapshot{}, err
	}
	return integrity.SMTRootSnapshot{
		CurrentRoot:         st.CurrentRoot,
		CommittedThroughSeq: st.CommittedThroughSeq,
	}, nil
}

type treeHeadStoreAdapter struct {
	store *store.TreeHeadStore
}

func (a treeHeadStoreAdapter) GetBySize(ctx context.Context, size uint64) (*apitypes.CosignedTreeHead, error) {
	return a.store.GetBySize(ctx, size)
}

func composeServers(cfg Config, d *deps.AppDeps, handlers api.Handlers) error {
	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	serverCfg.MaxEntrySize = cfg.MaxEntrySize
	serverCfg.TLSCertFile = cfg.TLSCertFile
	serverCfg.TLSKeyFile = cfg.TLSKeyFile
	serverCfg.ClientCAFile = cfg.InboundClientCAFile
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(d.PgPool.DB), handlers, d.Logger)

	server.SetReadinessProbe(func() error {
		probeCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		conn, err := d.DBBreaker.Acquire(probeCtx)
		if err != nil {
			return fmt.Errorf("database unavailable: %w", err)
		}
		conn.Release()
		return nil
	})

	connCap := cfg.MaxConcurrentConns
	if connCap <= 0 {
		connCap = 8 * runtime.NumCPU()
	}
	rawListener, err := net.Listen("tcp", serverCfg.Addr)
	if err != nil {
		return fmt.Errorf("http listen %q: %w", serverCfg.Addr, err)
	}
	d.HTTPListener = netutil.LimitListener(rawListener, connCap)
	d.HTTPServer = server
	d.HTTPTLSEnabled = serverCfg.TLSCertFile != "" && serverCfg.TLSKeyFile != ""
	d.Logger.Info("http listener ready",
		"addr", serverCfg.Addr,
		"max_concurrent_conns", connCap,
		"tls", serverCfg.TLSCertFile != "" && serverCfg.TLSKeyFile != "",
	)

	if cfg.PprofAddr != "" {
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		d.PprofServer = &http.Server{
			Addr:              cfg.PprofAddr,
			Handler:           pprofMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		d.Logger.Info("pprof listener ready", "addr", cfg.PprofAddr)
	}
	return nil
}

func startGoroutines(
	ctx context.Context,
	d *deps.AppDeps,
	cfg Config,
	bl *builder.BuilderLoop,
	checkpointLoop *builder.CheckpointLoop,
	seq *sequencer.Sequencer,
	ship *shipper.Shipper,
	detector *integrity.Detector,
	smtDetector *integrity.SMTDetector,
) {
	// #76: the constitution must be sequenced at position 0 BEFORE the write
	// surface opens. Start the sequencer (it drains the WAL → entry_index), then
	// synchronously ensure the genesis record, THEN open /v1/entries below. A log
	// that cannot seat its constitution at sequence 0 must not serve writes.
	lifecycle.SafeRunInWG(ctx, &d.WG, "sequencer", d.Logger, d.Fatal, func() error {
		if err := seq.Run(ctx); err != nil && !ctxCanceledOrDeadline(err) {
			d.Fatal <- fmt.Errorf("sequencer: %w", err)
			return err
		}
		return nil
	})
	genesisRecord, err := ensureGenesisRecordFromDeps(ctx, d, cfg)
	if err != nil {
		d.Fatal <- fmt.Errorf("genesis record: %w", err)
		return
	}
	// #76 Part 2: re-root the witness_sets baseline from the log's own seq-0
	// record (a cache of the log, not a config seed). Before /v1/entries opens,
	// so the history endpoints never serve a missing-baseline 404.
	if err := reRootWitnessBaselineFromDeps(ctx, d, cfg, genesisRecord); err != nil {
		d.Fatal <- fmt.Errorf("genesis baseline re-root: %w", err)
		return
	}

	lifecycle.SafeRunInWG(ctx, &d.WG, "http-server", d.Logger, d.Fatal, func() error {
		if d.HTTPServer == nil || d.HTTPListener == nil {
			return nil
		}
		if d.HTTPTLSEnabled {
			if err := d.HTTPServer.ServeTLSWithListener(d.HTTPListener); err != nil && err != http.ErrServerClosed {
				d.Logger.Error("http server (tls)", "error", err)
			}
			return nil
		}
		if err := d.HTTPServer.Serve(d.HTTPListener); err != nil && err != http.ErrServerClosed {
			d.Logger.Error("http server", "error", err)
		}
		return nil
	})

	if d.PprofServer != nil {
		lifecycle.SafeRunInWG(ctx, &d.WG, "pprof-server", d.Logger, nil, func() error {
			if err := d.PprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				d.Logger.Warn("pprof server", "error", err)
			}
			return nil
		})
	}

	lifecycle.SafeRunInWG(ctx, &d.WG, "builder-loop", d.Logger, d.Fatal, func() error {
		if err := bl.Run(ctx); err != nil {
			d.Logger.Error("builder loop exited with error", "error", err)
			return err
		}
		return nil
	})

	if checkpointLoop != nil {
		lifecycle.SafeRunInWG(ctx, &d.WG, "checkpoint-loop", d.Logger, d.Fatal, func() error {
			checkpointLoop.Run(ctx)
			return nil
		})
	}

	lifecycle.SafeRunInWG(ctx, &d.WG, "difficulty-controller", d.Logger, d.Fatal, func() error {
		d.DiffController.Run(ctx, 30*time.Second)
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "anchor-publisher", d.Logger, d.Fatal, func() error {
		d.AnchorPublisher.Run(ctx)
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "shipper", d.Logger, d.Fatal, func() error {
		if err := ship.Run(ctx); err != nil && !ctxCanceledOrDeadline(err) {
			d.Fatal <- fmt.Errorf("shipper: %w", err)
			return err
		}
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "integrity-detector", d.Logger, d.Fatal, func() error {
		if err := detector.Loop(ctx); err != nil && !ctxCanceledOrDeadline(err) {
			d.Fatal <- fmt.Errorf("integrity detector: %w", err)
			return err
		}
		return nil
	})

	lifecycle.SafeRunInWG(ctx, &d.WG, "smt-detector", d.Logger, d.Fatal, func() error {
		if err := smtDetector.Loop(ctx); err != nil && !ctxCanceledOrDeadline(err) {
			d.Fatal <- fmt.Errorf("smt detector: %w", err)
			return err
		}
		return nil
	})

	// Reservation reaper (ledger#193): expires un-finished artifact reservations
	// past their TTL so abandoned RESERVEs don't pin slots forever. Reaping is a
	// non-fatal background sweep, so failures log and retry rather than crash boot.
	if d.ReservationManager != nil {
		lifecycle.SafeRunInWG(ctx, &d.WG, "reservation-reaper", d.Logger, nil, func() error {
			reservation.NewReaper(d.ReservationManager, time.Minute, 256, d.Logger).Run(ctx)
			return nil
		})
	}

	// 2.1: WAL retention GC — reclaims SHIPPED entries below the retention buffer so
	// the WAL footprint stays bounded. WORK-DRIVEN, not wall-clock: a short poll of
	// the O(1) shipped-HWM runs GC only once a full RetentionBuffer has aged past
	// the last reclaim (wal.GCDue), so the cadence tracks shipping throughput and
	// each reclaim stays ~one buffer — the footprint is bounded at any write rate
	// with nothing tuned to load (a 5-min wall-clock would instead let the WAL grow
	// 5min×TPS between reclaims). The poll is configurable; the goroutine is skipped
	// entirely when GC is disabled (buffer 0).
	if d.WALCommitter != nil && d.WALCommitter.RetentionBuffer() > 0 {
		buffer := d.WALCommitter.RetentionBuffer()
		poll := 30 * time.Second
		if v := strings.TrimSpace(os.Getenv("LEDGER_WAL_RETENTION_INTERVAL")); v != "" {
			if dur, err := time.ParseDuration(v); err == nil && dur > 0 {
				poll = dur
			}
		}
		lifecycle.SafeRunInWG(ctx, &d.WG, "wal-retention-gc", d.Logger, nil, func() error {
			ticker := time.NewTicker(poll)
			defer ticker.Stop()
			var lastReclaimedHWM uint64
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					hwm, err := d.WALCommitter.HWM(ctx)
					if err != nil {
						d.Logger.Warn("wal retention GC: read shipped HWM", "error", err)
						continue
					}
					if !wal.GCDue(hwm, lastReclaimedHWM, buffer) {
						continue // < one buffer has aged out since the last reclaim
					}
					if n, err := d.WALCommitter.GCBelowRetention(ctx); err != nil {
						d.Logger.Warn("wal retention GC", "error", err)
					} else if n > 0 {
						lastReclaimedHWM = hwm
						d.Logger.Info("wal retention GC reclaimed", "entries", n, "disk_bytes", d.WALCommitter.DiskBytes(), "shipped_hwm", hwm)
					}
				}
			}
		})
	}

	startAuditTelemetry(ctx, d, detector, smtDetector)
}

func startAuditTelemetry(ctx context.Context, d *deps.AppDeps, detector *integrity.Detector, smtDetector *integrity.SMTDetector) {
	lifecycle.SafeRunInWG(ctx, &d.WG, "audit-telemetry", d.Logger, nil, func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				d.Logger.Info("integrity audit",
					"invariant_failures_total", detector.InvariantFailures(),
					"verify_errors_total", detector.VerifyErrors(),
					"samples_verified_total", detector.SamplesVerified(),
					"samples_skipped_total", detector.SamplesSkipped(),
					"smt_invariant_failures_total", smtDetector.InvariantFailures(),
					"smt_verify_errors_total", smtDetector.VerifyErrors(),
					"smt_samples_verified_total", smtDetector.SamplesVerified(),
					"smt_samples_skipped_total", smtDetector.SamplesSkipped(),
				)
				if d.GossipPublisher != nil {
					age := d.GossipPublisher.CosignAgeSeconds()
					if age >= 0 {
						d.Logger.Info("checkpoint cosig age", "age_seconds", age)
					}
				}
				if d.GossipStore != nil {
					statsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					stats, err := d.GossipStore.Stats(statsCtx)
					cancel()
					if err == nil {
						d.Logger.Info("gossip store growth",
							"event_count", stats.EventCount,
							"originator_count", stats.OriginatorCount,
						)
					}
				}
			}
		}
	})
}

func installLateBoundGauges(
	cfg Config,
	d *deps.AppDeps,
	seq *sequencer.Sequencer,
	ship *shipper.Shipper,
	checkpointLoop *builder.CheckpointLoop,
) {
	if !cfg.MetricsEnable || d.MeterProvider == nil {
		return
	}
	mp := otel.GetMeterProvider()
	seqMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/sequencer")
	if installed := sequencer.InstallDrainLagGauge(seqMeter, seq.CurrentLag); installed {
		d.Logger.Info("metrics: sequencer drain lag gauge installed",
			"metric", "baseproof_sequencer_drain_lag_seconds")
	}
	shipMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/shipper")
	if installed := shipper.InstallPendingGauge(shipMeter, ship.PendingCount); installed {
		d.Logger.Info("metrics: shipper pending gauge installed",
			"metric", "baseproof_shipper_pending_total")
	}
	if installed := shipper.InstallCounters(shipMeter, ship); installed {
		d.Logger.Info("metrics: shipper counters installed")
	}

	// Phase-2 durability gauges (sustained-load watch surface).
	if observability.RegisterFloat64Gauge(shipMeter, "baseproof_shipper_aimd_limit",
		"AIMD congestion-control concurrency limit (floats below MaxInFlight under store pressure).",
		ship.AIMDLimit) {
		d.Logger.Info("metrics: shipper AIMD limit gauge installed", "metric", "baseproof_shipper_aimd_limit")
	}
	if d.WALCommitter != nil {
		walMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/wal")
		if observability.RegisterInt64Gauge(walMeter, "baseproof_wal_backlog_total",
			"Sequenced-but-not-shipped WAL depth (highest sequenced seq minus HWM).",
			d.WALCommitter.Backlog) {
			d.Logger.Info("metrics: WAL backlog gauge installed", "metric", "baseproof_wal_backlog_total")
		}
		// 2.1: WAL on-disk size — flat post-ship once retention GC reclaims shipped
		// entries below the buffer; unbounded growth otherwise.
		if observability.RegisterInt64Gauge(walMeter, "baseproof_wal_disk_bytes",
			"WAL on-disk size in bytes (Badger LSM + value-log).",
			d.WALCommitter.DiskBytes) {
			d.Logger.Info("metrics: WAL disk-bytes gauge installed", "metric", "baseproof_wal_disk_bytes")
		}
	}
	if checkpointLoop != nil {
		builderMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/builder")
		if observability.RegisterInt64Gauge(builderMeter, "baseproof_horizon_lag_total",
			"Committed head tree_size minus the published witness-cosigned horizon tree_size.",
			checkpointLoop.HorizonLag) {
			d.Logger.Info("metrics: horizon lag gauge installed", "metric", "baseproof_horizon_lag_total")
		}
		// Memory-bounding watch surface: the un-tiled gap (committed − frontier, in
		// entries) and the in-memory node tail it drives. A sustained climb in either
		// means tiling is falling behind commit (the tail growing toward OOM) — the
		// signal the sequencer's tail-backpressure gate also keys on.
		if observability.RegisterInt64Gauge(builderMeter, "baseproof_smt_frontier_lag_total",
			"Committed seq minus the durable SMT tile frontier seq (the un-tiled gap ≈ in-memory node tail, in entries).",
			checkpointLoop.FrontierLag) {
			d.Logger.Info("metrics: SMT frontier lag gauge installed", "metric", "baseproof_smt_frontier_lag_total")
		}
		// Tail-GC observability: cumulative orphans evicted by the prune, and the
		// audit violation count (the scrape-able gate — MUST stay 0).
		if observability.RegisterInt64Gauge(builderMeter, "baseproof_tail_gc_orphans_dropped_total",
			"Cumulative cross-batch orphan nodes evicted from the in-memory SMT tail by the tail-GC prune.",
			checkpointLoop.OrphansDropped) {
			d.Logger.Info("metrics: tail-gc orphans-dropped gauge installed", "metric", "baseproof_tail_gc_orphans_dropped_total")
		}
		if observability.RegisterInt64Gauge(builderMeter, "baseproof_tail_gc_audit_violations_total",
			"Cumulative tail-GC audit violations (a published root reaching a non-durable would-drop node). MUST stay 0.",
			checkpointLoop.AuditViolations) {
			d.Logger.Info("metrics: tail-gc audit-violations gauge installed", "metric", "baseproof_tail_gc_audit_violations_total")
		}
		if d.NodeStore != nil {
			if observability.RegisterInt64Gauge(builderMeter, "baseproof_smt_tail_nodes",
				"In-memory SMT node tail size in nodes (committed-but-not-tiled, plus restart-cleared orphans).",
				func() int64 { return int64(d.NodeStore.TailLen()) }) {
				d.Logger.Info("metrics: SMT tail-nodes gauge installed", "metric", "baseproof_smt_tail_nodes")
			}
		}
	}
}

func ctxCanceledOrDeadline(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}

// ─────────────────────────────────────────────────────────────────────
// v1.37.0 SDK adoption — polymorphic admission via VerifierRegistry
// ─────────────────────────────────────────────────────────────────────
//
// buildIdentityDeps composes the identity-verification surface for
// the submission handler. v1.37.0 swaps the pre-existing hardcoded
// did:key ECDSA-only resolver for the SDK's polymorphic verifier
// registry, which dispatches on DID method (did:key, did:web,
// did:pkh) and algorithm (ECDSA secp256k1, Ed25519, EIP-191,
// EIP-712, EIP-1271, ML-DSA-65, ML-DSA-87, SLH-DSA-128s).
//
// The legacy DIDResolver field on IdentityDeps is retained for
// backward compatibility (tests pass it directly). Production sets
// Verifier; api/submission.go prefers Verifier when both are set.
//
// EIP-1271 (smart-contract wallets) is enabled only when
// LEDGER_EIP1271_ENABLED=true AND the operator supplied >=2 executor
// endpoints. At the default zero-valued PKHVerifierOptions, did:pkh
// runs in EOA-only mode (no chain RPC).
//
// did:web HTTPS fetches use d.OutboundHTTPClient (always non-nil
// since PR #181 / v1.34.0 contract honesty). A 5-minute CachingResolver
// wraps the method router to amortize repeated court-actor
// resolutions; the cache TTL matches the recommended floor from the
// court-system workload audit.
func buildIdentityDeps(d *deps.AppDeps) api.IdentityDeps {
	// Backward-compat: keep the existing did:key ECDSA resolver wired
	// on the DIDResolver field. The legacy single-sig admission path
	// and any tests that pass deps.Identity.DIDResolver still work
	// against ECDSA-only entries.
	legacyResolver := sdkdid.NewECDSAKeyResolver()

	// v1.37.0 polymorphic path. Method router dispatches on DID method;
	// each registered resolver is constructed lazily once at boot.
	router := sdkdid.NewMethodRouter()
	if err := router.Register("key", sdkdid.NewKeyResolver()); err != nil {
		d.Logger.Error("buildIdentityDeps: register did:key resolver", "error", err)
	}
	if d.OutboundHTTPClient != nil {
		webResolver, err := sdkdid.NewWebDIDResolver(sdkdid.WebDIDResolverConfig{
			Client: d.OutboundHTTPClient,
		})
		if err != nil {
			d.Logger.Error("buildIdentityDeps: NewWebDIDResolver", "error", err)
		} else {
			if rerr := router.Register("web", webResolver); rerr != nil {
				d.Logger.Error("buildIdentityDeps: register did:web", "error", rerr)
			}
		}
	}
	// did:pkh is registered but its public-key resolution is a no-op
	// at the resolver layer (the verifier dispatches address-based
	// ecrecover internally via PKHVerifier in DefaultVerifierRegistry).

	cached := sdkdid.NewCachingResolver(router, 5*time.Minute)

	// DefaultVerifierRegistry registers did:pkh + did:key + did:web
	// verifiers. PKHVerifierOptions controls EIP-1271; zero value =
	// EOA-only (the production default). Destination binding pins
	// signature verification to this ledger's DID — cross-network
	// replay attempts fail at the cryptographic boundary.
	registry, err := sdkdid.DefaultVerifierRegistry(
		d.LedgerDID, cached, d.PKHVerifierOptions)
	if err != nil {
		// Construction error is fatal at boot: a misconfigured
		// PKHVerifierOptions (e.g., K-of-N with invalid executor
		// set) MUST surface here, never as a silent fallback to
		// EOA-only at runtime. main.go has already validated
		// LEDGER_EIP1271_* env vars at LoadEIP1271Config; this is
		// the SDK-side validation gate.
		d.Logger.Error("buildIdentityDeps: DefaultVerifierRegistry",
			"error", err,
			"ledger_did", d.LedgerDID,
			"eip1271_enabled", len(d.PKHVerifierOptions.Executors) > 0,
		)
		// Fall through with Verifier=nil; admission falls back to
		// the legacy DIDResolver path (ECDSA-only via the adapter).
		// Boot does not exit because the legacy path remains
		// functional for ECDSA-only deployments.
		return api.IdentityDeps{
			Credits:     d.CreditStore,
			DIDResolver: legacyResolver,
		}
	}

	d.Logger.Info("v1.37.0: polymorphic verifier registry wired",
		"methods", []string{"did:key", "did:web", "did:pkh"},
		"eip1271_enabled", len(d.PKHVerifierOptions.Executors) > 0,
		"cache_ttl", "5m",
	)

	return api.IdentityDeps{
		Credits:     d.CreditStore,
		DIDResolver: legacyResolver,
		Verifier:    registry,
	}
}

// anchorChainProvider derives the /v1/network/anchors chain from the durable
// read-back confirmations: one hop per parent, freshest first-seen. The
// WitnessSetHash field is served zero — the parent's set hash at admission is
// the parent's state, not ours; consumers fetch it live via the parent's
// /v1/network/witnesses/* (the SDK walker re-verifies every hop regardless).
func anchorChainProvider(s *store.AnchorConfirmationStore, logDID string) func(ctx context.Context) (api.WireAnchorChain, error) {
	zeroSetHash := strings.Repeat("0", 64)
	return func(ctx context.Context) (api.WireAnchorChain, error) {
		latest, err := s.LatestPerParent(ctx)
		if err != nil {
			return api.WireAnchorChain{}, err
		}
		chain := api.WireAnchorChain{LogDID: logDID}
		for _, c := range latest {
			chain.Hops = append(chain.Hops, api.WireAnchorChainEntry{
				ParentLogDID:         c.ParentLogDID,
				WitnessSetHash:       zeroSetHash,
				LatestAnchorSeq:      c.ParentSeq,
				LatestAnchorTreeSize: c.AnchoredTreeSize,
			})
		}
		return chain, nil
	}
}
