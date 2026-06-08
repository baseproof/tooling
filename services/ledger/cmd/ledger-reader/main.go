/*
FILE PATH:

	cmd/ledger-reader/main.go

DESCRIPTION:

	Read-only Baseproof log ledger. Serves all GET endpoints.
	Does NOT run the builder loop, accept submissions, or write anything.

KEY ARCHITECTURAL DECISIONS:
  - Hash-only tiles: TesseraEntryReader removed because entry tiles now contain
    32-byte SHA-256 hashes, not full wire bytes. The reader needs access to the
    same byte store as the writer for full entry bytes.
  - Production: shared persistent byte store (DiskEntryStore, GCS-backed, etc.).
    The reader and writer ledger both access the same backing store.
  - Local dev: InMemoryEntryStore — the reader process has an EMPTY byte store
    unless it shares the writer's process or backing directory. Entry byte
    hydration will fail for entries not in the store. This is acceptable for
    local dev where the read-write ledger is the primary deployment.
  - All GET endpoints remain functional for Postgres-only queries (tree head,
    SMT proofs, difficulty). Entry byte hydration endpoints (entry fetch, query
    results with canonical_bytes) require the shared byte store.

OVERVIEW:

	Same startup as the read-write ledger, minus:
	- No builder loop (no advisory lock, no queue drain).
	- No submission handler (POST /v1/entries returns 404).
	- No witness cosign endpoint.
	- Entry byte store: InMemoryEntryStore (empty on start — production uses shared persistent).
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/baseproof/baseproof/core/smt"

	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/api/middleware"
	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/lifecycle"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/store/indexes"
	"github.com/baseproof/tooling/services/ledger/tessera"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("ledger-reader fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := loadConfig()
	logger.Info("config loaded (read-only mode)", "log_did", cfg.LogDID, "addr", cfg.ServerAddr)

	// ── Postgres read pool ─────────────────────────────────────────────
	dsn := cfg.ReplicaDSN
	if dsn == "" {
		dsn = cfg.PostgresDSN
	}
	// PG-off read front: boot even when Postgres is unreachable (LazyConnect),
	// so the object-store-backed surface (proofs, horizon, SMT/log tiles) stays
	// available during a PG outage. PG-backed endpoints (/v1/entries value
	// lookups, /v1/smt/leaf, /v1/query/*) then fail per-request and recover when
	// PG returns. Only a malformed DSN is fatal here.
	pool, err := store.InitPool(ctx, store.PoolConfig{
		DSN:              dsn,
		MaxConns:         int32(cfg.MaxConns),
		MinConns:         int32(cfg.MinConns),
		MaxConnLifetime:  30 * time.Minute,
		MaxConnIdleTime:  5 * time.Minute,
		StatementTimeout: cfg.StatementTimeout,
		LazyConnect:      true,
	})
	if err != nil {
		return fmt.Errorf("postgres pool: %w", err)
	}
	defer pool.Close()
	pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
	if pingErr := pool.DB.Ping(pingCtx); pingErr != nil {
		logger.Warn("postgres unreachable at boot — serving object-store-backed surface only; PG-backed endpoints will error until PG recovers", "error", pingErr)
	} else {
		logger.Info("postgres read pool initialized", "replica", cfg.ReplicaDSN != "")
	}
	pingCancel()

	// ── Entry byte store ──────────────────────────────────────────────
	// Reader points at the same backend + prefix the writer ledger uses, so
	// byte hydration on GET requests returns the same bytes the writer
	// admitted. Backend selected via LEDGER_BYTE_STORE_BACKEND (gcs|s3); the
	// factory enforces per-backend required fields. Resolved BEFORE the tile
	// backends below because the byte-store backend SELECTS the tile substrate:
	// an object store (S3/GCS) serves tessera log tiles, SMT tiles, and the
	// cosigned horizon to a PG-free read front with NO shared filesystem.
	switch cfg.ByteStoreBackend {
	case "":
		return fmt.Errorf("LEDGER_BYTE_STORE_BACKEND required (gcs|s3)")
	case "gcs":
		if cfg.ByteStoreGCSBucket == "" {
			return fmt.Errorf("LEDGER_BYTE_STORE_GCS_BUCKET required when LEDGER_BYTE_STORE_BACKEND=gcs")
		}
	case "s3":
		if cfg.ByteStoreS3Bucket == "" {
			return fmt.Errorf("LEDGER_BYTE_STORE_S3_BUCKET required when LEDGER_BYTE_STORE_BACKEND=s3")
		}
	default:
		return fmt.Errorf("LEDGER_BYTE_STORE_BACKEND=%q not supported (gcs|s3)", cfg.ByteStoreBackend)
	}
	entryBytes, gerr := bytestore.NewFromConfig(ctx, cfg.toBytestoreConfig())
	if gerr != nil {
		return fmt.Errorf("byte store init: %w", gerr)
	}
	defer func() {
		if closer, ok := entryBytes.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				logger.Warn("byte store close", "error", err)
			}
		}
	}()
	logger.Info("ledger-reader byte store ready",
		"backend", cfg.ByteStoreBackend,
		"prefix", cfg.ByteStorePrefix,
		"cache_size", cfg.ByteStoreCacheSize,
	)

	// ── Tessera log tiles + SMT tiles + cosigned horizon (read-only) ───
	//
	// The stateless read tier. When the byte store is an OBJECT store (S3/GCS),
	// inclusion proofs (tessera log tiles), SMT proofs, and the cosigned horizon
	// are ALL reconstructed from that shared store — the writer ships its log
	// tiles there (tessera/tile_shipper.go), so a reader pod needs no filesystem
	// shared with the writer and Postgres only for value lookups. Otherwise the
	// reader reads the writer's POSIX tile dir directly (single-node / k8s shared
	// volume). Proofs are served as-of the published cosigned horizon;
	// smt_leaves (PG) still backs /v1/smt/leaf value lookups.
	leafStore := store.NewPostgresLeafStore(pool.DB)
	var tileBackend tessera.TileBackend
	var tesseraAppender tessera.AppenderBackend
	var smtTiles store.SMTTileStore
	var horizon api.HorizonReader
	// Receipt-proof surface (the entry's third cosigned-root leg). Resolved per
	// substrate below: an object-store deployment reconstructs it PG-free from the
	// checkpoint-size index + the dense receipt-commitment archive; the POSIX
	// shared-volume reader uses the co-located Postgres (wired after treeHeadStore).
	var receiptHeads api.ReceiptHeadResolver
	var receiptProver api.ReceiptProver
	if s3, ok := entryBytes.(*bytestore.S3); ok {
		tileBackend = tessera.NewObjectTileBackend(s3)
		smtTiles = store.NewS3SMTTileStore(s3)
		s3Horizon := store.NewS3HorizonReader(s3)
		horizon = s3Horizon
		// PG-free receipt proofs: the checkpoint-size index enumerates published
		// checkpoints (the covering-head resolver) and the per-checkpoint
		// receipt-commit archive reconstructs the inclusion proof — both written
		// durable-before-horizon by the writer (store.S3CheckpointPublisher +
		// builder.CheckpointLoop), so any entry a published head covers has a
		// reconstructable receipt with no Postgres in the path.
		receiptHeads = store.NewS3ReceiptHeadResolver(store.NewS3CheckpointSizeIndex(s3), s3Horizon)
		receiptProver = store.NewArchiveReceiptRanger(s3Horizon, cfg.LogDID)
		// No POSIX checkpoint file in an object-store deployment: the proof
		// adapter's tree head/size come from the published cosigned horizon
		// (horizon_appender.go); the proofs themselves come from the tiles.
		tesseraAppender = newHorizonAppenderBackend(horizon)
		logger.Info("tessera initialized (read-only, object store)", "byte_store", cfg.ByteStoreBackend)
	} else {
		posix, perr := tessera.NewPOSIXTileBackend(cfg.TesseraStorageDir)
		if perr != nil {
			return fmt.Errorf("tessera posix tile backend: %w", perr)
		}
		tileDir := strings.TrimSpace(os.Getenv("LEDGER_SMT_TILE_EMIT_DIR"))
		if tileDir == "" {
			tileDir = "/var/lib/ledger/tiles"
		}
		tileBackend = posix
		smtTiles = store.NewPosixSMTTileStore(tileDir)
		horizon = api.NewTileBackendHorizon(posix)
		// ReadOnlyAppender's AppendLeaf returns ErrReadOnly — a loud rejection
		// if any future code path mistakenly tries to write from the reader.
		tesseraAppender = tessera.NewReadOnlyAppender(posix)
		logger.Info("tessera initialized (read-only, POSIX)", "storage_dir", cfg.TesseraStorageDir)
	}
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	tesseraAdapter := tessera.NewTesseraAdapter(ctx, tesseraAppender, tileReader, logger)
	nodeStore := smt.NewTiledNodeStore(ctx, smtTiles, smt.NewTileCache(cfg.SMTCacheSize))
	tree := smt.NewTree(leafStore, nodeStore)

	// ── Stores ─────────────────────────────────────────────────────────
	treeHeadStore := store.NewTreeHeadStore(pool.DB)
	commitmentStore := store.NewCommitmentStore(pool.DB)
	fetcher := store.NewPostgresEntryFetcher(pool.DB, entryBytes, cfg.LogDID)

	// POSIX shared-volume reader: receipts resolve from the co-located Postgres
	// (tree_heads as the covering-head ladder + entry_index as the commitment ranger).
	// The S3 branch above already wired the PG-free path; this fills only the POSIX case.
	if receiptHeads == nil {
		receiptHeads = treeHeadStore
		receiptProver = store.NewEntryIndexReceiptRanger(pool.DB, cfg.LogDID)
	}

	// ── Difficulty (static) ────────────────────────────────────────────
	diffController := middleware.NewDifficultyController(
		nil,
		middleware.DifficultyConfig{
			InitialDifficulty: uint32(cfg.InitialDifficulty),
			MinDifficulty:     uint32(cfg.MinDifficulty),
			MaxDifficulty:     uint32(cfg.MaxDifficulty),
			HashFunction:      cfg.HashFunction,
		}, logger,
	)

	// ── Stores (read-only) ─────────────────────────────────────────────
	entryStore := store.NewEntryStore(pool.DB)

	// ── Query API ──────────────────────────────────────────────────────
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool.DB, entryBytes, cfg.LogDID)

	// ── HTTP handlers ──────────────────────────────────────────────────
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: tesseraAdapter,
		Consistency: tesseraAdapter, Logger: logger,
		// PG-off: default the inclusion proof's tree size to the cosigned
		// horizon when the live head (Postgres) is unavailable.
		Horizon: horizon,
	}
	smtDeps := &api.SMTDeps{
		Tree:        tree,
		LeafStore:   leafStore,
		Logger:      logger,
		ProofSource: store.SMTProofSourceTiles,
		Tiles:       smtTiles,
		TileCache:   smt.NewTileCache(cfg.SMTCacheSize),
		Horizon:     horizon,
	}
	queryDeps := &api.QueryDeps{
		QueryAPI: queryAPI, DiffController: diffController, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI,
		EntryStore: entryStore,
		// Read-only ledger has no WAL — the /raw handler degrades
		// to "always 302 to byte store". Un-shipped entries surface
		// as bytestore 404; consumers retry against the writer.
		WAL: nil,
		// PublicURLer is satisfied by bytestore.GCS/S3 (Backend
		// embeds PublicURLer); type-assert here so this package
		// doesn't depend on bytestore types directly.
		PublicURLer: entryBytes.(api.PublicURLer),
		LogDID:      cfg.LogDID,
		Logger:      logger,
		// PG-off seq→hash: when the entry_index is unreachable, resolve the
		// canonical hash from the entry tile (object store), bounded by the
		// cosigned horizon, so /v1/entries/{seq}/raw still serves via redirect.
		SeqHashFallback: func(ctx context.Context, seq uint64) ([32]byte, bool, error) {
			head, _, herr := horizon.ReadHorizon(ctx)
			if herr != nil {
				return [32]byte{}, false, herr
			}
			return tessera.SeqHashFromEntryTile(ctx, tileReader, head.TreeSize, seq)
		},
	}
	commitDeps := &api.DerivationCommitmentDeps{
		CommitmentStore: commitmentStore, Logger: logger,
	}

	handlers := readerHandlers(treeDeps, smtDeps, queryDeps, entryReadDeps, commitDeps, horizon,
		&api.ReceiptDeps{Heads: receiptHeads, Receipts: receiptProver, MinSigs: cfg.WitnessQuorumK, Logger: logger},
		cfg.LogDID, logger)

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	// Serve open HTTPS like the writer when TLS material is configured
	// (LEDGER_TLS_CERT_FILE / LEDGER_TLS_KEY_FILE): the read front terminates TLS
	// in-binary with the same server cert, so proof tooling verifies it against
	// the run CA exactly as it does the writer — one transport, one client
	// posture. Absent both, it stays plain HTTP (local dev / sidecar).
	serverCfg.TLSCertFile = cfg.TLSCertFile
	serverCfg.TLSKeyFile = cfg.TLSKeyFile
	tlsEnabled := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(pool.DB), handlers, logger)

	// ── Start + shutdown ───────────────────────────────────────────────
	// HTTP server panic surfaces via the recover branch in
	// SafeRunInWG. ledger-reader has no fatal channel (no
	// supervisor goroutines beyond the HTTP server), so panics are
	// caught + logged and the goroutine exits; the signal-driven
	// shutdown path still drives the cleanup.
	serve := server.ListenAndServe
	if tlsEnabled {
		serve = server.ListenAndServeTLS
	}
	var wg sync.WaitGroup
	lifecycle.SafeRunInWG(ctx, &wg, "http-server", logger, nil, func() error {
		if err := serve(); err != nil {
			logger.Error("http server exited", "error", err)
		}
		return nil
	})
	logger.Info("HTTP server started (read-only)", "addr", cfg.ServerAddr, "tls", tlsEnabled)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("shutdown signal received", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	cancel()
	wg.Wait()
	logger.Info("ledger-reader stopped cleanly")
	return nil
}

// readerHandlers assembles the read-only ledger's HTTP handler set. Extracted
// from run() so the wiring — notably the cosigned-horizon route, which a PG-off
// read front MUST mount — is unit-testable without standing up PG / S3 / the
// object store.
//
// The Horizon route is the load-bearing addition: server.go mounts
// GET /v1/tree/horizon iff handlers.Horizon != nil, and an offline proof binds
// to the published cosigned head this serves, so a read front that omits it
// leaves clients with no anchor to fetch. It is built from the SAME
// HorizonReader smtDeps already uses for as-of proof serving.
func readerHandlers(
	treeDeps *api.TreeDeps,
	smtDeps *api.SMTDeps,
	queryDeps *api.QueryDeps,
	entryReadDeps *api.EntryReadDeps,
	commitDeps *api.DerivationCommitmentDeps,
	horizon api.HorizonReader,
	receiptDeps *api.ReceiptDeps,
	logDID string,
	logger *slog.Logger,
) api.Handlers {
	// CheckpointArchive (1.1a): the per-size cosigned-head read API. The horizon
	// reader serves it iff it backs a per-size archive (the POSIX TileBackend
	// horizon does); otherwise NewCheckpointArchiveHandler degrades to a 503.
	archiveReader, _ := horizon.(api.CheckpointArchiveReader)
	return api.Handlers{
		Submission:        nil, // No POST /v1/entries in read-only mode.
		TreeHead:          api.NewTreeHeadHandler(treeDeps),
		TreeInclusion:     api.NewTreeInclusionHandler(treeDeps),
		TreeConsistency:   api.NewTreeConsistencyHandler(treeDeps),
		Horizon:           api.NewCosignedCheckpointHandler(horizon, logger),
		CheckpointArchive: api.NewCheckpointArchiveHandler(archiveReader, logger),
		SMTProof:          api.NewSMTProofHandler(smtDeps),
		SMTBatchProof:     api.NewSMTBatchProofHandler(smtDeps),
		SMTRoot:           api.NewSMTRootHandler(smtDeps),
		// ReceiptProof + Burn are the v2 proof's third-root + equivocation legs. The
		// SDK gather fetches BOTH unconditionally and fails the proof on a 404
		// (log/bundle/v2_build.go), so a read front that omits them cannot serve a full
		// offline proof. ReceiptProof reconstructs PG-free from the object store (S3
		// branch) or PG (POSIX). Burn observes no gossip here, so it reports
		// is_burned=false (NewGossipBurnSource handles the nil store).
		ReceiptProof: api.NewReceiptProofHandler(receiptDeps),
		Burn:         api.NewBurnHandler(api.NewGossipBurnSource(nil), logDID, logger),
		CosignatureOf:     api.NewQueryCosignatureOfHandler(queryDeps),
		TargetRoot:        api.NewQueryTargetRootHandler(queryDeps),
		SignerDID:         api.NewQuerySignerDIDHandler(queryDeps),
		SchemaRef:         api.NewQuerySchemaRefHandler(queryDeps),
		Scan:              api.NewQueryScanHandler(queryDeps),
		Difficulty:        api.NewDifficultyHandler(queryDeps),
		EntryBySequence:   api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:        api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:          api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:           api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:      api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery:   api.NewDerivationCommitmentQueryHandler(commitDeps),
	}
}

// -------------------------------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------------------------------

type readerConfig struct {
	LogDID            string
	PostgresDSN       string
	ReplicaDSN        string
	MaxConns          int
	MinConns          int
	StatementTimeout  time.Duration // LEDGER_PG_STATEMENT_TIMEOUT, default 5s
	ServerAddr        string
	TesseraStorageDir string // shared POSIX dir with the writer ledger
	TileCacheSize     int
	WarmTopLevels     int
	SMTCacheSize      int
	InitialDifficulty int
	MinDifficulty     int
	MaxDifficulty     int
	HashFunction      string

	// WitnessQuorumK is the distinct-signer threshold a published checkpoint must meet
	// (LEDGER_WITNESS_QUORUM_K, matching the writer). The receipt-proof handler uses it
	// to pick the covering cosigned checkpoint; the S3 resolver treats every archived
	// checkpoint as already-quorum (only cosigned heads are published), so it bites
	// only on the POSIX/PG path. Default 1, the writer's default.
	WitnessQuorumK int

	// TLS. When both are set the read front serves HTTPS (ListenAndServeTLS)
	// with the writer's server cert — proof tooling pins it against the run CA
	// exactly as it does the writer. Both empty ⇒ plain HTTP (local dev/sidecar).
	TLSCertFile string
	TLSKeyFile  string

	// Byte store. Reader and writer must agree on backend + bucket
	// + prefix + NAMESPACE so reads resolve the same objects the
	// writer admitted. Backend selection mirrors the writer
	// ledger: "gcs" or "s3" via LEDGER_BYTE_STORE_BACKEND.
	ByteStoreBackend   string
	ByteStorePrefix    string
	ByteStoreCacheSize int
	// ByteStoreNamespace is the per-log isolation segment the *bytestore.S3 adapter
	// prepends to every RAW substrate key (cosigned-checkpoint horizon, SMT tiles,
	// tessera log tiles, per-size checkpoint + receipt + index archives). It MUST match
	// the writer or the reader resolves none of them. Empty ⇒ derived from LogDID via
	// the SHARED bytestore.NamespaceForLog, exactly as the writer derives it
	// (LEDGER_BYTE_STORE_NAMESPACE overrides, also matching the writer).
	ByteStoreNamespace string
	// GCS-specific.
	ByteStoreGCSBucket   string
	ByteStoreGCSEndpoint string
	ByteStoreGCSAnon     bool
	// S3-specific.
	ByteStoreS3Bucket    string
	ByteStoreS3Endpoint  string
	ByteStoreS3Region    string
	ByteStoreS3AccessKey string
	ByteStoreS3SecretKey string
	ByteStoreS3PathStyle bool
}

func loadConfig() readerConfig {
	return readerConfig{
		// Prefer the writer's LEDGER_* names so the read front is a drop-in with
		// the SAME env (only the DSN points elsewhere / at a dead host for PG-off);
		// the BASEPROOF_* names remain as a fallback so existing deploys keep working.
		LogDID:            envOr("LEDGER_LOG_DID", envOr("BASEPROOF_LOG_DID", "did:baseproof:ledger:001")),
		PostgresDSN:       envOr("LEDGER_DATABASE_URL", envOr("BASEPROOF_POSTGRES_DSN", "postgres://baseproof:baseproof@localhost:5432/baseproof?sslmode=disable")),
		ReplicaDSN:        envOr("LEDGER_REPLICA_DSN", envOr("BASEPROOF_REPLICA_DSN", "")),
		MaxConns:          20,
		MinConns:          5,
		StatementTimeout:  parsePgStatementTimeout(),
		ServerAddr:        envOr("LEDGER_ADDR", envOr("BASEPROOF_SERVER_ADDR", ":8081")),
		TesseraStorageDir: envOr("LEDGER_TESSERA_STORAGE_DIR", envOr("BASEPROOF_TESSERA_STORAGE_DIR", "/var/lib/baseproof/tessera")),
		TileCacheSize:     10000,
		WarmTopLevels:     32,
		SMTCacheSize:      100000,
		InitialDifficulty: 16,
		MinDifficulty:     8,
		MaxDifficulty:     24,
		HashFunction:      "sha256",
		WitnessQuorumK:    envIntOr("LEDGER_WITNESS_QUORUM_K", 1),
		TLSCertFile:       os.Getenv("LEDGER_TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("LEDGER_TLS_KEY_FILE"),

		ByteStoreBackend:   os.Getenv("LEDGER_BYTE_STORE_BACKEND"),
		ByteStorePrefix:    envOr("LEDGER_BYTE_STORE_PREFIX", "entries"),
		ByteStoreNamespace: os.Getenv("LEDGER_BYTE_STORE_NAMESPACE"), // empty → derived from LogDID in toBytestoreConfig
		ByteStoreCacheSize: 4096,
		// GCS family.
		ByteStoreGCSBucket:   os.Getenv("LEDGER_BYTE_STORE_GCS_BUCKET"),
		ByteStoreGCSEndpoint: os.Getenv("LEDGER_BYTE_STORE_GCS_ENDPOINT"),
		ByteStoreGCSAnon:     os.Getenv("LEDGER_BYTE_STORE_GCS_ANONYMOUS") == "true",
		// S3 family.
		ByteStoreS3Bucket:    os.Getenv("LEDGER_BYTE_STORE_S3_BUCKET"),
		ByteStoreS3Endpoint:  os.Getenv("LEDGER_BYTE_STORE_S3_ENDPOINT"),
		ByteStoreS3Region:    os.Getenv("LEDGER_BYTE_STORE_S3_REGION"),
		ByteStoreS3AccessKey: os.Getenv("LEDGER_BYTE_STORE_S3_ACCESS_KEY"),
		ByteStoreS3SecretKey: os.Getenv("LEDGER_BYTE_STORE_S3_SECRET_KEY"),
		ByteStoreS3PathStyle: os.Getenv("LEDGER_BYTE_STORE_S3_PATH_STYLE") == "true",
	}
}

// toBytestoreConfig flattens the reader config into the bytestore
// factory's Config. Mirrors cmd/ledger/main.go's helper so the
// reader and writer pick identical backends — AND the identical per-log
// namespace — from identical env vars; without the matching namespace
// the reader resolves none of the writer's raw substrate objects.
func (c readerConfig) toBytestoreConfig() bytestore.Config {
	bc := bytestore.Config{
		Backend:   c.ByteStoreBackend,
		Prefix:    c.ByteStorePrefix,
		Namespace: c.byteStoreNamespace(),
		CacheSize: c.ByteStoreCacheSize,
	}
	switch c.ByteStoreBackend {
	case "gcs":
		bc.Bucket = c.ByteStoreGCSBucket
		bc.GCSEndpoint = c.ByteStoreGCSEndpoint
		bc.GCSAnonymous = c.ByteStoreGCSAnon
	case "s3":
		bc.Bucket = c.ByteStoreS3Bucket
		bc.S3Endpoint = c.ByteStoreS3Endpoint
		bc.S3Region = c.ByteStoreS3Region
		bc.S3AccessKey = c.ByteStoreS3AccessKey
		bc.S3PathStyle = c.ByteStoreS3PathStyle
		bc.S3SecretKey = c.ByteStoreS3SecretKey
	}
	return bc
}

// byteStoreNamespace resolves the per-log object-store namespace the writer prepends
// to every raw substrate key. An explicit LEDGER_BYTE_STORE_NAMESPACE wins; otherwise
// it is DERIVED from the LogDID via the SHARED bytestore.NamespaceForLog — the EXACT
// derivation cmd/ledger uses (config.byteStoreNamespace) — so the read front resolves
// the SAME namespace for a given log and finds the writer's horizon, tiles, and
// checkpoint/receipt/index archives. Empty only when LogDID is empty.
func (c readerConfig) byteStoreNamespace() string {
	if c.ByteStoreNamespace != "" {
		return c.ByteStoreNamespace
	}
	return bytestore.NamespaceForLog(c.LogDID)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envIntOr reads key as a base-10 int, falling back to def when unset or unparseable.
func envIntOr(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// parsePgStatementTimeout reads LEDGER_PG_STATEMENT_TIMEOUT as a Go
// duration. Defaults to 5 s. An unparseable value silently falls
// back to the default — the writer ledger emits a warning if its
// own copy fails to parse, so the misconfig is still administrator-
// visible from the writer's logs.
func parsePgStatementTimeout() time.Duration {
	const def = 5 * time.Second
	v := os.Getenv("LEDGER_PG_STATEMENT_TIMEOUT")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return def
	}
	return d
}
