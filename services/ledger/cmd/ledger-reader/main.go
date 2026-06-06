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

	// ── Tessera (read-only) ─────────────────────────────────────
	// The reader binary reads tiles + checkpoint directly off the
	// POSIX directory the writer ledger's embedded Tessera writes
	// to (shared volume in k8s, same host in single-node
	// deployments). ReadOnlyAppender's AppendLeaf returns
	// ErrReadOnly — a loud rejection if any future code path
	// mistakenly tries to write from the reader.
	tileBackend, err := tessera.NewPOSIXTileBackend(cfg.TesseraStorageDir)
	if err != nil {
		return fmt.Errorf("tessera posix tile backend: %w", err)
	}
	tileReader := tessera.NewTileReader(tileBackend, cfg.TileCacheSize)
	roAppender := tessera.NewReadOnlyAppender(tileBackend)
	tesseraAdapter := tessera.NewTesseraAdapter(ctx, roAppender, tileReader, logger)
	logger.Info("tessera initialized (read-only)", "storage_dir", cfg.TesseraStorageDir)

	// ── Entry byte store ──────────────────────────────────────────────
	// Reader points at the same backend + prefix the writer ledger
	// uses, so byte hydration on GET requests returns the same bytes
	// the writer admitted. Backend selected via LEDGER_BYTE_STORE_BACKEND
	// (gcs|s3); the factory enforces per-backend required fields.
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

	// ── SMT (read-only, de-polluted) ───────────────────────────────────
	//
	// The stateless read tier: the SMT node DAG is read from content-addressed
	// tiles (shared S3/SeaweedFS when the byte store is S3 — every reader pod
	// reads the same objects; else the local POSIX tile dir), NOT jellyfish_nodes.
	// Proofs are served as-of the published cosigned horizon, so no live-root
	// seeding. smt_leaves (PG) still backs /v1/smt/leaf value lookups.
	leafStore := store.NewPostgresLeafStore(pool.DB)
	var smtTiles store.SMTTileStore
	var horizon api.HorizonReader
	if s3, ok := entryBytes.(*bytestore.S3); ok {
		smtTiles = store.NewS3SMTTileStore(s3)
		horizon = store.NewS3HorizonReader(s3)
	} else {
		tileDir := strings.TrimSpace(os.Getenv("LEDGER_SMT_TILE_EMIT_DIR"))
		if tileDir == "" {
			tileDir = "/var/lib/ledger/tiles"
		}
		smtTiles = store.NewPosixSMTTileStore(tileDir)
		horizon = api.NewTileBackendHorizon(tileBackend)
	}
	nodeStore := smt.NewTiledNodeStore(ctx, smtTiles, smt.NewTileCache(cfg.SMTCacheSize))
	tree := smt.NewTree(leafStore, nodeStore)

	// ── Stores ─────────────────────────────────────────────────────────
	treeHeadStore := store.NewTreeHeadStore(pool.DB)
	commitmentStore := store.NewCommitmentStore(pool.DB)
	fetcher := store.NewPostgresEntryFetcher(pool.DB, entryBytes, cfg.LogDID)

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

	handlers := readerHandlers(treeDeps, smtDeps, queryDeps, entryReadDeps, commitDeps, horizon, logger)

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = cfg.ServerAddr
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(pool.DB), handlers, logger)

	// ── Start + shutdown ───────────────────────────────────────────────
	// HTTP server panic surfaces via the recover branch in
	// SafeRunInWG. ledger-reader has no fatal channel (no
	// supervisor goroutines beyond the HTTP server), so panics are
	// caught + logged and the goroutine exits; the signal-driven
	// shutdown path still drives the cleanup.
	var wg sync.WaitGroup
	lifecycle.SafeRunInWG(ctx, &wg, "http-server", logger, nil, func() error {
		if err := server.ListenAndServe(); err != nil {
			logger.Error("http server exited", "error", err)
		}
		return nil
	})
	logger.Info("HTTP server started (read-only)", "addr", cfg.ServerAddr)

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
	logger *slog.Logger,
) api.Handlers {
	return api.Handlers{
		Submission:      nil, // No POST /v1/entries in read-only mode.
		TreeHead:        api.NewTreeHeadHandler(treeDeps),
		TreeInclusion:   api.NewTreeInclusionHandler(treeDeps),
		TreeConsistency: api.NewTreeConsistencyHandler(treeDeps),
		Horizon:         api.NewCosignedCheckpointHandler(horizon, logger),
		SMTProof:        api.NewSMTProofHandler(smtDeps),
		SMTBatchProof:   api.NewSMTBatchProofHandler(smtDeps),
		SMTRoot:         api.NewSMTRootHandler(smtDeps),
		CosignatureOf:   api.NewQueryCosignatureOfHandler(queryDeps),
		TargetRoot:      api.NewQueryTargetRootHandler(queryDeps),
		SignerDID:       api.NewQuerySignerDIDHandler(queryDeps),
		SchemaRef:       api.NewQuerySchemaRefHandler(queryDeps),
		Scan:            api.NewQueryScanHandler(queryDeps),
		Difficulty:      api.NewDifficultyHandler(queryDeps),
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryBatch:      api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:        api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:         api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:    api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery: api.NewDerivationCommitmentQueryHandler(commitDeps),
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

	// Byte store. Reader and writer must agree on backend + bucket
	// + prefix so reads return the same bytes
	// the writer admitted. Backend selection mirrors the writer
	// ledger: "gcs" or "s3" via LEDGER_BYTE_STORE_BACKEND.
	ByteStoreBackend   string
	ByteStorePrefix    string
	ByteStoreCacheSize int
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
		LogDID:            envOr("BASEPROOF_LOG_DID", "did:baseproof:ledger:001"),
		PostgresDSN:       envOr("BASEPROOF_POSTGRES_DSN", "postgres://baseproof:baseproof@localhost:5432/baseproof?sslmode=disable"),
		ReplicaDSN:        envOr("BASEPROOF_REPLICA_DSN", ""),
		MaxConns:          20,
		MinConns:          5,
		StatementTimeout:  parsePgStatementTimeout(),
		ServerAddr:        envOr("BASEPROOF_SERVER_ADDR", ":8081"),
		TesseraStorageDir: envOr("BASEPROOF_TESSERA_STORAGE_DIR", "/var/lib/baseproof/tessera"),
		TileCacheSize:     10000,
		WarmTopLevels:     32,
		SMTCacheSize:      100000,
		InitialDifficulty: 16,
		MinDifficulty:     8,
		MaxDifficulty:     24,
		HashFunction:      "sha256",

		ByteStoreBackend:   os.Getenv("LEDGER_BYTE_STORE_BACKEND"),
		ByteStorePrefix:    envOr("LEDGER_BYTE_STORE_PREFIX", "entries"),
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
// reader and writer pick identical backends from identical env vars.
func (c readerConfig) toBytestoreConfig() bytestore.Config {
	bc := bytestore.Config{
		Backend:   c.ByteStoreBackend,
		Prefix:    c.ByteStorePrefix,
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
		bc.S3SecretKey = c.ByteStoreS3SecretKey
		bc.S3PathStyle = c.ByteStoreS3PathStyle
	}
	return bc
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
