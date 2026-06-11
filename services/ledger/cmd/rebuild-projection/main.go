/*
FILE PATH: cmd/rebuild-projection/main.go

CLI wrapper around recovery.Rebuild() (services/ledger/recovery). Operators invoke this in
two disaster-recovery scenarios:

 1. Postgres volume corrupted/wiped. The tile store is intact
    (S3/GCS/CDN); the gossip feed is intact. Re-running migrations
    creates the empty projection schema, then this binary walks
    the tiles and repopulates entry_index, smt_leaves,
    smt_root_state, builder_cursor.

 2. Schema rebase. A migration changes the projection layout. After
    the schema is in place, this binary rebuilds the projection
    content from the immutable tile source.

In both cases the integrity proof is: re-running the live
admission/builder against the same inputs would produce the same
projection rows, byte-for-byte. The integration test
(recovery/rebuild_test.go) pins this invariant.

OPERATIONAL NOTES:

  - The binary is idempotent; re-running over a partial rebuild
    overwrites prior rows (entry_index ON CONFLICT, smt_leaves
    UPSERT). A crash mid-rebuild leaves a consistent partial state
    that the next run finishes.
  - Migrations are NOT run by this binary. Operator must run
    schema migrations first; otherwise the INSERTs fail loudly.
  - Tree heads + witness sets are NOT rebuilt here (they come from
    the gossip feed; that path is §E2 in the production-readiness
    doc).
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/recovery"
	"github.com/baseproof/tooling/services/ledger/store"
	optessera "github.com/baseproof/tooling/services/ledger/tessera"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

func main() {
	var (
		tileDir     = flag.String("tile-dir", "", "filesystem path to the Tessera POSIX tile store (REQUIRED)")
		pgDSN       = flag.String("pg-dsn", "", "Postgres DSN (REQUIRED)")
		logDID      = flag.String("log-did", "", "the log's DID — must match the Origin in the checkpoint (REQUIRED)")
		bsBackend   = flag.String("bytestore-backend", "", "bytestore backend: s3|gcs (REQUIRED — tile/entries holds hashes only; canonical bytes live in the bytestore)")
		bsBucket    = flag.String("bytestore-bucket", "", "bytestore bucket name (REQUIRED)")
		bsPrefix    = flag.String("bytestore-prefix", "", "bytestore key prefix (matches what the live shipper writes to)")
		bsEndpoint  = flag.String("bytestore-endpoint", "", "S3 endpoint URL (for S3-compatible backends; ignored for native GCS)")
		bsRegion    = flag.String("bytestore-region", "us-east-1", "S3 region")
		bsAccessKey = flag.String("bytestore-access-key", "", "S3 access key (or use AWS_ACCESS_KEY_ID env)")
		bsSecretKey = flag.String("bytestore-secret-key", "", "S3 secret key (or use AWS_SECRET_ACCESS_KEY env)")
		bsPathStyle = flag.Bool("bytestore-path-style", false, "S3 path-style addressing (true for SeaweedFS/MinIO; false for AWS S3)")
		batchSize   = flag.Int("batch-size", 500, "entries processed per atomic commit; bounds memory + lock-hold time")
		verbose     = flag.Bool("verbose", false, "log every batch commit at INFO level (default: warn-only)")
		tilesFromBS = flag.Bool("tiles-from-bytestore", false, "read Tessera tiles from the object store the writer ships them to (rebuild-from-object-store / DR path) instead of --tile-dir; the published head is taken from the cosigned horizon")
		bootstrap   = flag.String("bootstrap", "", "path to the network constitution (bootstrap.json). When set, the witness_sets genesis baseline is re-rooted from the log's seq-0 record after the tile walk — the trust root (NetworkID) for that re-root comes from THIS file, out-of-band, exactly as the ledger boots. When unset, witness_sets is left to the gossip-replay path (§E2) and a warning is logged.")
	)
	flag.Parse()
	missing := []string{}
	if *tileDir == "" && !*tilesFromBS {
		missing = append(missing, "--tile-dir (or --tiles-from-bytestore)")
	}
	if *pgDSN == "" {
		missing = append(missing, "--pg-dsn")
	}
	if *logDID == "" {
		missing = append(missing, "--log-did")
	}
	if *bsBackend == "" {
		missing = append(missing, "--bytestore-backend")
	}
	if *bsBucket == "" {
		missing = append(missing, "--bytestore-bucket")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "rebuild-projection: missing required flag(s): %s\n", strings.Join(missing, ", "))
		flag.PrintDefaults()
		os.Exit(2)
	}

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Honour SIGTERM/SIGINT so a long rebuild can be cancelled
	// cleanly; partial state is consistent (cursor + leaves +
	// entry_index advance together per atomic batch).
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	pool, err := pgxpool.New(ctx, *pgDSN)
	if err != nil {
		logger.Error("open postgres pool", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	bsCfg := bytestore.Config{
		Backend:     *bsBackend,
		Bucket:      *bsBucket,
		Prefix:      *bsPrefix,
		S3Endpoint:  *bsEndpoint,
		S3Region:    *bsRegion,
		S3AccessKey: *bsAccessKey,
		S3SecretKey: *bsSecretKey,
		S3PathStyle: *bsPathStyle,
	}
	bs, err := bytestore.NewFromConfig(ctx, bsCfg)
	if err != nil {
		logger.Error("open bytestore", "backend", *bsBackend, "bucket", *bsBucket, "err", err)
		os.Exit(1)
	}

	logger.Info("rebuild-projection: starting",
		"tile_dir", *tileDir,
		"log_did", *logDID,
		"bytestore_backend", *bsBackend,
		"bytestore_bucket", *bsBucket,
		"bytestore_prefix", *bsPrefix,
		"batch_size", *batchSize,
	)

	tileBackend, head, err := resolveTileSource(ctx, *tilesFromBS, *tileDir, bs)
	if err != nil {
		logger.Error("resolve tile source", "tiles_from_bytestore", *tilesFromBS, "err", err)
		os.Exit(1)
	}
	logger.Info("rebuild-projection: head resolved", "tree_size", head.TreeSize, "tiles_from_bytestore", *tilesFromBS)

	start := time.Now()
	stats, err := recovery.Rebuild(ctx, recovery.RebuildDeps{
		TileBackend: tileBackend,
		Head:        head,
		Bytestore:   bs,
		Pool:        pool,
		LogDID:      *logDID,
		BatchSize:   *batchSize,
		Logger:      logger,
	})
	if err != nil {
		logger.Error("rebuild failed",
			"err", err,
			"elapsed", time.Since(start),
		)
		os.Exit(1)
	}

	fmt.Printf("rebuild-projection: complete\n")
	fmt.Printf("  tree_size:      %d\n", stats.TreeSize)
	fmt.Printf("  entries:        %d\n", stats.EntriesProcessed)
	fmt.Printf("  leaves_written: %d\n", stats.LeavesWritten)
	fmt.Printf("  root:           %x\n", stats.Root)
	fmt.Printf("  duration:       %s\n", stats.Duration.Round(time.Millisecond))

	// Witness-set baseline re-root (#76 Part 2). The tile walk above rebuilds
	// entry_index/smt_*; the witness_sets genesis baseline is a projection of
	// the log's OWN seq-0 constitution record, so we reconstruct it from entry 0
	// — no off-log seed. The trust root (NetworkID pin) comes from --bootstrap,
	// out-of-band, so a tampered/wrong genesis record is refused by the same
	// ceremony+hash door the ledger boots through.
	if *bootstrap == "" {
		logger.Warn("rebuild-projection: witness_sets baseline NOT rebuilt — pass --bootstrap to re-root it from the log's seq-0 record (without it, /v1/network/witnesses/* will 404 until the gossip-replay path repopulates)")
		return
	}
	if err := rebuildWitnessBaseline(ctx, pool, bs, *logDID, *bootstrap, logger); err != nil {
		logger.Error("rebuild-projection: witness baseline re-root", "err", err)
		os.Exit(1)
	}
}

// rebuildWitnessBaseline re-roots the witness_sets genesis baseline from the
// log's seq-0 constitution record. The pin is derived from the operator-mounted
// bootstrap file through LoadVerifiedBootstrap (the same fail-closed first-
// contact door the ledger boots through), then entry 0's domain payload is fed
// to witnessclient.RebuildGenesisBaselineFromLog, which re-verifies the embedded
// constitution against that pin and seeds the byte-identical baseline row.
func rebuildWitnessBaseline(
	ctx context.Context,
	pool *pgxpool.Pool,
	bs bytestore.Backend,
	logDID, bootstrapFile string,
	logger *slog.Logger,
) error {
	raw, err := os.ReadFile(bootstrapFile)
	if err != nil {
		return fmt.Errorf("read bootstrap %s: %w", bootstrapFile, err)
	}
	// Fail-closed first contact with our own mounted file, through the SDK's
	// self-pin door (baseproof#52): strict decode + the genesis ceremony whenever
	// the policy requires it. A require constitution stripped of endorsements
	// must not pass — the rebuilt baseline derives only from a verified trust root.
	doc, err := network.LoadSelfVerifiedBootstrap(raw)
	if err != nil {
		return fmt.Errorf("bootstrap %s failed first-contact verification: %w", bootstrapFile, err)
	}
	ids, err := doc.IDs()
	if err != nil {
		return fmt.Errorf("bootstrap %s: %w", bootstrapFile, err)
	}
	pin := [32]byte(ids.NetworkID)

	fetcher := store.NewPostgresEntryFetcher(pool, bs, logDID)
	meta, err := fetcher.Fetch(ctx, types.LogPosition{LogDID: logDID, Sequence: 0})
	if err != nil {
		return fmt.Errorf("read sequence 0: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("sequence 0 not found in the rebuilt projection — the log has no genesis record to re-root from")
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return fmt.Errorf("deserialize sequence 0: %w", err)
	}
	recorded, err := witnessclient.RebuildGenesisBaselineFromLog(ctx, pool, entry.DomainPayload, pin)
	if err != nil {
		return err
	}
	logger.Info("rebuild-projection: witness_sets genesis baseline re-rooted from log",
		"network_id", fmt.Sprintf("%x", pin[:8]),
		"row_inserted", recorded,
	)
	return nil
}

// resolveTileSource builds the tile backend + the published head for the rebuild.
// Default: the local Tessera POSIX dir + its signed checkpoint. With
// --tiles-from-bytestore: the shared object store the writer ships tiles to (no
// local filesystem) + the cosigned horizon for the head (the shipper writes
// tiles, not the tessera checkpoint, to the store). This is the
// rebuild-from-object-store / DR backbone — a wiped node reconstructs Postgres
// from the object store alone.
func resolveTileSource(ctx context.Context, fromBytestore bool, tileDir string, bs bytestore.Backend) (optessera.TileBackend, types.TreeHead, error) {
	if fromBytestore {
		// "S3" here is the object-store abstraction (S3 protocol — SeaweedFS /
		// MinIO / AWS), not an AWS hard-tie; *bytestore.S3 is that implementation.
		s3, ok := bs.(*bytestore.S3)
		if !ok {
			return nil, types.TreeHead{}, fmt.Errorf("--tiles-from-bytestore requires an S3-protocol object store, got %T", bs)
		}
		ch, _, err := store.NewS3HorizonReader(s3).ReadHorizon(ctx)
		if err != nil {
			return nil, types.TreeHead{}, fmt.Errorf("read cosigned horizon: %w", err)
		}
		return optessera.NewObjectTileBackend(s3), ch.TreeHead, nil
	}
	backend, err := optessera.NewPOSIXTileBackend(tileDir)
	if err != nil {
		return nil, types.TreeHead{}, fmt.Errorf("open posix tile backend: %w", err)
	}
	cpBytes, err := backend.ReadCheckpoint(ctx)
	if err != nil {
		return nil, types.TreeHead{}, fmt.Errorf("read checkpoint: %w", err)
	}
	head, err := optessera.ParseCheckpoint(cpBytes)
	if err != nil {
		return nil, types.TreeHead{}, fmt.Errorf("parse checkpoint: %w", err)
	}
	return backend, head, nil
}
