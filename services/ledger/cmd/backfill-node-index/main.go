// Command backfill-node-index rebuilds the durable SMT node→tile-top index
// (smt_node_index, migration 0018) from the durable tile set.
//
// WHEN: the index is normally filled FORWARD at tile-emit time and persists in
// Postgres across restarts, so this is NOT part of normal operation. Run it once
// after a DB-loss recovery (the index table was wiped but the tiles survive) or
// when retrofitting the index onto a ledger whose tiles predate it. It is O(tiles)
// — a scan of the checkpoint-attested tile set, NOT a replay of entry history —
// and idempotent (safe to re-run, and to run while the ledger is live, since
// PutNodes is ON CONFLICT DO NOTHING).
//
// Usage (POSIX tiles):
//
//	backfill-node-index -database-url=$LEDGER_DATABASE_URL -tile-dir=/var/lib/ledger/tiles
//
// Usage (S3/SeaweedFS tiles — pass the SAME bucket/namespace the ledger uses;
// endpoint + credentials come from the standard AWS_* environment):
//
//	backfill-node-index -database-url=… -backend=s3 -bucket=… -prefix=… -namespace=…
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/store"
)

func main() {
	var (
		databaseURL = flag.String("database-url", os.Getenv("LEDGER_DATABASE_URL"), "Postgres connection string")
		backend     = flag.String("backend", "posix", "tile backend: posix | s3")
		tileDir     = flag.String("tile-dir", os.Getenv("LEDGER_SMT_TILE_EMIT_DIR"), "POSIX tile directory (backend=posix)")
		bucket      = flag.String("bucket", "", "object-store bucket (backend=s3)")
		prefix      = flag.String("prefix", "", "object key prefix (backend=s3; match the ledger)")
		namespace   = flag.String("namespace", "", "per-log namespace segment (backend=s3; match the ledger)")
		flushEvery  = flag.Int("flush-every", 5000, "index rows buffered per write")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx := context.Background()

	if *databaseURL == "" {
		logger.Error("backfill-node-index: -database-url (or LEDGER_DATABASE_URL) is required")
		os.Exit(2)
	}

	tiles, err := tileStore(ctx, *backend, *tileDir, *bucket, *prefix, *namespace)
	if err != nil {
		logger.Error("backfill-node-index: tile store", "error", err)
		os.Exit(1)
	}

	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		logger.Error("backfill-node-index: pgxpool", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	idx := store.NewPGNodeIndex(ctx, pool)

	start := time.Now()
	nTiles, nNodes, err := store.BackfillNodeIndex(ctx, tiles, idx, *flushEvery)
	if err != nil {
		// Partial progress is durable + idempotent, so a re-run resumes safely.
		logger.Error("backfill-node-index: FAILED (re-run to resume — idempotent)",
			"tiles_scanned", nTiles, "nodes_indexed", nNodes, "elapsed", time.Since(start), "error", err)
		os.Exit(1)
	}
	logger.Info("backfill-node-index: complete",
		"tiles_scanned", nTiles, "nodes_indexed", nNodes, "elapsed", time.Since(start))
}

// tileStore mirrors the ledger's smtTileStore selection: a POSIX directory or an
// S3-compatible object store (built via the same bytestore.NewFromConfig the
// ledger boots with). Both returned stores enumerate (ListTiles) + Fetch.
func tileStore(ctx context.Context, backend, tileDir, bucket, prefix, namespace string) (interface {
	store.SMTTileLister
	Fetch(ctx context.Context, id [32]byte) ([]byte, error)
}, error) {
	switch backend {
	case "s3":
		bs, err := bytestore.NewFromConfig(ctx, bytestore.Config{
			Backend:   "s3",
			Bucket:    bucket,
			Prefix:    prefix,
			Namespace: namespace,
		})
		if err != nil {
			return nil, err
		}
		return store.NewS3SMTTileStore(bs.(*bytestore.S3)), nil
	default: // posix
		return store.NewPosixSMTTileStore(tileDir), nil
	}
}
