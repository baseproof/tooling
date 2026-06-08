/*
FILE PATH: recovery/archive_backfill.go

ArchiveBackfill — the operator entrypoint that regenerates the cold-read archives
(checkpoints/<n> + the checkpoint-size index, receipts/<n>, the rotation index) for ALL
published history, from Postgres. Run it once to give history that PREDATES the forward
archivers (store.S3CheckpointPublisher, builder.CheckpointLoop's receipt archiver, the
witness-rotation handler) a cold form in the object store — the precondition for
bounding Postgres, since a bounded PG must be reconstructable below its window from the
object store alone.

The walk logic lives in store.ArchiveBackfillJob (ascending cosigned ladder, idempotent,
best-effort per item, off any hot path). This wrapper composes the job from a Postgres
pool + a shared object store so the caller surface — the ledger boot hook
(LEDGER_ARCHIVE_BACKFILL_ON_BOOT) and the future operator CLI — does not repeat the store
wiring.
*/
package recovery

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/tooling/services/ledger/store"
)

// ObjectStore is the shared object store the cold archives live in. Its method set
// matches the store package's internal object surface, so the archive store constructors
// accept it: *bytestore.S3 satisfies it (boot / CLI) and an in-memory fake satisfies it
// (tests). The *bytestore.S3 adapter applies the per-log namespace transparently.
type ObjectStore interface {
	PutObject(ctx context.Context, key string, data []byte) error
	GetObject(ctx context.Context, key string) ([]byte, error)
	HeadObject(ctx context.Context, key string) (bool, error)
}

// ArchiveBackfillDeps are the inputs to a backfill run: the live ledger's Postgres pool +
// shared object store + LogDID, and MinSigs (the witness quorum K the cosigned ladder
// filters on — only K-of-N heads are walked).
type ArchiveBackfillDeps struct {
	Pool        *pgxpool.Pool
	ObjectStore ObjectStore
	LogDID      string
	MinSigs     int
	Logger      *slog.Logger
}

// ArchiveBackfill regenerates the cold-read archives for ALL published history by
// composing the ledger's archive writers over the Postgres cosigned ladder and walking it
// once (store.NewArchiveBackfillFromStores). Idempotent — every write keys on tree_size
// and re-archives identical bytes — and best-effort per item: a single failed object
// write is counted in the returned report and the walk continues, so one corrupt
// checkpoint never abandons the rest of history. Only a ladder-enumeration fault
// (Postgres) returns an error. Off any hot path; ctx cancellation aborts promptly.
func ArchiveBackfill(ctx context.Context, deps ArchiveBackfillDeps) (store.BackfillReport, error) {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	job := store.NewArchiveBackfillFromStores(
		store.NewTreeHeadStore(deps.Pool),
		store.NewS3CheckpointPublisher(deps.ObjectStore),
		store.NewReceiptArchiveWriter(store.NewEntryIndexReceiptRanger(deps.Pool, deps.LogDID), deps.ObjectStore),
		store.NewRotationIndexArchiveJob(deps.Pool, deps.ObjectStore),
		deps.MinSigs,
		logger,
	)
	return job.Run(ctx)
}
