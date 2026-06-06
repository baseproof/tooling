/*
FILE PATH: store/archive_backfill.go

ArchiveBackfillJob — the operator job that regenerates the cold-read archives
(checkpoints/<n>, receipts/<n>, the rotation index) from PG source, for pre-archive
history or after an object-store loss (1.x).

It composes the THREE archive writers already built (S3CheckpointPublisher.
ArchiveCheckpointAt, ReceiptArchiveWriter, RotationIndexArchiveJob) by walking the
cosigned ladder once and invoking each per checkpoint. Operational, NOT load-bearing:
idempotent (every write keys on tree_size and re-archives identical bytes), best-effort
PER ITEM (an item's error is counted + logged, the walk continues), and entirely off
any hot path. The per-checkpoint archive ops are INJECTED as closures so this core
stays free of the apitypes→sdk conversion + object-store types — the composition root
wires them.
*/
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	sdktypes "github.com/baseproof/baseproof/types"
)

// HeadToSDK converts the ledger's apitypes cosigned head (the tree_heads row shape)
// to the SDK's types.CosignedTreeHead — the form the per-size checkpoint archive
// stores (FromCosignedTreeHead) and proofs consume. Each apitypes signature carries a
// JSON-encoded types.WitnessSignature; an unparseable one is skipped (the quorum check
// fails closed downstream). Shared by the receipt handler and the backfill so both
// map a stored head to the SDK shape identically.
func HeadToSDK(h *CosignedTreeHead) sdktypes.CosignedTreeHead {
	if h == nil {
		return sdktypes.CosignedTreeHead{}
	}
	sigs := make([]sdktypes.WitnessSignature, 0, len(h.Signatures))
	for _, s := range h.Signatures {
		var ws sdktypes.WitnessSignature
		if err := json.Unmarshal(s.Signature, &ws); err != nil {
			continue
		}
		sigs = append(sigs, ws)
	}
	return sdktypes.CosignedTreeHead{
		TreeHead: sdktypes.TreeHead{
			RootHash:    h.RootHash,
			SMTRoot:     h.SMTRoot,
			ReceiptRoot: h.ReceiptRoot,
			TreeSize:    h.TreeSize,
		},
		Signatures: sigs,
	}
}

// cosignedLadder enumerates published checkpoints by ascending size — the backfill's
// driver. Satisfied by *TreeHeadStore.
type cosignedLadder interface {
	CosignedSizeAtOrAbove(ctx context.Context, minSize uint64, minSigs int) (uint64, bool, error)
}

// BackfillReport summarizes a run for the operator (and the CLI's exit code).
type BackfillReport struct {
	Checkpoints    int  // published checkpoints walked
	CheckpointErrs int  // per-size checkpoint-archive write failures
	ReceiptErrs    int  // per-checkpoint receipt-archive write failures
	RotationErr    bool // the one rotation-index archive failed
}

// ArchiveBackfillJob regenerates the cold-read archives. The archive ops are
// best-effort closures: checkpoint(size) writes checkpoints/<size>; receipts(cover,
// from, to) writes receipts/<cover>; rotations() writes the rotation index. A nil op
// is skipped.
type ArchiveBackfillJob struct {
	ladder     cosignedLadder
	minSigs    int
	checkpoint func(ctx context.Context, size uint64) error
	receipts   func(ctx context.Context, coveringSize, fromSeq, toSeq uint64) error
	rotations  func(ctx context.Context) error
	logger     *slog.Logger
}

// NewArchiveBackfillFromStores composes the backfill from the ledger's stores: it
// walks heads' cosigned ladder and, per checkpoint, archives the head via publisher
// (per-size, no horizon move), the receipt commitments via receipts, and finally the
// rotation index via rotations. A nil store disables its op (e.g. a receipts-only
// rerun). The per-op type conversion (HeadToSDK) is captured here so the job core
// stays store-agnostic.
func NewArchiveBackfillFromStores(
	heads *TreeHeadStore,
	publisher *S3CheckpointPublisher,
	receipts *ReceiptArchiveWriter,
	rotations *RotationIndexArchiveJob,
	minSigs int,
	logger *slog.Logger,
) *ArchiveBackfillJob {
	var checkpoint func(context.Context, uint64) error
	if heads != nil && publisher != nil {
		checkpoint = func(ctx context.Context, size uint64) error {
			head, err := heads.GetBySize(ctx, size)
			if err != nil {
				return err
			}
			if head == nil {
				return nil // a size that is not a cosigned head — nothing to archive
			}
			return publisher.ArchiveCheckpointAt(ctx, HeadToSDK(head))
		}
	}
	var receiptsOp func(context.Context, uint64, uint64, uint64) error
	if receipts != nil {
		receiptsOp = receipts.ArchiveReceiptCommits
	}
	var rotationsOp func(context.Context) error
	if rotations != nil {
		rotationsOp = rotations.ArchiveCurrentIndex
	}
	return NewArchiveBackfillJob(heads, minSigs, checkpoint, receiptsOp, rotationsOp, logger)
}

// NewArchiveBackfillJob wires the job. logger nil → slog.Default().
func NewArchiveBackfillJob(
	ladder cosignedLadder,
	minSigs int,
	checkpoint func(ctx context.Context, size uint64) error,
	receipts func(ctx context.Context, coveringSize, fromSeq, toSeq uint64) error,
	rotations func(ctx context.Context) error,
	logger *slog.Logger,
) *ArchiveBackfillJob {
	if logger == nil {
		logger = slog.Default()
	}
	return &ArchiveBackfillJob{ladder: ladder, minSigs: minSigs, checkpoint: checkpoint, receipts: receipts, rotations: rotations, logger: logger}
}

// Run walks the cosigned ladder ascending — for each published checkpoint at size
// covering receipt range [prevSize, size-1], it best-effort archives the checkpoint
// head and the receipt commitments — then archives the rotation index once. A
// per-item error is counted + logged and the walk continues (a single corrupt
// checkpoint must not abandon the rest of history). Only a ladder-enumeration error
// (PG fault) aborts. ctx cancellation aborts promptly.
func (j *ArchiveBackfillJob) Run(ctx context.Context) (BackfillReport, error) {
	var rep BackfillReport
	if j == nil || j.ladder == nil {
		return rep, nil
	}
	var prevSize uint64
	size, ok, err := j.ladder.CosignedSizeAtOrAbove(ctx, 1, j.minSigs)
	for err == nil && ok {
		if cErr := ctx.Err(); cErr != nil {
			return rep, cErr
		}
		if j.checkpoint != nil {
			if e := j.checkpoint(ctx, size); e != nil {
				rep.CheckpointErrs++
				j.logger.WarnContext(ctx, "backfill: checkpoint archive failed (best-effort, continuing)", "size", size, "error", e)
			}
		}
		if j.receipts != nil {
			if e := j.receipts(ctx, size, prevSize, size-1); e != nil {
				rep.ReceiptErrs++
				j.logger.WarnContext(ctx, "backfill: receipt archive failed (best-effort, continuing)", "size", size, "from", prevSize, "to", size-1, "error", e)
			}
		}
		rep.Checkpoints++
		prevSize = size

		next, more, nErr := j.ladder.CosignedSizeAtOrAbove(ctx, size+1, j.minSigs)
		if nErr != nil {
			err = nErr
			break
		}
		if more && next <= size {
			// Defensive: the ladder must strictly advance; a non-advancing result
			// would loop forever. Stop rather than spin.
			j.logger.ErrorContext(ctx, "backfill: ladder did not advance — stopping", "at", size, "next", next)
			break
		}
		size, ok = next, more
	}
	if err != nil {
		return rep, fmt.Errorf("store/archive-backfill: enumerate ladder: %w", err)
	}

	if j.rotations != nil {
		if e := j.rotations(ctx); e != nil {
			rep.RotationErr = true
			j.logger.WarnContext(ctx, "backfill: rotation-index archive failed (best-effort)", "error", e)
		}
	}
	j.logger.InfoContext(ctx, "backfill complete",
		"checkpoints", rep.Checkpoints, "checkpoint_errs", rep.CheckpointErrs,
		"receipt_errs", rep.ReceiptErrs, "rotation_err", rep.RotationErr)
	return rep, nil
}
