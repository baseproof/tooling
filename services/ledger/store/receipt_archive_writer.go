/*
FILE PATH: store/receipt_archive_writer.go

ReceiptArchiveWriter — best-effort writer of the per-checkpoint dense
receipt-commitment archive (1.2a step 3), the source ArchiveReceiptRanger
reconstructs PG-free receipt proofs from.

WHY: at publish the CheckpointLoop has just computed the checkpoint's ReceiptRoot
over the delta [fromSeq, toSeq] (entry_index, PG). This writer re-gathers the SAME
dense commitment set — via the SAME EntryIndexReceiptRanger.commitsInRange the
cosigned ReceiptRoot was computed from — and writes it to receipts/<coveringSize>,
so the archive is byte-consistent with the cosigned root BY CONSTRUCTION. Best-
effort: builder.CheckpointLoop calls it after a successful publish and never stalls
a checkpoint on a write error; the backfill job (1.x) regenerates any gaps. Object-
store path only (PutObject); the per-log namespace is applied by the *bytestore.S3
adapter, exactly as the checkpoint archive (1.1a).
*/
package store

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/core/smt"
)

// receiptCommitGatherer gathers the dense commitment set over [fromSeq, toSeq] — the
// EntryIndexReceiptRanger method the cosigned ReceiptRoot is computed from. Unexported
// so only store-package rangers satisfy it: the archive is consistent with the
// cosigned root BY sharing this exact source.
type receiptCommitGatherer interface {
	commitsInRange(ctx context.Context, fromSeq, toSeq uint64) ([]smt.ReceiptCommitment, error)
}

// ReceiptArchiveWriter gathers a checkpoint's dense commitment set via the same PG
// ranger the cosigned ReceiptRoot was computed with, and writes it to the object
// store. Satisfies builder.ReceiptCommitArchiver.
type ReceiptArchiveWriter struct {
	ranger receiptCommitGatherer // commit source (PG) — same as the cosigned root
	obj    objectPutGetter       // object-store sink (PutObject)
}

// NewReceiptArchiveWriter wires the writer to the PG ranger (commit source) and the
// object store (sink). A nil component makes ArchiveReceiptCommits a no-op, so the
// composition root can wire it unconditionally.
func NewReceiptArchiveWriter(ranger *EntryIndexReceiptRanger, obj objectPutGetter) *ReceiptArchiveWriter {
	w := &ReceiptArchiveWriter{obj: obj}
	if ranger != nil { // keep w.ranger a true nil interface for the no-op guard
		w.ranger = ranger
	}
	return w
}

// ArchiveReceiptCommits gathers [fromSeq, toSeq] and writes the encoded commitment
// set to receipts/<coveringSize>. The returned error is for the caller to LOG; the
// checkpoint loop treats archiving as best-effort and never stalls publish on it.
func (w *ReceiptArchiveWriter) ArchiveReceiptCommits(ctx context.Context, coveringSize, fromSeq, toSeq uint64) error {
	if w == nil || w.ranger == nil || w.obj == nil {
		return nil
	}
	commits, err := w.ranger.commitsInRange(ctx, fromSeq, toSeq)
	if err != nil {
		return fmt.Errorf("store/receipt-archive-writer: gather [%d,%d]: %w", fromSeq, toSeq, err)
	}
	if err := w.obj.PutObject(ctx, receiptArchiveKey(coveringSize), EncodeReceiptCommits(commits)); err != nil {
		return fmt.Errorf("store/receipt-archive-writer: put receipts/%d: %w", coveringSize, err)
	}
	return nil
}
