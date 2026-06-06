/*
FILE PATH: store/receipt_archive_ranger.go

ArchiveReceiptRanger — a PG-free receipt prover that reconstructs a checkpoint's
ReceiptRoot + inclusion proofs from the per-checkpoint commitment archive
(receipt_archive.go) instead of entry_index.web3_receipts.

WHY (1.2a step 2): EntryIndexReceiptRanger reads entry_index (PG) — gone when PG is
off or the entry's metadata row has been GC'd. This ranger reads the archived dense
commitment set from object storage and runs the IDENTICAL smt math, so a receipt
proof served PG-free verifies against the same cosigned ReceiptRoot. Its method set
matches EntryIndexReceiptRanger (ReceiptRoot + ReceiptInclusionProof), so it is a
drop-in behind the receipt handler's ReceiptProver seam and a graceful fallback
(api/receipt_fallback.go) when PG is unavailable.
*/
package store

import (
	"context"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// ReceiptCommitReader reads the archived dense commitment blob for the checkpoint
// at coveringSize — the checkpoint covering receipt range [prevSize, coveringSize-1].
// os.ErrNotExist when that checkpoint's receipts were never archived.
type ReceiptCommitReader interface {
	ReadReceiptCommits(ctx context.Context, coveringSize uint64) ([]byte, error)
}

// ArchiveReceiptRanger reconstructs receipt roots/proofs from the per-checkpoint
// commitment archive. logDID is the log whose positions the commitments carry
// (DecodeReceiptCommits reattaches it).
type ArchiveReceiptRanger struct {
	reader ReceiptCommitReader
	logDID string
}

// NewArchiveReceiptRanger wires the ranger to a commitment-archive reader.
func NewArchiveReceiptRanger(reader ReceiptCommitReader, logDID string) *ArchiveReceiptRanger {
	return &ArchiveReceiptRanger{reader: reader, logDID: logDID}
}

// commitsFor reads + decodes the archived commitment set for the checkpoint whose
// receipt range ends at toSeq (coveringSize = toSeq+1, the handler's checkpoint
// size). The archived set IS the full dense [prevSize, toSeq] range, so fromSeq is
// implied by the archive and not needed to reconstruct the root/proof.
func (r *ArchiveReceiptRanger) commitsFor(ctx context.Context, toSeq uint64) ([]smt.ReceiptCommitment, error) {
	raw, err := r.reader.ReadReceiptCommits(ctx, toSeq+1)
	if err != nil {
		return nil, err
	}
	return DecodeReceiptCommits(r.logDID, raw)
}

// ReceiptRoot reconstructs the checkpoint ReceiptRoot over [fromSeq, toSeq] from the
// archive — byte-identical to EntryIndexReceiptRanger.ReceiptRoot for the same
// checkpoint (smt.ReceiptRoot over the same dense set).
func (r *ArchiveReceiptRanger) ReceiptRoot(ctx context.Context, fromSeq, toSeq uint64) ([32]byte, error) {
	commits, err := r.commitsFor(ctx, toSeq)
	if err != nil {
		return [32]byte{}, err
	}
	return smt.ReceiptRoot(commits), nil
}

// ReceiptInclusionProof builds the receipt-membership proof for targetSeq within the
// archived checkpoint range — the proof verifies against that checkpoint's cosigned
// ReceiptRoot (smt.VerifyReceiptInclusion). A target absent from the archived set
// yields smt.ErrReceiptLeafNotFound (the gap/tombstone case), exactly as the PG
// ranger does.
func (r *ArchiveReceiptRanger) ReceiptInclusionProof(ctx context.Context, fromSeq, toSeq, targetSeq uint64) (*smt.ReceiptInclusionProof, error) {
	commits, err := r.commitsFor(ctx, toSeq)
	if err != nil {
		return nil, err
	}
	return smt.GenerateReceiptInclusionProof(commits, types.LogPosition{LogDID: r.logDID, Sequence: targetSeq})
}
