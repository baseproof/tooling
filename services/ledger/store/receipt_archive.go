/*
FILE PATH: store/receipt_archive.go

Per-checkpoint dense receipt-commitment list, serialized for the cold-storage
archive so receipt proofs reconstruct PG-free.

WHY (1.2a): EntryIndexReceiptRanger computes a checkpoint's ReceiptRoot +
inclusion proof from entry_index.web3_receipts (PG). For a PG-off read front — or
a cold seq whose entry_index rows are GC'd — that source is gone. Archiving the
exact dense commitment set the cosigned ReceiptRoot is computed over lets the read
front reconstruct the SAME root + proofs from object storage. Additive and
best-effort: the archive never gates a publish (cf. 1.1a), and its absence
degrades only the receipt endpoint, never the main read path.

The reconstruction is byte-identical to the PG path: both feed smt.ReceiptRoot /
smt.GenerateReceiptInclusionProof the same []smt.ReceiptCommitment, and
smt.ReceiptRoot sorts by (LogDID, Sequence) internally, so serialization order is
not load-bearing.
*/
package store

import (
	"encoding/binary"
	"fmt"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// receiptArchiveVersion prefixes the encoded blob so the format can evolve
// without silently misreading an older archive.
const receiptArchiveVersion byte = 1

// receiptCommitWidth is the fixed per-commitment record width: 8-byte big-endian
// sequence + 32-byte ReceiptHash. LogDID is constant per log (supplied at decode),
// so it is not repeated per record.
const receiptCommitWidth = 8 + 32

// EncodeReceiptCommits serializes the dense receipt-commitment list a checkpoint's
// ReceiptRoot is computed over: a 1-byte version, then one fixed-width record per
// commitment. Order is preserved but NOT load-bearing (smt.ReceiptRoot sorts
// internally), so re-encoding a re-ordered set reconstructs the same root.
func EncodeReceiptCommits(commits []smt.ReceiptCommitment) []byte {
	out := make([]byte, 1, 1+len(commits)*receiptCommitWidth)
	out[0] = receiptArchiveVersion
	var rec [receiptCommitWidth]byte
	for _, c := range commits {
		binary.BigEndian.PutUint64(rec[:8], c.Position.Sequence)
		copy(rec[8:], c.ReceiptHash[:])
		out = append(out, rec[:]...)
	}
	return out
}

// DecodeReceiptCommits validates the version + framing and reattaches logDID to
// each Position. A blob whose body is not a whole number of records is REJECTED
// (corruption), never silently truncated — so a damaged archive surfaces as an
// error the caller maps to a transient fault, not a fabricated (and wrong)
// ReceiptRoot.
func DecodeReceiptCommits(logDID string, raw []byte) ([]smt.ReceiptCommitment, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("store/receipt-archive: empty commitment blob")
	}
	if raw[0] != receiptArchiveVersion {
		return nil, fmt.Errorf("store/receipt-archive: unsupported version %d (want %d)", raw[0], receiptArchiveVersion)
	}
	body := raw[1:]
	if len(body)%receiptCommitWidth != 0 {
		return nil, fmt.Errorf("store/receipt-archive: corrupt commitment blob: %d body bytes not a multiple of %d", len(body), receiptCommitWidth)
	}
	n := len(body) / receiptCommitWidth
	commits := make([]smt.ReceiptCommitment, 0, n)
	for i := 0; i < n; i++ {
		off := i * receiptCommitWidth
		seq := binary.BigEndian.Uint64(body[off : off+8])
		var rh [32]byte
		copy(rh[:], body[off+8:off+receiptCommitWidth])
		commits = append(commits, smt.ReceiptCommitment{
			Position:    types.LogPosition{LogDID: logDID, Sequence: seq},
			ReceiptHash: rh,
		})
	}
	return commits, nil
}
