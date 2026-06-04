/*
FILE PATH: store/receipt_ranger.go

EntryIndexReceiptRanger — computes a checkpoint's ReceiptRoot over a committed
sequence range by reading ONLY the entry_index.web3_receipts column.

WHY (Badger-flow independence): the receipts a cosigned head commits are a
function of committed METADATA (entry_index), not of whether an entry's wire
bytes are still in the Badger-backed WAL or already shipped to the byte store.
The full EntryFetcher.Fetch also reads the wire bytes (store/entries.go) and
errors on a byte miss, so using it here would couple the lagging checkpoint loop
to the WAL state machine (Admitted → Sequenced → Shipped, with pruning): a
delta entry whose bytes were shipped and pruned could stall the horizon for a
ReceiptRoot it can compute from metadata alone. Reading web3_receipts straight
from entry_index keeps the checkpoint loop downstream of admission/sequencing
only, never of byte availability — and is a single range query instead of one
fetch per entry.

The per-entry derivation is identical to the builder's former per-batch Step 6c
(types.EntryReceiptHash → smt.ReceiptCommitment → smt.ReceiptRoot), so a
single-entry checkpoint yields the same root the single-entry batch would have.
*/
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// EntryIndexReceiptRanger satisfies builder.ReceiptRanger over entry_index.
type EntryIndexReceiptRanger struct {
	db     *pgxpool.Pool
	logDID string
}

// NewEntryIndexReceiptRanger wires the ranger to the entry_index table.
func NewEntryIndexReceiptRanger(db *pgxpool.Pool, logDID string) *EntryIndexReceiptRanger {
	return &EntryIndexReceiptRanger{db: db, logDID: logDID}
}

// ReceiptRoot computes the dense ReceiptRoot over committed seqs in
// [fromSeq, toSeq] (inclusive) — one commitment per entry_index row in range,
// including zero-receipt entries (types.EntryReceiptHash(nil) is the empty-set
// sentinel). Rows absent from entry_index (gaps: tombstones / ghost leaves) are
// skipped, exactly as the builder's per-batch computation skipped non-existent
// seqs. An empty or inverted range returns the zero hash (the smt.ReceiptRoot
// "no receipts" sentinel). Reads only metadata — never the WAL/byte store.
func (r *EntryIndexReceiptRanger) ReceiptRoot(ctx context.Context, fromSeq, toSeq uint64) ([32]byte, error) {
	if r == nil || r.db == nil || toSeq < fromSeq {
		return [32]byte{}, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT sequence_number, web3_receipts
		FROM entry_index
		WHERE sequence_number BETWEEN $1 AND $2
		ORDER BY sequence_number ASC`,
		int64(fromSeq), int64(toSeq),
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("store/receipt-ranger: query [%d,%d]: %w", fromSeq, toSeq, err)
	}
	defer rows.Close()

	var commits []smt.ReceiptCommitment
	for rows.Next() {
		var seq int64
		var receipts []byte
		if sErr := rows.Scan(&seq, &receipts); sErr != nil {
			return [32]byte{}, fmt.Errorf("store/receipt-ranger: scan: %w", sErr)
		}
		var web3 []types.Web3VerificationReceipt
		if len(receipts) > 0 {
			decoded, decErr := decodeEntryWeb3Receipts(receipts)
			if decErr != nil {
				return [32]byte{}, fmt.Errorf("store/receipt-ranger: decode web3_receipts seq=%d: %w", seq, decErr)
			}
			web3 = decoded
		}
		rh, rhErr := types.EntryReceiptHash(web3)
		if rhErr != nil {
			return [32]byte{}, fmt.Errorf("store/receipt-ranger: receipt hash seq=%d: %w", seq, rhErr)
		}
		commits = append(commits, smt.ReceiptCommitment{
			Position:    types.LogPosition{LogDID: r.logDID, Sequence: uint64(seq)},
			ReceiptHash: rh,
		})
	}
	if rErr := rows.Err(); rErr != nil {
		return [32]byte{}, fmt.Errorf("store/receipt-ranger: rows: %w", rErr)
	}
	return smt.ReceiptRoot(commits), nil
}
