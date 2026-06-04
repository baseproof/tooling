-- FILE PATH: store/migrations/0010_tree_heads_receipt_root.sql
--
-- Adds the receipt_root column to tree_heads so the witness-cosigned
-- payload's full 104-byte commitment (RootHash || SMTRoot ||
-- ReceiptRoot || TreeSize) persists in full. Pairs with baseproof SDK
-- v1.9.1's single-payload collapse (cosign.NewTreeHeadPayload is now
-- 104-byte and binds all three roots) and v1.9.2's gossip wire fix.
--
-- # WHY THIS EXISTS
--
-- tree_heads already persists root_hash (0001) and smt_root (0007).
-- v1.9.1 made ReceiptRoot the THIRD root the witness signature binds.
-- A CosignedTreeHead reconstructed from this table
-- (store/tree_heads.go::Latest / LatestCosigned / GetBySize) without
-- receipt_root carries ReceiptRoot=0, so cosign.VerifyTreeHeadCosignatures
-- recomputes a DIVERGENT canonical message and the persisted
-- signatures fail to verify for any batch with a non-zero ReceiptRoot
-- (real Web3VerificationReceipts). The gossip wire carries it as of
-- v1.9.2; this migration closes the same gap in the ledger's own
-- persistence so PG-served STHs stay independently verifiable.
--
-- # DEFAULT FOR EXISTING ROWS
--
-- Pre-existing rows pre-date the receipt binding (and, in the
-- steady-state ECDSA-only adapter, carried a zero ReceiptRoot anyway).
-- We backfill with 32 zero bytes. Unlike RootHash/SMTRoot, a zero
-- ReceiptRoot is a VALID value, not a sentinel: cosign's payload
-- Validate exempts the zero ReceiptRoot (empty-batch case,
-- smt.ReceiptRoot(nil) == zero hash), so backfilled rows recompute
-- the correct canonical message for empty-receipt batches.

ALTER TABLE tree_heads
    ADD COLUMN receipt_root BYTEA NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::BYTEA;

-- Drop the default so future inserts must supply the value
-- explicitly (store/tree_heads.go::InsertHead takes an explicit
-- receiptRoot [32]byte arg). The column remains NOT NULL.
ALTER TABLE tree_heads
    ALTER COLUMN receipt_root DROP DEFAULT;
