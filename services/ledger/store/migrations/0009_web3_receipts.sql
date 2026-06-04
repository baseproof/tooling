-- Migration 0009 — web3_verification_receipts on entry_index
--
-- Adds the per-entry serialized Web3VerificationReceipt slice
-- captured at admission (baseproof v1.7.0+) so the builder can
-- rehydrate it into types.EntryWithMetadata.Web3Receipts and fold
-- the per-entry receipt-hash into the per-batch ReceiptRoot
-- (baseproof v2.0.0 cosign payload).
--
-- Wire format inside the bytea (matches wal/meta.go V2 trailer
-- payload):
--
--   [2 bytes uint16 receipt count BE]
--   [per-receipt:]
--     [4 bytes uint32 length BE]
--     [N bytes envelope.SerializeWeb3VerificationReceipt(receipt)]
--
-- NULL ⇒ no receipts captured for this entry (legacy single-sig
-- path, or pre-PR-N3 entries that landed before this column
-- existed). The builder treats NULL identically to an empty
-- slice — types.EntryReceiptHash(nil) returns the deterministic
-- empty-set hash per baseproof v1.7.0.
--
-- bytea is the right column shape (not jsonb): the receipt's
-- canonical wire encoding is fixed-deterministic per the SDK
-- (core/envelope/web3_receipt_serialize.go); jsonb would impose
-- a JSON round-trip that loses the byte-for-byte determinism
-- the SDK guarantees and that the V2 cosign payload binds.
ALTER TABLE entry_index
    ADD COLUMN IF NOT EXISTS web3_receipts bytea;

COMMENT ON COLUMN entry_index.web3_receipts IS
    'PR-N4: per-entry serialized Web3VerificationReceipts (baseproof v1.7.0). NULL ⇒ no receipts captured. Wire format: uint16 count BE || (uint32 len BE || envelope.SerializeWeb3VerificationReceipt)+';
