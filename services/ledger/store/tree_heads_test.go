/*
FILE PATH: store/tree_heads_test.go

Regression guard for the v1.9.1 ReceiptRoot persistence (migration
0010). A cosigned head reconstructed from PG must carry the SAME
ReceiptRoot it was written with — otherwise cosign.Verify recomputes
a divergent 104-byte canonical message and PG-served STHs fail to
verify for any batch with real Web3VerificationReceipts.

DSN-gated like the other store integration tests (skips when
BASEPROOF_TEST_DSN is unset).
*/
package store

import (
	"context"
	"testing"
)

func TestTreeHeadStore_ReceiptRoot_RoundTrip(t *testing.T) {
	pool := requireDB(t)
	defer pool.Close()
	ctx := context.Background()
	// DELETE (not TRUNCATE) — tree_head_sigs has an FK to tree_heads.
	if _, err := pool.Exec(ctx, `DELETE FROM tree_head_sigs`); err != nil {
		t.Fatalf("clear tree_head_sigs: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tree_heads`); err != nil {
		t.Fatalf("clear tree_heads: %v", err)
	}

	s := NewTreeHeadStore(pool)

	const (
		size     = uint64(424242)
		hashAlgo = uint16(1)
	)
	rootHash := [32]byte{0x11, 0x22}
	smtRoot := [32]byte{0x33, 0x44}
	// Non-zero ReceiptRoot is the regression: a zero value would pass
	// even with the column dropped (zero == zero).
	receiptRoot := [32]byte{0x55, 0x66, 0x77}

	if err := s.InsertHead(ctx, size, rootHash, smtRoot, receiptRoot, hashAlgo); err != nil {
		t.Fatalf("InsertHead: %v", err)
	}
	// One sig so LatestCosigned(minSigs=1) returns the head.
	if err := s.InsertSig(ctx, size, hashAlgo, "witness:test", 1, []byte(`{"sig":"x"}`)); err != nil {
		t.Fatalf("InsertSig: %v", err)
	}

	reads := map[string]func() (*CosignedTreeHead, error){
		"GetBySize":      func() (*CosignedTreeHead, error) { return s.GetBySize(ctx, size) },
		"Latest":         func() (*CosignedTreeHead, error) { return s.Latest(ctx) },
		"LatestCosigned": func() (*CosignedTreeHead, error) { return s.LatestCosigned(ctx, 1) },
	}
	for name, read := range reads {
		got, err := read()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got == nil {
			t.Fatalf("%s: nil head", name)
		}
		if got.ReceiptRoot != receiptRoot {
			t.Errorf("%s: ReceiptRoot = %x, want %x — PG dropped receipt_root",
				name, got.ReceiptRoot, receiptRoot)
		}
		if got.SMTRoot != smtRoot {
			t.Errorf("%s: SMTRoot = %x, want %x", name, got.SMTRoot, smtRoot)
		}
		if got.RootHash != rootHash {
			t.Errorf("%s: RootHash = %x, want %x", name, got.RootHash, rootHash)
		}
	}
}
