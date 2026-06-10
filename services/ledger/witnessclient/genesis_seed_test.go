/*
FILE PATH: witnessclient/genesis_seed_test.go

SeedGenesisBaseline contract tests — the three reconcile cases from
genesis_seed.go (empty table → active genesis row; rotated-without-
genesis table → retired genesis backfill; already-recorded → no-op),
plus idempotence. DB-backed; skips without BASEPROOF_TEST_DSN
(requireWitnessDSN, shared with rotation_history_test.go).
*/
package witnessclient_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"

	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// TestSeedGenesisBaseline_EmptyTableInsertsActive pins the fresh-network
// case (the mo5 404): an empty witness_sets table gains the genesis row —
// ACTIVE (retired_seq NULL), effective_seq 0, set_hash = the keyset's
// content-addressable identity — and /current + /at(any seq) resolve to it.
func TestSeedGenesisBaseline_EmptyTableInsertsActive(t *testing.T) {
	ctx := context.Background()
	pool := requireWitnessDSN(t)

	keys, _ := freshHistoryKeys(t, 3)
	set, err := cosign.NewWitnessKeySet(keys, historyNetID(), 2, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	recorded, err := witnessclient.SeedGenesisBaseline(ctx, pool, set, keys, 0x01)
	if err != nil {
		t.Fatalf("SeedGenesisBaseline: %v", err)
	}
	if !recorded {
		t.Fatal("expected the genesis baseline to be recorded on an empty table")
	}

	wantHash := set.SetHash()
	cur, err := witnessclient.LoadCurrentSetRow(ctx, pool)
	if err != nil {
		t.Fatalf("LoadCurrentSetRow after seed: %v", err)
	}
	if !bytes.Equal(cur.SetHash[:], wantHash[:]) {
		t.Fatalf("current set_hash = %x, want the genesis keyset identity %x", cur.SetHash, wantHash)
	}
	if cur.EffectiveSeq != 0 || cur.RetiredSeq != nil {
		t.Fatalf("genesis row classification: effective_seq=%d retired=%v, want 0/NULL", cur.EffectiveSeq, cur.RetiredSeq)
	}

	for _, seq := range []uint64{0, 1, 999} {
		row, aerr := witnessclient.LoadSetAtSeq(ctx, pool, seq)
		if aerr != nil {
			t.Fatalf("LoadSetAtSeq(%d): %v", seq, aerr)
		}
		if !bytes.Equal(row.SetHash[:], wantHash[:]) {
			t.Fatalf("LoadSetAtSeq(%d) = %x, want genesis %x", seq, row.SetHash, wantHash)
		}
	}

	// Idempotent: a second boot records nothing and changes nothing.
	again, err := witnessclient.SeedGenesisBaseline(ctx, pool, set, keys, 0x01)
	if err != nil {
		t.Fatalf("SeedGenesisBaseline (second call): %v", err)
	}
	if again {
		t.Fatal("second seed reported recorded=true; want no-op")
	}
}

// TestSeedGenesisBaseline_BackfillsGenesisEraHole pins the rotated-on-empty-
// table repair: a deployment whose first rotation landed BEFORE the baseline
// existed has an active rotation row at effective_seq>0 and nothing covering
// [0, that seq). The seed inserts genesis RETIRED at the earliest recorded
// effective_seq — closing the hole without touching the active row.
func TestSeedGenesisBaseline_BackfillsGenesisEraHole(t *testing.T) {
	ctx := context.Background()
	pool := requireWitnessDSN(t)

	// The (post-rotation) active row, as ProcessRotation would have written
	// it on an empty table: effective_seq=7, nothing retired.
	rotKeys, _ := freshHistoryKeys(t, 3)
	rotSet, err := cosign.NewWitnessKeySet(rotKeys, historyNetID(), 2, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet (rotation): %v", err)
	}
	rotHash := rotSet.SetHash()
	if _, err = pool.Exec(ctx, `
		INSERT INTO witness_sets
		    (set_hash, keys_json, scheme_tag, effective_seq, retired_seq, rotation_event_id)
		VALUES ($1, '[]', 1, 7, NULL, NULL)`, rotHash[:]); err != nil {
		t.Fatalf("insert rotation row: %v", err)
	}

	genKeys, _ := freshHistoryKeys(t, 3)
	genSet, err := cosign.NewWitnessKeySet(genKeys, historyNetID(), 2, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet (genesis): %v", err)
	}
	genHash := genSet.SetHash()

	recorded, err := witnessclient.SeedGenesisBaseline(ctx, pool, genSet, genKeys, 0x01)
	if err != nil {
		t.Fatalf("SeedGenesisBaseline: %v", err)
	}
	if !recorded {
		t.Fatal("expected the genesis-era hole to be backfilled")
	}

	// Genesis covers [0,7); the rotation row stays active and covers 7+.
	for _, seq := range []uint64{0, 3, 6} {
		row, aerr := witnessclient.LoadSetAtSeq(ctx, pool, seq)
		if aerr != nil {
			t.Fatalf("LoadSetAtSeq(%d): %v", seq, aerr)
		}
		if !bytes.Equal(row.SetHash[:], genHash[:]) {
			t.Fatalf("LoadSetAtSeq(%d) = %x, want genesis %x", seq, row.SetHash, genHash)
		}
		if row.RetiredSeq == nil || *row.RetiredSeq != 7 {
			t.Fatalf("genesis backfill retired_seq = %v, want 7", row.RetiredSeq)
		}
	}
	at7, err := witnessclient.LoadSetAtSeq(ctx, pool, 7)
	if err != nil {
		t.Fatalf("LoadSetAtSeq(7): %v", err)
	}
	if !bytes.Equal(at7.SetHash[:], rotHash[:]) {
		t.Fatalf("LoadSetAtSeq(7) = %x, want the rotation row %x", at7.SetHash, rotHash)
	}
	cur, err := witnessclient.LoadCurrentSetRow(ctx, pool)
	if err != nil {
		t.Fatalf("LoadCurrentSetRow: %v", err)
	}
	if !bytes.Equal(cur.SetHash[:], rotHash[:]) {
		t.Fatalf("current = %x, want the rotation row %x (backfill must not steal ACTIVE)", cur.SetHash, rotHash)
	}
}

// TestSeedGenesisBaseline_NoopWhenGenesisRecorded pins the third case: any
// row at effective_seq=0 (a prior boot's baseline, retired or active) makes
// the seed a no-op — the reconcile never duplicates or rewrites history.
func TestSeedGenesisBaseline_NoopWhenGenesisRecorded(t *testing.T) {
	ctx := context.Background()
	pool := requireWitnessDSN(t)

	keys, _ := freshHistoryKeys(t, 3)
	set, err := cosign.NewWitnessKeySet(keys, historyNetID(), 2, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	if recorded, serr := witnessclient.SeedGenesisBaseline(ctx, pool, set, keys, 0x01); serr != nil || !recorded {
		t.Fatalf("first seed: recorded=%v err=%v", recorded, serr)
	}

	// A different genesis derivation (e.g. operator changed quorum K in the
	// bundle) must NOT produce a second baseline row.
	otherSet, err := cosign.NewWitnessKeySet(keys, historyNetID(), 3, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet (K=3): %v", err)
	}
	recorded, err := witnessclient.SeedGenesisBaseline(ctx, pool, otherSet, keys, 0x01)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if recorded {
		t.Fatal("seed inserted a second genesis row; want no-op when effective_seq=0 exists")
	}
}
