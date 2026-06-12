// FILE PATH: libs/witnessrotation/journalpg/journal_test.go
//
// AT-1 tests — ZT-SCN-02 (Historical Bundle Verification, the Year-15
// scenario). A witness set rotates S0 → S1 → S2 over time. Evidence cosigned
// by S1 in "year 1.5" must verify against the RECONSTRUCTED S1, and MUST NOT
// silently verify against the modern set S2.
//
//   - TestWitnessSetAt_ReconstructsHistoricalSet_ZTSCN02 runs WITHOUT Postgres:
//     it builds real witness sets + real rotations (signed via the universal
//     cosign rotation payload) and a real S1-cosigned head, reconstructs the
//     historical set with witness.WitnessSetAt, and proves the verify-against-
//     historical-not-modern mandate.
//   - TestPostgresWitnessRotationJournal_RoundTrip_ZTSCN02 (AUDITOR_TEST_PG_DSN-
//     gated — the CI matrix's shared test-PG env) proves the DURABLE
//     materialization: RecordRotation → the store's WitnessSetAt accessor
//     reconstructs the same historical set off Postgres.
//   - TestJournalParity_MemoryMirrorsPostgres locks the cross-implementation
//     contract: the in-memory journal and the durable journal expose
//     byte-identical chains for the same scenario (one seam, two custodians).
package journalpg

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/libs/witnessrotation"
	"github.com/baseproof/tooling/libs/witnessrotation/internal/rottest"
)

// scn02Chain builds the S0→S1→S2 rotation chain shared by the tests:
// genesis S0, rotate to S1 at effective seq 100, to S2 at effective seq 200.
type scn02Chain struct {
	netID      cosign.NetworkID
	logDID     string
	s0, s1, s2 *cosign.WitnessKeySet
	records    []types.WitnessRotationRecord
	s1Kit      *witnesstest.Set
}

func buildSCN02Chain(t *testing.T, logDID string) scn02Chain {
	t.Helper()
	const n, k = 5, 3
	netID := rottest.NetID()
	s0 := witnesstest.NewSet(t, netID, n, k)
	s1 := witnesstest.NewSet(t, netID, n, k)
	s2 := witnesstest.NewSet(t, netID, n, k)

	r1 := witnesstest.MintRotation(t, netID, s0, s1, k) // S0 authorizes S1
	r2 := witnesstest.MintRotation(t, netID, s1, s2, k) // S1 authorizes S2

	records := []types.WitnessRotationRecord{
		{Rotation: r1, EffectivePos: types.LogPosition{LogDID: logDID, Sequence: 100}},
		{Rotation: r2, EffectivePos: types.LogPosition{LogDID: logDID, Sequence: 200}},
	}
	return scn02Chain{
		netID: netID, logDID: logDID,
		s0: s0.KeySet, s1: s1.KeySet, s2: s2.KeySet,
		s1Kit:   s1,
		records: records,
	}
}

func TestWitnessSetAt_ReconstructsHistoricalSet_ZTSCN02(t *testing.T) {
	c := buildSCN02Chain(t, "did:web:source-log.zt-scn-02.test")

	at := func(seq uint64) *cosign.WitnessKeySet {
		set, err := witness.WitnessSetAt(c.s0, c.records, types.LogPosition{LogDID: c.logDID, Sequence: seq})
		if err != nil {
			t.Fatalf("WitnessSetAt(seq=%d): %v", seq, err)
		}
		return set
	}

	// Reconstruction at three points in history (asOf is INCLUSIVE of a
	// rotation's EffectivePos).
	if at(50).SetHash() != c.s0.SetHash() {
		t.Error("asOf before the first rotation must be the genesis (year-1) set S0")
	}
	if at(100).SetHash() != c.s1.SetHash() {
		t.Error("asOf == R1.EffectivePos must already be S1 (inclusive boundary)")
	}
	if at(150).SetHash() != c.s1.SetHash() {
		t.Error("asOf between R1 and R2 must be S1")
	}
	if at(250).SetHash() != c.s2.SetHash() {
		t.Error("asOf after R2 must be the current set S2")
	}

	// ── ZT-SCN-02 CORE ────────────────────────────────────────────────
	// A tree head cosigned by S1 (the set authoritative at seq 150) must
	// verify against the RECONSTRUCTED S1 — and MUST NOT verify against the
	// modern set S2. "Never silently fail by evaluating historical data
	// against modern keys."
	head := rottest.FullTreeHead(150)
	s1Cosigned := rottest.CosignHead(t, head, c.s1Kit.Keys, c.s1Kit.Privs, 3, c.netID)

	reconstructedS1 := at(150)
	if vc := cosign.VerifyTreeHeadCosignatures(s1Cosigned, reconstructedS1); vc < 3 {
		t.Fatalf("S1-cosigned head failed against the reconstructed historical set S1: validCount=%d, want >=3", vc)
	}
	modernS2 := at(250)
	if vc := cosign.VerifyTreeHeadCosignatures(s1Cosigned, modernS2); vc >= 3 {
		t.Fatalf("ZT-SCN-02 VIOLATED: S1-cosigned head verified against the MODERN set S2 (validCount=%d)", vc)
	}
}

// openTestPG opens the CI matrix's shared test Postgres, skipping when unset.
func openTestPG(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("AUDITOR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUDITOR_TEST_PG_DSN unset — skipping live Postgres integration")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestPostgresWitnessRotationJournal_RoundTrip_ZTSCN02 proves the DURABLE
// materialization: rotations journaled to Postgres, then reconstructed off the
// store via its WitnessSetAt accessor — same verdict as the in-memory chain.
func TestPostgresWitnessRotationJournal_RoundTrip_ZTSCN02(t *testing.T) {
	db := openTestPG(t)
	ctx := context.Background()
	j, err := NewPostgresWitnessRotationJournal(db)
	if err != nil {
		t.Fatalf("NewPostgresWitnessRotationJournal: %v", err)
	}
	if err := j.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Unique per-run logDID: the journal is append-only (NEVER DELETE), so
	// isolate runs by identity rather than cleanup.
	logDID := fmt.Sprintf("did:web:source-log.zt-scn-02.test/%d", time.Now().UnixNano())
	c := buildSCN02Chain(t, logDID)

	for _, rec := range c.records {
		if err := j.RecordRotation(ctx, rec); err != nil {
			t.Fatalf("RecordRotation(seq=%d): %v", rec.EffectivePos.Sequence, err)
		}
	}
	// Idempotent re-delivery (gossip is at-least-once) is a harmless no-op.
	if err := j.RecordRotation(ctx, c.records[0]); err != nil {
		t.Fatalf("idempotent RecordRotation: %v", err)
	}

	// Reconstruct off the durable store.
	got, err := j.WitnessSetAt(ctx, c.s0, logDID, types.LogPosition{LogDID: logDID, Sequence: 150})
	if err != nil {
		t.Fatalf("store WitnessSetAt: %v", err)
	}
	if got.SetHash() != c.s1.SetHash() {
		t.Fatalf("store reconstructed the wrong set at seq 150: got %x, want S1 %x",
			got.SetHash(), c.s1.SetHash())
	}

	// The reconstructed historical set verifies an S1-cosigned head; the
	// modern set (seq 250) does not — ZT-SCN-02 through the durable path.
	head := rottest.FullTreeHead(150)
	s1Cosigned := rottest.CosignHead(t, head, c.s1Kit.Keys, c.s1Kit.Privs, 3, c.netID)
	if vc := cosign.VerifyTreeHeadCosignatures(s1Cosigned, got); vc < 3 {
		t.Fatalf("durably-reconstructed S1 failed to verify the S1-cosigned head: validCount=%d", vc)
	}
	modernS2, err := j.WitnessSetAt(ctx, c.s0, logDID, types.LogPosition{LogDID: logDID, Sequence: 250})
	if err != nil {
		t.Fatalf("store WitnessSetAt(250): %v", err)
	}
	if vc := cosign.VerifyTreeHeadCosignatures(s1Cosigned, modernS2); vc >= 3 {
		t.Fatalf("ZT-SCN-02 VIOLATED via durable path: S1 head verified against modern S2 (validCount=%d)", vc)
	}

	// ── REBUILDABLE CACHE (not bedrock) ──────────────────────────────────
	// The journal is a materialized projection of the log: dropping it is safe
	// because the chain is rebuilt by re-walking the log. Purge → reconstruction
	// collapses to genesis (no records) → re-record (the rebuild) → S1 is back.
	if err := j.PurgeFor(ctx, logDID); err != nil {
		t.Fatalf("PurgeFor: %v", err)
	}
	afterPurge, err := j.WitnessSetAt(ctx, c.s0, logDID, types.LogPosition{LogDID: logDID, Sequence: 150})
	if err != nil {
		t.Fatalf("WitnessSetAt after purge: %v", err)
	}
	if afterPurge.SetHash() != c.s0.SetHash() {
		t.Fatalf("after purge, reconstruction must collapse to genesis S0 (cache gone); got %x", afterPurge.SetHash())
	}
	for _, rec := range c.records { // rebuild by re-walking the log (idempotent)
		if err := j.RecordRotation(ctx, rec); err != nil {
			t.Fatalf("rebuild RecordRotation: %v", err)
		}
	}
	rebuilt, err := j.WitnessSetAt(ctx, c.s0, logDID, types.LogPosition{LogDID: logDID, Sequence: 150})
	if err != nil {
		t.Fatalf("WitnessSetAt after rebuild: %v", err)
	}
	if rebuilt.SetHash() != c.s1.SetHash() {
		t.Fatalf("after rebuild, reconstruction must be S1 again; got %x want %x", rebuilt.SetHash(), c.s1.SetHash())
	}
}

// TestJournalParity_MemoryMirrorsPostgres locks the one-seam-two-custodians
// contract: for the same recorded scenario (out-of-order delivery, idempotent
// re-delivery, null-pos refusal), the in-memory journal and the durable
// journal return BYTE-IDENTICAL chains and identical refusals — so a consumer
// wired against either resolves identically.
func TestJournalParity_MemoryMirrorsPostgres(t *testing.T) {
	db := openTestPG(t)
	ctx := context.Background()
	pg, err := NewPostgresWitnessRotationJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	mem := witnessrotation.NewMemoryRotationJournal()

	logDID := fmt.Sprintf("did:web:source-log.parity.test/%d", time.Now().UnixNano())
	c := buildSCN02Chain(t, logDID)

	type journal interface {
		RecordRotation(ctx context.Context, record types.WitnessRotationRecord) error
		RecordsFor(ctx context.Context, logDID string) ([]types.WitnessRotationRecord, error)
	}
	for name, j := range map[string]journal{"pg": pg, "memory": mem} {
		// Out of order + duplicate — both must converge to the same chain.
		if err := j.RecordRotation(ctx, c.records[1]); err != nil {
			t.Fatalf("%s: record r2: %v", name, err)
		}
		if err := j.RecordRotation(ctx, c.records[0]); err != nil {
			t.Fatalf("%s: record r1: %v", name, err)
		}
		if err := j.RecordRotation(ctx, c.records[1]); err != nil {
			t.Fatalf("%s: duplicate r2: %v", name, err)
		}
		// Null position refuses identically.
		bad := c.records[0]
		bad.EffectivePos = types.LogPosition{}
		if err := j.RecordRotation(ctx, bad); err == nil {
			t.Fatalf("%s: null EffectivePos must refuse", name)
		}
	}

	pgChain, err := pg.RecordsFor(ctx, logDID)
	if err != nil {
		t.Fatal(err)
	}
	memChain, err := mem.RecordsFor(ctx, logDID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pgChain) != 2 || len(memChain) != 2 {
		t.Fatalf("chain lengths: pg=%d mem=%d, want 2/2", len(pgChain), len(memChain))
	}
	for i := range pgChain {
		if pgChain[i].EffectivePos != memChain[i].EffectivePos {
			t.Fatalf("record %d positions diverge: pg=%+v mem=%+v", i, pgChain[i].EffectivePos, memChain[i].EffectivePos)
		}
		pgBytes, err := witness.EncodeWitnessRotationPayload(pgChain[i].Rotation)
		if err != nil {
			t.Fatal(err)
		}
		memBytes, err := witness.EncodeWitnessRotationPayload(memChain[i].Rotation)
		if err != nil {
			t.Fatal(err)
		}
		if string(pgBytes) != string(memBytes) {
			t.Fatalf("record %d canonical bytes diverge between implementations", i)
		}
	}

	// And the resolver reaches the same era verdicts off either journal.
	for name, src := range map[string]witnessrotation.RotationRecordSource{"pg": pg, "memory": mem} {
		r, err := witnessrotation.NewJournalWitnessSetResolver(src, []witnessrotation.LogTrustRoot{{LogDID: logDID, Genesis: c.s0}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.SetAt(ctx, logDID, types.LogPosition{LogDID: logDID, Sequence: 150})
		if err != nil || got.SetHash() != c.s1.SetHash() {
			t.Fatalf("%s-backed resolver at seq 150: %v", name, err)
		}
	}
}
