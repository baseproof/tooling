// FILE PATH: services/auditor/internal/store/witness_rotation_journal_test.go
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
//     gated) proves the DURABLE materialization: RecordRotation → the store's
//     WitnessSetAt accessor reconstructs the same historical set off Postgres.
package store

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/baseproof/witness/witnesstest"
)

// rotTestNetID is a fixed non-zero network id (NewWitnessKeySet rejects zero).
func rotTestNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// genWitnessSet mints an n-key, k-quorum ECDSA witness set via the SDK fixture
// kit (the kit's private keys sign rotations / cosign heads under the set).
func genWitnessSet(t *testing.T, n, k int, netID cosign.NetworkID) *witnesstest.Set {
	t.Helper()
	return witnesstest.NewSet(t, netID, n, k)
}

// buildRotation mints a valid rotation old → next through the production
// assembly path: the first sigCount OLD members authorize and every joiner
// countersigns (Step-6 consent), so witness.VerifyRotation accepts it under
// every current rule.
func buildRotation(t *testing.T, old, next *witnesstest.Set, sigCount int, netID cosign.NetworkID) types.WitnessRotation {
	t.Helper()
	return witnesstest.MintRotation(t, netID, old, next, sigCount)
}

// cosignHead produces a K-of-N cosigned tree head signed by the supplied set's
// private keys — a real witness-cosigned head for the verify step.
func cosignHead(
	t *testing.T, head types.TreeHead,
	keys []types.WitnessPublicKey, privs []*ecdsa.PrivateKey, sigCount int, netID cosign.NetworkID,
) types.CosignedTreeHead {
	t.Helper()
	payload := cosign.NewTreeHeadPayload(head)
	sigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sb, err := cosign.SignECDSA(payload, netID, cosign.HashAlgoSHA256, privs[i])
		if err != nil {
			t.Fatalf("SignECDSA head: %v", err)
		}
		sigs[i] = types.WitnessSignature{
			PubKeyID:  keys[i].ID,
			SchemeTag: signatures.SchemeECDSA,
			SigBytes:  sb,
		}
	}
	return types.CosignedTreeHead{TreeHead: head, Signatures: sigs}
}

// fullTreeHead returns a TreeHead with all commitment roots populated — cosign's
// dual-commitment binding rejects an all-zero RootHash/SMTRoot.
func fullTreeHead(size uint64) types.TreeHead {
	return types.TreeHead{
		RootHash:    [32]byte{0x01, 0xC0, 0x5C},
		SMTRoot:     [32]byte{0x02, 0x5A, 0x7B},
		ReceiptRoot: [32]byte{0x03, 0x4C, 0x7D},
		TreeSize:    size,
	}
}

// scn02Chain builds the S0→S1→S2 rotation chain shared by both tests:
// genesis S0, rotate to S1 at effective seq 100, to S2 at effective seq 200.
type scn02Chain struct {
	netID      cosign.NetworkID
	logDID     string
	s0, s1, s2 *cosign.WitnessKeySet
	k1         []types.WitnessPublicKey
	p1         []*ecdsa.PrivateKey
	records    []types.WitnessRotationRecord
}

func buildSCN02Chain(t *testing.T, logDID string) scn02Chain {
	t.Helper()
	const n, k = 5, 3
	netID := rotTestNetID()
	s0 := genWitnessSet(t, n, k, netID)
	s1 := genWitnessSet(t, n, k, netID)
	s2 := genWitnessSet(t, n, k, netID)

	r1 := buildRotation(t, s0, s1, k, netID) // S0 authorizes S1
	r2 := buildRotation(t, s1, s2, k, netID) // S1 authorizes S2

	records := []types.WitnessRotationRecord{
		{Rotation: r1, EffectivePos: types.LogPosition{LogDID: logDID, Sequence: 100}},
		{Rotation: r2, EffectivePos: types.LogPosition{LogDID: logDID, Sequence: 200}},
	}
	return scn02Chain{
		netID: netID, logDID: logDID,
		s0: s0.KeySet, s1: s1.KeySet, s2: s2.KeySet,
		k1: s1.Keys, p1: s1.Privs,
		records: records,
	}
}

func TestWitnessSetAt_ReconstructsHistoricalSet_ZTSCN02(t *testing.T) {
	c := buildSCN02Chain(t, "did:web:ledger.zt-scn-02.test")

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
	head := fullTreeHead(150)
	s1Cosigned := cosignHead(t, head, c.k1, c.p1, 3, c.netID)

	reconstructedS1 := at(150)
	if vc := cosign.VerifyTreeHeadCosignatures(s1Cosigned, reconstructedS1); vc < 3 {
		t.Fatalf("S1-cosigned head failed against the reconstructed historical set S1: validCount=%d, want >=3", vc)
	}
	modernS2 := at(250)
	if vc := cosign.VerifyTreeHeadCosignatures(s1Cosigned, modernS2); vc >= 3 {
		t.Fatalf("ZT-SCN-02 VIOLATED: S1-cosigned head verified against the MODERN set S2 (validCount=%d)", vc)
	}
}

// TestPostgresWitnessRotationJournal_RoundTrip_ZTSCN02 proves the DURABLE
// materialization: rotations journaled to Postgres, then reconstructed off the
// store via its WitnessSetAt accessor — same verdict as the in-memory chain.
// Gated on AUDITOR_TEST_PG_DSN (skips otherwise).
func TestPostgresWitnessRotationJournal_RoundTrip_ZTSCN02(t *testing.T) {
	dsn := os.Getenv("AUDITOR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUDITOR_TEST_PG_DSN unset — skipping live Postgres integration")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

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
	logDID := fmt.Sprintf("did:web:ledger.zt-scn-02.test/%d", time.Now().UnixNano())
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
	head := fullTreeHead(150)
	s1Cosigned := cosignHead(t, head, c.k1, c.p1, 3, c.netID)
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
