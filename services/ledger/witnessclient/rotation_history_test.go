/*
FILE PATH: witnessclient/rotation_history_test.go

Tests for the witness_sets history extension shipped in Part II.2:
  - migration 0014_witness_history_extension.sql adds
    (effective_seq, retired_seq, rotation_event_id) columns + the
    witness_sets_active partial unique index +
    witness_sets_set_hash unique index.
  - ProcessRotation populates the new columns and atomically
    retires the prior active row.
  - LoadCurrentSetRow / LoadSetByHash / LoadSetAtSeq are the
    structured loaders backing the upcoming
    /v1/network/witnesses/* HTTP endpoints (Part II.1).

# WHY THESE TESTS NEED A REAL POSTGRES

The partial unique index witness_sets_active ON (retired_seq)
WHERE retired_seq IS NULL is the load-bearing invariant: exactly
one row has retired_seq IS NULL at any moment. A regression that
inserts a new active row WITHOUT retiring the prior one would
slip through any in-memory mock but would be rejected by
Postgres with a unique-constraint violation. To exercise this we
need the real index.

Tests skip when BASEPROOF_TEST_DSN is unset, matching the existing
head_sync_test.go pattern.
*/
package witnessclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// requireWitnessDSN returns an isolated DB schema with all migrations
// applied (including 0014). Skips the test if BASEPROOF_TEST_DSN is
// unset — matches witnessclient/head_sync_test.go:requireDSN.
func requireWitnessDSN(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("BASEPROOF_TEST_DSN") == "" {
		t.Skip("BASEPROOF_TEST_DSN unset — skipping DB-backed witness-history test")
	}
	pool := store.IsolatedDB(t)
	// IsolatedDB applies migrations into a fresh per-test schema, so
	// every test sees an empty witness_sets table.
	return pool
}

func historyNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(0xC0 | (i & 0x07))
	}
	return n
}

// withHandler wires a RotationHandler over the supplied pool with a fresh
// K-of-N witness set (the predecessor) bound to historyNetID, returning the
// handler and that set so a test can mint a rotation FROM it via witnesstest.
func withHandler(t *testing.T, pool *pgxpool.Pool, K, N int) (*witnessclient.RotationHandler, *witnesstest.Set) {
	t.Helper()
	old := witnesstest.NewSet(t, historyNetID(), N, K)
	mgr := quorum.NewManager(old.KeySet)
	return witnessclient.NewRotationHandler(
		pool, mgr, signatures.SchemeECDSA, "https://ledger.test/", nil,
	), old
}

// mintHistoryRotation mints a complete rotation from old to a fresh
// newN-member, K-of-N next set, returning the rotation and the next set (for
// set_hash / key-count assertions). It routes through witnesstest, so the
// rotation satisfies every current verifier rule — predecessor quorum, Step-6
// per-joiner consent, and the 2K>N quorum-intersection invariant — by
// construction. The pre-rc4 hand-rolled builder placed a 0xEE/0xAA placeholder
// where the joiner consent now must be, which the rc4 verifier rejects; it is
// gone.
func mintHistoryRotation(t *testing.T, old *witnesstest.Set, newN, K int) (types.WitnessRotation, []types.WitnessPublicKey) {
	t.Helper()
	next := witnesstest.NewSet(t, historyNetID(), newN, K)
	return witnesstest.MintRotation(t, historyNetID(), old, next, K), next.Keys
}

// ─────────────────────────────────────────────────────────────────────
// ProcessRotation — new persistence path
// ─────────────────────────────────────────────────────────────────────

// TestProcessRotation_PopulatesV1_3Columns pins the new INSERT contract:
// every row produced by ProcessRotation carries the v1.3 set_hash
// semantic (content-addressable identity, not the old "rotation
// anchor" semantic), and effective_seq + retired_seq classify it as
// the live row.
func TestProcessRotation_PopulatesV1_3Columns(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	rh, old := withHandler(t, pool, 2, 3)
	rot, newKeys := mintHistoryRotation(t, old, 3, 2)

	// v1.39: effective_seq is the on-log appender's returned position, not
	// MAX(tree_size). Wire an appender at position 0 so this row's
	// effective_seq is the 0 asserted below.
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 0})

	out, err := rh.ProcessRotation(ctx, rot)
	if err != nil {
		t.Fatalf("ProcessRotation: %v", err)
	}
	if len(out) != len(newKeys) {
		t.Errorf("returned key count = %d, want %d", len(out), len(newKeys))
	}

	row, err := witnessclient.LoadCurrentSetRow(ctx, pool)
	if err != nil {
		t.Fatalf("LoadCurrentSetRow: %v", err)
	}
	// set_hash MUST be cosign.WitnessKeySet.SetHash(newSet), NOT
	// the old "rotation authorization anchor" interpretation.
	wantSet, err := cosign.NewWitnessKeySet(
		newKeys, historyNetID(), 2, nil,
	)
	if err != nil {
		t.Fatalf("NewWitnessKeySet[want]: %v", err)
	}
	wantHash := wantSet.SetHash()
	if row.SetHash != wantHash {
		t.Errorf("set_hash mismatch:\n  got  %x\n  want %x", row.SetHash, wantHash)
	}
	if row.RetiredSeq != nil {
		t.Errorf("RetiredSeq = %v on freshly-inserted row; want nil", *row.RetiredSeq)
	}
	// v1.39: effective_seq is the position the on-log appender returned
	// (its intrinsic leaf sequence), NOT the pre-v1.39 MAX(tree_size). The
	// fake appender above committed at position 0, so effective_seq is 0.
	if row.EffectiveSeq != 0 {
		t.Errorf("EffectiveSeq = %d; want 0 (the fake appender's returned position)", row.EffectiveSeq)
	}
	if row.SchemeTag != signatures.SchemeECDSA {
		t.Errorf("SchemeTag = 0x%02x, want SchemeECDSA (0x%02x)",
			row.SchemeTag, signatures.SchemeECDSA)
	}
	// keys_json round-trip MUST decode to the same key set.
	var decoded []types.WitnessPublicKey
	if err := json.Unmarshal(row.KeysJSON, &decoded); err != nil {
		t.Fatalf("unmarshal keys_json: %v", err)
	}
	if len(decoded) != len(newKeys) {
		t.Errorf("decoded len = %d, want %d", len(decoded), len(newKeys))
	}
}

// TestProcessRotation_RetiresPriorActive pins the atomic
// retire-and-replace flow: after a rotation, the prior row's
// retired_seq is set and a NEW row carries retired_seq IS NULL.
// The witness_sets_active partial UNIQUE index enforces "exactly
// one active row" — without atomic retire-first, the INSERT would
// fail with a unique-constraint violation.
func TestProcessRotation_RetiresPriorActive(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	// Pre-seed the table with one active row, simulating a prior
	// rotation having been persisted.
	if _, err := pool.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag, effective_seq, retired_seq)
		VALUES ($1, '[]'::jsonb::text::bytea, 1, 0, NULL)
	`, make([]byte, 32)); err != nil {
		t.Fatalf("seed prior row: %v", err)
	}

	rh, old := withHandler(t, pool, 2, 3)
	rot, _ := mintHistoryRotation(t, old, 3, 2)

	// v1.39: the new row's effective_seq AND the prior row's retired_seq are
	// both stamped with the on-log appender's returned position. Commit at
	// position 5 so the prior row retires at seq 5 (a concrete, non-NULL
	// value, as the assertion below requires).
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 5})

	if _, err := rh.ProcessRotation(ctx, rot); err != nil {
		t.Fatalf("ProcessRotation: %v", err)
	}

	// Count active rows — MUST be exactly 1.
	var active int
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM witness_sets WHERE retired_seq IS NULL",
	).Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if active != 1 {
		t.Errorf("active row count = %d; partial-unique invariant broken (want exactly 1)", active)
	}

	// Count total rows — MUST be exactly 2 (prior + new).
	var total int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM witness_sets").Scan(&total); err != nil {
		t.Fatalf("count total: %v", err)
	}
	if total != 2 {
		t.Errorf("total rows = %d; want 2 (prior retired + new active)", total)
	}

	// The prior row's retired_seq MUST now be populated with the appender's
	// returned position (5, set above) — the column MUST NOT be NULL.
	var priorRetired *int64
	if err := pool.QueryRow(ctx,
		"SELECT retired_seq FROM witness_sets WHERE set_hash = $1",
		make([]byte, 32),
	).Scan(&priorRetired); err != nil {
		t.Fatalf("query prior retired_seq: %v", err)
	}
	if priorRetired == nil {
		t.Error("prior row's retired_seq is still NULL; retire step did not run")
	} else if *priorRetired != 5 {
		// The retire step stamps the prior row with the NEW rotation's
		// effective position — the appender returned 5 above.
		t.Errorf("prior row retired_seq = %d; want 5 (the appender's returned position)", *priorRetired)
	}
}

// TestProcessRotation_FailsClosedOnConstraintViolation: a pre-existing
// row with the SAME set_hash as the NEW set would cause a unique-
// index violation. The handler MUST surface that error (not swallow
// it) so the operator can diagnose duplicate-rotation accidents.
func TestProcessRotation_FailsClosedOnDuplicateSetHash(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	// Construct the new set, compute its expected hash, pre-insert a
	// row with that exact set_hash — already-retired so the partial
	// active index doesn't refuse it for unrelated reasons. The SAME next
	// set must back both the predicted hash and the minted rotation.
	rh, old := withHandler(t, pool, 2, 3)
	next := witnesstest.NewSet(t, historyNetID(), 3, 2)
	collidingHash := next.KeySet.SetHash()
	retired := int64(99)
	if _, err := pool.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag, effective_seq, retired_seq)
		VALUES ($1, '\x'::bytea, 1, 0, $2)
	`, collidingHash[:], retired); err != nil {
		t.Fatalf("seed colliding row: %v", err)
	}

	rot := witnesstest.MintRotation(t, historyNetID(), old, next, 2)

	// The appender must SUCCEED so the flow reaches the persist step (Step 3),
	// where the duplicate set_hash trips the witness_sets_set_hash unique
	// index. The position (1) is irrelevant to this test. A nil appender
	// would short-circuit earlier ("appender not wired") and mask the
	// constraint we're pinning.
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 1})

	_, err := rh.ProcessRotation(ctx, rot)
	if err == nil {
		t.Fatal("ProcessRotation accepted a rotation whose new-set hash collides with an existing row; unique constraint not enforced")
	}
}

// ─────────────────────────────────────────────────────────────────────
// LoadCurrentSetRow / LoadSetByHash / LoadSetAtSeq
// ─────────────────────────────────────────────────────────────────────

// TestLoadCurrentSetRow_EmptyTableReturnsNoRows pins the no-rotations
// case — boot path falls back to genesis config (verified separately
// in cmd/ledger/boot/wire/gossip.go).
func TestLoadCurrentSetRow_EmptyTableReturnsNoRows(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	_, err := witnessclient.LoadCurrentSetRow(ctx, pool)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("LoadCurrentSetRow on empty table: got err=%v; want wraps pgx.ErrNoRows", err)
	}
}

// TestLoadSetByHash_RoundTrip after a rotation, the loader returns the
// row by its content-addressable set_hash.
func TestLoadSetByHash_RoundTrip(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	rh, old := withHandler(t, pool, 2, 3)
	rot, newKeys := mintHistoryRotation(t, old, 3, 2)
	// Wire the on-log appender (v1.39 requires it); this test asserts only
	// set_hash + active status, so the appender's position is immaterial.
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 0})
	if _, err := rh.ProcessRotation(ctx, rot); err != nil {
		t.Fatalf("ProcessRotation: %v", err)
	}

	// Compute the expected set_hash.
	wantSet, err := cosign.NewWitnessKeySet(newKeys, historyNetID(), 2, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	wantHash := wantSet.SetHash()

	row, err := witnessclient.LoadSetByHash(ctx, pool, wantHash)
	if err != nil {
		t.Fatalf("LoadSetByHash: %v", err)
	}
	if row.SetHash != wantHash {
		t.Errorf("loaded set_hash != requested: got %x, want %x", row.SetHash, wantHash)
	}
	if row.RetiredSeq != nil {
		t.Errorf("freshly-rotated row should still be active; RetiredSeq=%v", *row.RetiredSeq)
	}
}

// TestLoadSetByHash_MissReturnsNoRows pins the lookup-miss case.
func TestLoadSetByHash_MissReturnsNoRows(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	var bogus [32]byte
	for i := range bogus {
		bogus[i] = 0xAB
	}
	_, err := witnessclient.LoadSetByHash(ctx, pool, bogus)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("LoadSetByHash[miss]: got err=%v; want wraps pgx.ErrNoRows", err)
	}
}

// TestLoadSetAtSeq_BeforeAfterRotation pins the historical-lookup
// semantic: at seq=50 the prior (retired_seq=100) set is returned;
// at seq=150 the new (retired_seq IS NULL) set is returned.
func TestLoadSetAtSeq_BeforeAfterRotation(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	// Seed a manually-staged history: two rows, the first retired at
	// seq 100, the second active from seq 100 onward.
	var oldHash, newHash [32]byte
	for i := range oldHash {
		oldHash[i] = 0x01
		newHash[i] = 0x02
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag, effective_seq, retired_seq)
		VALUES
		    ($1, $2, 1,   0, 100),
		    ($3, $2, 1, 100, NULL)
	`, oldHash[:], []byte(`[]`), newHash[:]); err != nil {
		t.Fatalf("seed two-row history: %v", err)
	}

	// At seq=50 → OLD row.
	row, err := witnessclient.LoadSetAtSeq(ctx, pool, 50)
	if err != nil {
		t.Fatalf("LoadSetAtSeq[50]: %v", err)
	}
	if row.SetHash != oldHash {
		t.Errorf("at seq=50 got set_hash=%x, want OLD=%x", row.SetHash, oldHash)
	}

	// At seq=99 → still OLD (boundary just before retirement).
	row, err = witnessclient.LoadSetAtSeq(ctx, pool, 99)
	if err != nil {
		t.Fatalf("LoadSetAtSeq[99]: %v", err)
	}
	if row.SetHash != oldHash {
		t.Errorf("at seq=99 got set_hash=%x, want OLD=%x (just before retirement)",
			row.SetHash, oldHash)
	}

	// At seq=100 → NEW (effective_seq=100 is inclusive).
	row, err = witnessclient.LoadSetAtSeq(ctx, pool, 100)
	if err != nil {
		t.Fatalf("LoadSetAtSeq[100]: %v", err)
	}
	if row.SetHash != newHash {
		t.Errorf("at seq=100 got set_hash=%x, want NEW=%x (effective_seq inclusive)",
			row.SetHash, newHash)
	}

	// At seq=1000 → NEW (still active).
	row, err = witnessclient.LoadSetAtSeq(ctx, pool, 1000)
	if err != nil {
		t.Fatalf("LoadSetAtSeq[1000]: %v", err)
	}
	if row.SetHash != newHash {
		t.Errorf("at seq=1000 got set_hash=%x, want NEW=%x", row.SetHash, newHash)
	}
}

// TestLoadSetAtSeq_PredatingFirstRowReturnsNoRows pins the contract
// for the "seq < any effective_seq" case. The HTTP handler maps this
// to a 404 (the network had no committed witness set at that time —
// caller should fall back to genesis config from BootstrapDocument).
func TestLoadSetAtSeq_PredatingFirstRowReturnsNoRows(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	var h [32]byte
	for i := range h {
		h[i] = 0x42
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag, effective_seq, retired_seq)
		VALUES ($1, '[]'::bytea, 1, 500, NULL)
	`, h[:]); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := witnessclient.LoadSetAtSeq(ctx, pool, 100)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("LoadSetAtSeq[100]: got err=%v; want wraps pgx.ErrNoRows", err)
	}
}

// TestPartialUniqueIndex_RejectsSecondActive is the DB-level pin for
// the partial unique index witness_sets_active. Any future code path
// that tries to insert a second active row MUST be rejected — even
// if the new row has a different set_hash. This catches regressions
// where ProcessRotation drops the retire-prior step.
func TestPartialUniqueIndex_RejectsSecondActive(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	var h1, h2 [32]byte
	for i := range h1 {
		h1[i] = 0x11
		h2[i] = 0x22
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag, effective_seq, retired_seq)
		VALUES ($1, '[]'::bytea, 1, 0, NULL)
	`, h1[:]); err != nil {
		t.Fatalf("seed first active row: %v", err)
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO witness_sets (set_hash, keys_json, scheme_tag, effective_seq, retired_seq)
		VALUES ($1, '[]'::bytea, 1, 5, NULL)
	`, h2[:])
	if err == nil {
		t.Fatal("second active-row INSERT accepted; witness_sets_active partial unique index NOT enforced")
	}
}

// TestEffectiveSeqFromAppenderPosition pins the v1.39 contract: a rotation's
// effective_seq is the INTRINSIC position the on-log appender returns (the
// leaf sequence it assigned + proved), NOT the pre-v1.39 MAX(tree_size)
// derived from the tree_heads table.
//
// The test makes the distinction load-bearing: it seeds tree_heads at
// tree_size 42 BUT commits the rotation through an appender at position
// 1000. effective_seq MUST be 1000 (the appender's position), never 42 (the
// stale MAX(tree_size) source). A regression that resurrects the
// tree_heads-derived path would stamp 42 and fail here.
func TestEffectiveSeqFromAppenderPosition(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	// Seed a tree_heads row at tree_size 42. Under v1.39 this is IRRELEVANT
	// to effective_seq — present only to prove the handler no longer reads
	// it (the assertion below wants 1000, the appender's position, not 42).
	var rootHash, smtRoot, receiptRoot [32]byte
	for i := range rootHash {
		rootHash[i] = 0xAA
		smtRoot[i] = 0xBB
		receiptRoot[i] = 0xCC
	}
	// hash_algo is a SMALLINT algorithm code (migration 0001), written by the
	// production store as int16(hashAlgo) — see store.TreeHeadStore.InsertHead.
	// Seed it the same way (cosign.HashAlgoSHA256 = 0x01), not as a string.
	if _, err := pool.Exec(ctx, `
		INSERT INTO tree_heads (tree_size, root_hash, smt_root, receipt_root, hash_algo)
		VALUES (42, $1, $2, $3, $4)
	`, rootHash[:], smtRoot[:], receiptRoot[:], int16(cosign.HashAlgoSHA256)); err != nil {
		t.Fatalf("seed tree_heads: %v", err)
	}

	rh, old := withHandler(t, pool, 2, 3)
	rot, _ := mintHistoryRotation(t, old, 3, 2)

	// Commit at position 1000 — deliberately != the seeded tree_size (42).
	const appenderPos = 1000
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: appenderPos})

	if _, err := rh.ProcessRotation(ctx, rot); err != nil {
		t.Fatalf("ProcessRotation: %v", err)
	}
	row, err := witnessclient.LoadCurrentSetRow(ctx, pool)
	if err != nil {
		t.Fatalf("LoadCurrentSetRow: %v", err)
	}
	if row.EffectiveSeq != appenderPos {
		t.Errorf("EffectiveSeq = %d; want %d (the appender's returned position, "+
			"NOT MAX(tree_size)=42)", row.EffectiveSeq, appenderPos)
	}
}

// _ keeps time/store imported for fixture timestamps in future tests.
var (
	_ = time.Now
	_ = store.RunMigrations
)
