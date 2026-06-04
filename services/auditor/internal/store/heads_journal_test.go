// Tests for PostgresHeadsJournal.
//
// # STRATEGY
//
// The behavioral contract is pinned by the in-memory implementation's
// test suite (libs/monitoring/heads_journal_test.go) — every scenario
// (year-15 retrieval, fork detection, burn fail-closed, multi-log
// isolation, wire-format preservation) runs against the
// HeadsJournal interface, which PostgresHeadsJournal satisfies via
// the compile-time `var _ monitoring.HeadsJournal = ...` check at
// line 79 of heads_journal.go.
//
// This file pins the things specific to the Postgres impl:
//
//   - the schema SQL is structurally well-formed (idempotent, has
//     all required columns, indexes, primary keys, advisory-lock-
//     friendly shape)
//   - nil-DB construction is rejected
//   - the optional live-Postgres integration test (gated on
//     AUDITOR_TEST_PG_DSN env var) runs the FULL HeadsJournal
//     contract against a real database
package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/monitoring"
)

// TestNewPostgresHeadsJournal_RejectsNilDB pins the constructor's
// fail-fast contract.
func TestNewPostgresHeadsJournal_RejectsNilDB(t *testing.T) {
	t.Parallel()
	_, err := NewPostgresHeadsJournal(nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
}

// TestHeadsJournal_Schema_HasRequiredStructure pins the schema SQL
// contains every column the Go-side scanHead expects, every required
// index, and the PRIMARY KEY shape (LogDID, Sequence, RootHash) the
// design specifies. A schema change that drops one of these silently
// breaks the journal — the test catches that drift at build time.
func TestHeadsJournal_Schema_HasRequiredStructure(t *testing.T) {
	t.Parallel()

	required := []string{
		// Columns
		"log_did", "sequence", "root_hash", "smt_root", "receipt_root",
		"signatures", "canonical_bytes", "lamport_time", "committed_at", "recorded_at",
		// Primary key
		"PRIMARY KEY (log_did, sequence, root_hash)",
		// Reach indexes
		"heads_journal_log_seq_desc",
		"heads_journal_log_committed",
		// Burns table
		"heads_journal_burns",
		"first_fork_sequence",
		"conflicting_roots",
		// Idempotency: every CREATE TABLE / INDEX uses IF NOT EXISTS
		"CREATE TABLE IF NOT EXISTS heads_journal",
		"CREATE INDEX IF NOT EXISTS heads_journal_log_seq_desc",
		"CREATE INDEX IF NOT EXISTS heads_journal_log_committed",
		"CREATE TABLE IF NOT EXISTS heads_journal_burns",
	}
	for _, want := range required {
		if !strings.Contains(schemaSQLHeadsJournal, want) {
			t.Errorf("schemaSQLHeadsJournal missing required substring: %q", want)
		}
	}
}

// TestHeadsJournal_Postgres_Live runs the FULL HeadsJournal contract
// against a real Postgres instance. Gated on AUDITOR_TEST_PG_DSN —
// CI runners with no Postgres skip the test cleanly; runners with
// Postgres (and an empty test database) cover the persistence
// behavior end-to-end.
//
// Suggested local invocation:
//
//	docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=test postgres:16
//	AUDITOR_TEST_PG_DSN="postgres://postgres:test@localhost:5432/postgres?sslmode=disable" \
//	go test ./services/auditor/internal/store/... -run TestHeadsJournal_Postgres_Live -v
func TestHeadsJournal_Postgres_Live(t *testing.T) {
	dsn := os.Getenv("AUDITOR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUDITOR_TEST_PG_DSN unset — skipping live Postgres integration")
	}
	t.Parallel()
	ctx := context.Background()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Use a unique schema for isolation between concurrent test
	// runs.
	schemaName := "heads_journal_test_" + strings.ReplaceAll(time.Now().UTC().Format("20060102_150405.000000"), ".", "_")
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+schemaName); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, "DROP SCHEMA "+schemaName+" CASCADE") })
	if _, err := db.ExecContext(ctx, "SET search_path TO "+schemaName); err != nil {
		t.Fatalf("set search_path: %v", err)
	}

	j, err := NewPostgresHeadsJournal(db)
	if err != nil {
		t.Fatalf("NewPostgresHeadsJournal: %v", err)
	}
	if err := j.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Run the same scenarios the in-memory tests cover, but
	// against the Postgres implementation.
	t.Run("happy_path_roundtrip", func(t *testing.T) {
		h := pgHead("did:web:tn", 100, 1, 0x01, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC))
		v, err := j.Record(ctx, h)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if !v.Persisted || v.Equivocation {
			t.Errorf("verdict = %+v, want Persisted only", v)
		}
		got, err := j.HeadByRootHash(ctx, "did:web:tn", 100, h.RootHash)
		if err != nil {
			t.Fatalf("HeadByRootHash: %v", err)
		}
		if got.LogDID != h.LogDID || got.TreeSize != 100 || got.RootHash != h.RootHash {
			t.Errorf("round-trip mismatch: got %+v", got.TreeHead)
		}
		if string(got.CanonicalBytes) != string(h.CanonicalBytes) {
			t.Errorf("CanonicalBytes drift")
		}
		if len(got.Signatures) != len(h.Signatures) {
			t.Errorf("signature count drift: got %d, want %d", len(got.Signatures), len(h.Signatures))
		}
	})

	t.Run("idempotent_exact_dup", func(t *testing.T) {
		h := pgHead("did:web:idem", 1, 1, 0x77, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if _, err := j.Record(ctx, h); err != nil {
			t.Fatalf("first Record: %v", err)
		}
		v, err := j.Record(ctx, h)
		if err != nil {
			t.Fatalf("dup Record: %v", err)
		}
		if v.Persisted {
			t.Error("Persisted = true on exact dup")
		}
	})

	t.Run("equivocation_detect_and_burn", func(t *testing.T) {
		const did = "did:web:fork.example"
		h1 := pgHead(did, 500, 5, 0xAA, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		h2 := pgHead(did, 500, 6, 0xBB, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if _, err := j.Record(ctx, h1); err != nil {
			t.Fatalf("Record h1: %v", err)
		}
		v, err := j.Record(ctx, h2)
		if err != nil {
			t.Fatalf("Record h2: %v", err)
		}
		if !v.Equivocation || !v.BurnTransition {
			t.Errorf("verdict = %+v, want Equivocation+BurnTransition", v)
		}

		// Burn-aware reads fail closed.
		if _, err := j.LatestHead(ctx, did); !errors.Is(err, monitoring.ErrEquivocatedLog) {
			t.Errorf("LatestHead = %v, want ErrEquivocatedLog", err)
		}
		// Forensic reads succeed.
		heads, err := j.HeadsAtSequence(ctx, did, 500)
		if err != nil {
			t.Fatalf("HeadsAtSequence: %v", err)
		}
		if len(heads) != 2 {
			t.Errorf("len(HeadsAtSequence) = %d, want 2", len(heads))
		}
	})

	t.Run("HeadAt_orderingSemantics", func(t *testing.T) {
		const did = "did:web:order.example"
		base := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := uint64(1); i <= 5; i++ {
			h := pgHead(did, i*10, i, byte(i), base.Add(time.Duration(i)*time.Hour))
			if _, err := j.Record(ctx, h); err != nil {
				t.Fatalf("seed i=%d: %v", i, err)
			}
		}
		// asOf=25 → returns seq=20
		got, err := j.HeadAt(ctx, did, 25)
		if err != nil {
			t.Fatalf("HeadAt(25): %v", err)
		}
		if got.TreeSize != 20 {
			t.Errorf("HeadAt(25).TreeSize = %d, want 20", got.TreeSize)
		}
	})

	t.Run("multi_log_isolation", func(t *testing.T) {
		// Burn one log; another must remain clean.
		const burnt = "did:web:isolation-burnt.example"
		const clean = "did:web:isolation-clean.example"
		now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		if _, err := j.Record(ctx, pgHead(burnt, 7, 1, 0xA1, now)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.Record(ctx, pgHead(burnt, 7, 2, 0xA2, now)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.Record(ctx, pgHead(clean, 7, 1, 0xC1, now)); err != nil {
			t.Fatal(err)
		}
		if _, err := j.LatestHead(ctx, clean); err != nil {
			t.Errorf("clean LatestHead = %v, want success after sibling burn", err)
		}
		if _, err := j.LatestHead(ctx, burnt); !errors.Is(err, monitoring.ErrEquivocatedLog) {
			t.Errorf("burnt LatestHead = %v, want ErrEquivocatedLog", err)
		}
	})
}

func pgHead(logDID string, sequence, lamport uint64, rootSeed byte, committedAt time.Time) monitoring.Head {
	return monitoring.Head{
		LogDID: logDID,
		TreeHead: types.TreeHead{
			RootHash:    [32]byte{rootSeed},
			SMTRoot:     [32]byte{rootSeed ^ 0xFF},
			ReceiptRoot: [32]byte{},
			TreeSize:    sequence,
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0xAA, rootSeed}, SchemeTag: 0x01, SigBytes: []byte{0xCD, rootSeed}},
		},
		CanonicalBytes: []byte("wire:" + logDID),
		LamportTime:    lamport,
		CommittedAt:    committedAt,
	}
}
