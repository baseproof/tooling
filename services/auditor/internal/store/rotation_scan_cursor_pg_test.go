// FILE PATH: services/auditor/internal/store/rotation_scan_cursor_pg_test.go
//
// Live-Postgres integration tests for the AT-2 SQL surfaces, following the
// house harness (AUDITOR_TEST_PG_DSN-gated, like heads_journal_test.go):
//
//	AUDITOR_TEST_PG_DSN="postgres://postgres:test@localhost:5432/postgres?sslmode=disable" \
//	  go test ./internal/store/ -run TestPG_RotationAT2
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/types"
)

func openPGOrSkip(t *testing.T) *sql.DB {
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

// TestPG_RotationAT2_ScanCursor pins the cursor contract: zero for a log never
// scanned, round-trip, and the MONOTONIC guard (a replayed older pass must not
// regress coverage — coverage regression would silently reopen tail-omission).
func TestPG_RotationAT2_ScanCursor(t *testing.T) {
	db := openPGOrSkip(t)
	ctx := context.Background()
	c, err := NewPostgresRotationScanCursor(db)
	if err != nil {
		t.Fatalf("NewPostgresRotationScanCursor: %v", err)
	}
	if err := c.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	logDID := "did:web:cursor.pg.test"
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM witness_rotation_scan_cursor WHERE log_did = $1`, logDID)
	})

	if got, err := c.ScanCursor(ctx, logDID); err != nil || got != 0 {
		t.Fatalf("fresh cursor = %d, %v; want 0, nil", got, err)
	}
	if err := c.SetScanCursor(ctx, logDID, 500); err != nil {
		t.Fatalf("SetScanCursor(500): %v", err)
	}
	if got, _ := c.ScanCursor(ctx, logDID); got != 500 {
		t.Fatalf("cursor = %d, want 500", got)
	}
	// Replayed older pass: must NOT regress (GREATEST guard).
	if err := c.SetScanCursor(ctx, logDID, 100); err != nil {
		t.Fatalf("SetScanCursor(100): %v", err)
	}
	if got, _ := c.ScanCursor(ctx, logDID); got != 500 {
		t.Fatalf("cursor regressed to %d after stale write; want 500", got)
	}
	if err := c.SetScanCursor(ctx, logDID, 900); err != nil {
		t.Fatalf("SetScanCursor(900): %v", err)
	}
	if got, _ := c.ScanCursor(ctx, logDID); got != 900 {
		t.Fatalf("cursor = %d, want 900", got)
	}
}

// TestPG_RotationAT2_LatestRecordedAt pins the adoption-grace clock: absent for
// an unjournaled log; the NEWEST record's recorded_at otherwise.
func TestPG_RotationAT2_LatestRecordedAt(t *testing.T) {
	db := openPGOrSkip(t)
	ctx := context.Background()
	j, err := NewPostgresWitnessRotationJournal(db)
	if err != nil {
		t.Fatalf("NewPostgresWitnessRotationJournal: %v", err)
	}
	if err := j.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	logDID := "did:web:recordedat.pg.test"
	t.Cleanup(func() { _ = j.PurgeFor(ctx, logDID) })

	if _, ok, err := j.LatestRecordedAtFor(ctx, logDID); err != nil || ok {
		t.Fatalf("empty journal: ok=%v err=%v; want false, nil", ok, err)
	}

	netID := rotTestNetID()
	s0, k0, p0 := genWitnessSet(t, 3, 2, netID)
	_ = s0
	_, k1, _ := genWitnessSet(t, 3, 2, netID)
	rot := buildRotation(t, k0, p0, k1, 2, netID)
	before := time.Now().Add(-time.Minute)
	if err := j.RecordRotation(ctx, types.WitnessRotationRecord{
		Rotation:     rot,
		EffectivePos: types.LogPosition{LogDID: logDID, Sequence: 7},
	}); err != nil {
		t.Fatalf("RecordRotation: %v", err)
	}
	at, ok, err := j.LatestRecordedAtFor(ctx, logDID)
	if err != nil || !ok {
		t.Fatalf("LatestRecordedAtFor: ok=%v err=%v", ok, err)
	}
	if at.Before(before) || at.After(time.Now().Add(time.Minute)) {
		t.Fatalf("recorded_at %v outside sane window", at)
	}
}

// TestPG_RotationAT2_LatestSTHWithTime pins the frozen-log observation clock:
// the newest STH row's payload decodes back AND its inserted_at is surfaced.
func TestPG_RotationAT2_LatestSTHWithTime(t *testing.T) {
	db := openPGOrSkip(t)
	ctx := context.Background()
	st, err := NewPostgresStore(db)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	originator := "did:key:zSTHTimePG"
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM peer_gossip WHERE originator = $1`, originator)
	})

	if _, _, ok, err := st.LatestSTHWithTime(ctx, originator); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v; want false, nil", ok, err)
	}

	// Insert a row the way the store itself persists events (json payload),
	// with two lamports — the newer must win.
	insert := func(lamport int64, body string) {
		ev := gossip.SignedEvent{
			Kind:       gossip.KindCosignedTreeHead,
			Originator: originator,
			LamportTime: func() uint64 {
				return uint64(lamport)
			}(),
			Body: json.RawMessage(body),
		}
		payload, merr := json.Marshal(ev)
		if merr != nil {
			t.Fatalf("marshal: %v", merr)
		}
		if _, ierr := db.ExecContext(ctx,
			`INSERT INTO peer_gossip (event_id, originator, kind, lamport, payload) VALUES ($1, $2, $3, $4, $5)`,
			"sthtime-pg-"+body[:8]+"-"+time.Now().Format("150405.000000000"),
			originator, string(gossip.KindCosignedTreeHead), lamport, payload); ierr != nil {
			t.Fatalf("insert: %v", ierr)
		}
	}
	insert(1, `{"which":"older"}`)
	insert(2, `{"which":"newest"}`)

	ev, at, ok, err := st.LatestSTHWithTime(ctx, originator)
	if err != nil || !ok {
		t.Fatalf("LatestSTHWithTime: ok=%v err=%v", ok, err)
	}
	if string(ev.Body) != `{"which":"newest"}` {
		t.Fatalf("got body %s, want the max-lamport row", ev.Body)
	}
	if at.IsZero() || time.Since(at) > time.Minute {
		t.Fatalf("inserted_at %v not surfaced as a recent observation clock", at)
	}
}
