//go:build integration

// This is the REAL-DATABASE half of the conformance pattern: the same suite the
// in-memory fake passes is run against Postgres in CI. Run with:
//
//	LEDGER_TEST_DATABASE_URL=postgres://... go test -tags integration ./reservation/...
//
// against a database migrated through 0016_artifact_reservations.sql.
package reservation_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/tooling/services/ledger/reservation"
	"github.com/baseproof/tooling/services/ledger/reservation/reservationtest"
)

func TestPostgresStore_Conformance(t *testing.T) {
	url := os.Getenv("LEDGER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set LEDGER_TEST_DATABASE_URL (a migrated DB) to run the Postgres conformance suite")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	reservationtest.StoreConformance(t, func() reservation.Store {
		// Each sub-test gets a clean table (the fake gets a fresh map).
		if _, err := pool.Exec(context.Background(), "TRUNCATE artifact_reservations"); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return reservation.NewPostgresStore(pool)
	})
}
