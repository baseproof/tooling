/*
FILE PATH:

	internal/embeddedpg/embeddedpg.go

DESCRIPTION:

	A test harness that runs a REAL Postgres (via embedded-postgres — a real PG
	binary in a temp dir, no Docker) and applies the ledger's production
	migrations through store.RunMigrations, so integration tests exercise the
	actual SQL / transactional / CAS behaviour against the real engine on the
	real schema — the "real backend in CI" tier of the conformance pattern.

	Start gracefully t.Skip()s when the engine cannot be brought up (no network
	for the one-time binary download, or a sandbox that forbids the process), so
	the suite validates where it can and never hard-fails elsewhere. Postgres
	refuses to run as root, so these tests must run as a non-root user.
*/
package embeddedpg

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/tooling/services/ledger/store"
)

// Start brings up a real Postgres, applies the ledger's embedded migrations via
// store.RunMigrations, and returns a connected pool. It t.Skip()s if the engine
// can't start. Engine + pool are torn down via t.Cleanup.
func Start(t *testing.T, port uint32) *pgxpool.Pool {
	t.Helper()

	runtime := t.TempDir()
	pg := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Username("ledger").
			Password("ledger").
			Database("ledger").
			Port(port).
			RuntimePath(filepath.Join(runtime, "rt")).
			DataPath(filepath.Join(runtime, "data")).
			BinariesPath(filepath.Join(runtime, "bin")).
			StartTimeout(90 * time.Second),
	)
	if err := pg.Start(); err != nil {
		t.Skipf("embedded postgres unavailable (no DB validation in this environment): %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })

	dsn := fmt.Sprintf("postgres://ledger:ledger@localhost:%d/ledger?sslmode=disable", port)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("embeddedpg: connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := store.RunMigrations(ctx, pool); err != nil {
		t.Fatalf("embeddedpg: migrate: %v", err)
	}
	return pool
}
