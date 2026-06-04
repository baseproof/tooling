package embeddedpg_test

import (
	"context"
	"testing"

	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
)

// Feasibility probe: can a real Postgres start here, and do the migrations apply?
func TestEmbeddedPG_Smoke(t *testing.T) {
	pool := embeddedpg.Start(t, 54330)
	var one int
	if err := pool.QueryRow(context.Background(), "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("ping: err=%v one=%d", err, one)
	}
	// Confirm a late migration landed (artifact_reservations from 0016).
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='artifact_reservations')`,
	).Scan(&exists); err != nil {
		t.Fatalf("table check: %v", err)
	}
	if !exists {
		t.Fatal("artifact_reservations table not created by migrations")
	}
}
