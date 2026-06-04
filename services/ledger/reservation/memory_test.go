package reservation_test

import (
	"testing"

	"github.com/baseproof/tooling/services/ledger/reservation"
	"github.com/baseproof/tooling/services/ledger/reservation/reservationtest"
)

// The in-memory fake must satisfy the same contract as Postgres.
func TestMemoryStore_Conformance(t *testing.T) {
	reservationtest.StoreConformance(t, func() reservation.Store {
		return reservation.NewMemoryStore()
	})
}
