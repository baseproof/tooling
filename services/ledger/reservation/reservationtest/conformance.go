/*
FILE PATH:

	reservation/reservationtest/conformance.go

DESCRIPTION:

	StoreConformance — the reusable contract suite every reservation.Store
	implementation MUST pass (the conformance-test pattern). The in-memory fake
	runs it on every `go test`; the Postgres impl runs the SAME suite against a
	real database in CI. One definition of "correct" — fake and real cannot drift.

	Lives in a separate package so the reservation package never depends on
	testing in its production build.
*/
package reservationtest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/baseproof/tooling/services/ledger/reservation"
)

// StoreConformance asserts the reservation.Store contract. Backends pass a
// factory for a fresh, empty store.
func StoreConformance(t *testing.T, newStore func() reservation.Store) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// cid generates a distinct artifact-CID string per id (the reservation key).
	cid := func(id int) string {
		return fmt.Sprintf("sha256:%064x", id)
	}
	mk := func(id int, expires time.Time) reservation.Reservation {
		return reservation.Reservation{
			ArtifactCID: cid(id), ContentDigest: "sha256:cd",
			MaxSize: 1024, Owner: "did:court", Status: reservation.StatusPendingUpload,
			ExpiresAt: expires, CreatedAt: base,
		}
	}

	t.Run("create + get + duplicate", func(t *testing.T) {
		s := newStore()
		if _, err := s.Get(ctx, cid(1)); !errors.Is(err, reservation.ErrNotFound) {
			t.Fatalf("get absent: want ErrNotFound, got %v", err)
		}
		if err := s.Create(ctx, mk(1, base.Add(time.Hour))); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := s.Get(ctx, cid(1))
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.ArtifactCID != cid(1) || got.Status != reservation.StatusPendingUpload {
			t.Fatalf("get mismatch: %+v", got)
		}
		if err := s.Create(ctx, mk(1, base.Add(time.Hour))); !errors.Is(err, reservation.ErrDuplicate) {
			t.Fatalf("duplicate: want ErrDuplicate, got %v", err)
		}
	})

	t.Run("CAS transitions", func(t *testing.T) {
		s := newStore()
		_ = s.Create(ctx, mk(2, base.Add(time.Hour)))
		if err := s.SetStatus(ctx, cid(2), reservation.StatusPendingUpload, reservation.StatusUploaded); err != nil {
			t.Fatalf("pending->uploaded: %v", err)
		}
		// Stale `from` (already moved) is a conflict.
		if err := s.SetStatus(ctx, cid(2), reservation.StatusPendingUpload, reservation.StatusCommitted); !errors.Is(err, reservation.ErrConflict) {
			t.Fatalf("stale from: want ErrConflict, got %v", err)
		}
		if err := s.SetStatus(ctx, cid(2), reservation.StatusUploaded, reservation.StatusCommitted); err != nil {
			t.Fatalf("uploaded->committed: %v", err)
		}
		// From a terminal status: no further move.
		if err := s.SetStatus(ctx, cid(2), reservation.StatusCommitted, reservation.StatusExpired); !errors.Is(err, reservation.ErrConflict) {
			t.Fatalf("from terminal: want ErrConflict, got %v", err)
		}
		// Absent row.
		if err := s.SetStatus(ctx, cid(999), reservation.StatusPendingUpload, reservation.StatusCommitted); !errors.Is(err, reservation.ErrNotFound) {
			t.Fatalf("absent: want ErrNotFound, got %v", err)
		}
	})

	t.Run("list expirable excludes future + terminal", func(t *testing.T) {
		s := newStore()
		_ = s.Create(ctx, mk(10, base.Add(-time.Minute)))                                           // expired, non-terminal
		_ = s.Create(ctx, mk(11, base.Add(time.Hour)))                                              // not yet expired
		_ = s.Create(ctx, mk(12, base.Add(-time.Hour)))                                             // expired...
		_ = s.SetStatus(ctx, cid(12), reservation.StatusPendingUpload, reservation.StatusCommitted) // ...but terminal
		exp, err := s.ListExpirable(ctx, base, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(exp) != 1 || exp[0].ArtifactCID != cid(10) {
			t.Fatalf("expirable: want [%s], got %+v", cid(10), exp)
		}
	})
}
