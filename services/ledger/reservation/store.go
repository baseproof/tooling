/*
FILE PATH:

	reservation/store.go

DESCRIPTION:

	Store — the persistence port for reservations (the "repository interface" of
	the Kubernetes test pattern). The Manager's lifecycle logic is written against
	this interface, so it is unit-tested against the in-memory fake (MemoryStore)
	deterministically, while the production PostgresStore is held to the SAME
	contract by reservationtest.StoreConformance (run against a real DB in CI).

	The load-bearing method is SetStatus(from, to): an ATOMIC compare-and-swap
	transition. Concurrency safety (two finishers, finish-vs-reaper) reduces to
	"exactly one CAS wins", which both impls must guarantee — the in-memory one
	under a mutex, the Postgres one via UPDATE ... WHERE status = from.
*/
package reservation

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when no reservation exists for an artifact CID.
var ErrNotFound = errors.New("reservation: not found")

// ErrConflict is returned by SetStatus when the row is not in the expected
// `from` status (a concurrent transition already moved it) or the move is
// illegal per CanTransition. The caller lost the race and MUST re-read.
var ErrConflict = errors.New("reservation: status conflict (CAS failed)")

// ErrDuplicate is returned by Create when a reservation already exists for the
// artifact CID.
var ErrDuplicate = errors.New("reservation: already exists")

// Store is the reservation persistence port. Reservations are keyed by
// ArtifactCID (a string CID), the content address known synchronously at
// submission time.
type Store interface {
	// Create inserts a new reservation. ErrDuplicate if ArtifactCID already exists.
	Create(ctx context.Context, r Reservation) error

	// Get returns the reservation for artifactCID, or ErrNotFound.
	Get(ctx context.Context, artifactCID string) (Reservation, error)

	// SetStatus atomically moves artifactCID from `from` to `to`. It returns
	// ErrConflict if the row is not currently in `from` (lost CAS) or the move
	// is not legal per CanTransition, and ErrNotFound if the row is absent.
	SetStatus(ctx context.Context, artifactCID string, from, to Status) error

	// ListExpirable returns reservations still in a non-terminal state whose
	// ExpiresAt is at or before now, up to limit rows (the reaper's work set).
	ListExpirable(ctx context.Context, now time.Time, limit int) ([]Reservation, error)
}
