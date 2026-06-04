/*
FILE PATH:

	reservation/memory.go

DESCRIPTION:

	MemoryStore — the in-memory reservation Store (the "fake client" of the
	Kubernetes pattern). Deterministic and DB-free, so the Manager's RESERVE /
	FINISH / REAP logic is unit-tested against it without a database. It honors
	the same contract as PostgresStore (proven by reservationtest.StoreConformance),
	so passing tests against the fake are meaningful for the real impl.
*/
package reservation

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is a thread-safe in-memory Store.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string]Reservation
}

// NewMemoryStore creates an empty in-memory reservation store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{m: make(map[string]Reservation)} }

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) Create(_ context.Context, r Reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[r.ArtifactCID]; ok {
		return ErrDuplicate
	}
	s.m[r.ArtifactCID] = r
	return nil
}

func (s *MemoryStore) Get(_ context.Context, artifactCID string) (Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[artifactCID]
	if !ok {
		return Reservation{}, ErrNotFound
	}
	return r, nil
}

func (s *MemoryStore) SetStatus(_ context.Context, artifactCID string, from, to Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[artifactCID]
	if !ok {
		return ErrNotFound
	}
	// Atomic CAS: the row must currently be in `from`, and from->to must be a
	// legal move. Either failure is a conflict — the caller re-reads.
	if r.Status != from || !CanTransition(from, to) {
		return ErrConflict
	}
	r.Status = to
	s.m[artifactCID] = r
	return nil
}

func (s *MemoryStore) ListExpirable(_ context.Context, now time.Time, limit int) ([]Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Reservation
	for _, r := range s.m {
		if r.Status.terminal() {
			continue
		}
		if !r.ExpiresAt.After(now) { // ExpiresAt <= now
			out = append(out, r)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
