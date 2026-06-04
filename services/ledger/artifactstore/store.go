/*
FILE PATH:

	artifactstore/store.go

DESCRIPTION:

	The ledger's in-process artifact store: a storage.ContentStore (baseproof#97
	seam) layered over a dumb byte Backend. It is the consumer-side foundation
	for ledger#193 — the commitment sidecar (#190) and, later, large/sealed
	judicial artifacts — and is deliberately PORTABLE: it imports only
	baseproof/storage + standard-library backends, never any other ledger package,
	so it relocates ledger -> tooling -> SDK toolkit by moving a directory
	(enforced by scripts/artifactstore-portability-guard.sh).

KEY ARCHITECTURAL DECISIONS:
  - Invariants on top, dumb bytes below: Store enforces the Zero-Trust seam
    invariants (producer-computes-CID, backend-never-recomputes,
    verify-on-read); Backend just moves opaque (key -> bytes). Adapters
    (memory, posix; later GCS/S3) stay trivial and the integrity logic lives
    in one place.
  - Push stores VERBATIM: the producer supplies the CID; the backend does not
    recompute or reject it (invariant #1). Write-time CID checking is an
    UPLOAD-protocol concern (ledger#193 §A, verify-on-write at the HTTP
    boundary), not the in-process port — and the SDK conformance suite relies
    on being able to push mismatched bytes to exercise verify-on-read.
  - Fetch verifies-on-read (invariant #2): the backend is an untrusted channel;
    the CID is the trust anchor (constant-time CID.Verify), else
    storage.ErrIntegrityViolation.

OVERVIEW:

	NewStore(backend) -> a storage.ContentStore. Push -> Backend.Put verbatim;
	Fetch -> Backend.Get then CID.Verify; Exists/Delete pass through; Pin is a
	no-op (these backends keep every object durably). Passes
	storagetest.ContentStoreConformance for every backend.

KEY DEPENDENCIES:
  - github.com/baseproof/baseproof/storage: the ContentStore port, CID,
    and the sentinel errors. THE ONLY non-stdlib dependency (portability).
*/
package artifactstore

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/storage"
)

// Backend is the dumb byte-storage substrate: opaque (key -> bytes), no CID
// awareness. Adapters (MemoryBackend, PosixBackend; later cloud) implement it.
type Backend interface {
	// Put stores data under key, overwriting any prior value.
	Put(ctx context.Context, key string, data []byte) error
	// Get returns the bytes for key, or storage.ErrContentNotFound if absent.
	Get(ctx context.Context, key string) ([]byte, error)
	// Has reports whether key is present without fetching it.
	Has(ctx context.Context, key string) (bool, error)
	// Delete removes key. Absent key is not an error (idempotent).
	Delete(ctx context.Context, key string) error
}

// Store is a storage.ContentStore over a Backend.
type Store struct {
	backend Backend
}

// NewStore wraps a Backend as a CID-aware ContentStore.
func NewStore(backend Backend) *Store { return &Store{backend: backend} }

// Store is a storage.ContentStore.
var _ storage.ContentStore = (*Store)(nil)

// Push stores data under cid verbatim. The producer computed the CID; the store
// never recomputes it (invariant #1). Keyed by cid.String().
func (s *Store) Push(ctx context.Context, cid storage.CID, data []byte) error {
	if cid.IsZero() {
		return fmt.Errorf("artifactstore: push with zero CID")
	}
	return s.backend.Put(ctx, cid.String(), data)
}

// Fetch returns the bytes for cid, verified on read against it (invariant #2).
func (s *Store) Fetch(ctx context.Context, cid storage.CID) ([]byte, error) {
	data, err := s.backend.Get(ctx, cid.String())
	if err != nil {
		return nil, err
	}
	if !cid.Verify(data) {
		return nil, fmt.Errorf("artifactstore: fetch %s: %w", cid, storage.ErrIntegrityViolation)
	}
	return data, nil
}

// Exists reports whether cid is present.
func (s *Store) Exists(ctx context.Context, cid storage.CID) (bool, error) {
	return s.backend.Has(ctx, cid.String())
}

// Pin is a no-op for these durable backends (no GC), so every present object is
// effectively pinned. Returns ErrContentNotFound for an absent CID, matching the
// SDK in-memory reference store.
func (s *Store) Pin(ctx context.Context, cid storage.CID) error {
	ok, err := s.backend.Has(ctx, cid.String())
	if err != nil {
		return err
	}
	if !ok {
		return storage.ErrContentNotFound
	}
	return nil
}

// Delete removes cid from the store (Layer-1 byte deletion). Idempotent.
func (s *Store) Delete(ctx context.Context, cid storage.CID) error {
	return s.backend.Delete(ctx, cid.String())
}
