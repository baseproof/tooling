/*
FILE PATH:

	artifactstore/memory.go

DESCRIPTION:

	MemoryBackend — an in-memory Backend for dev, tests, and the scale harness.
	Thread-safe; copies on the way in and out so callers can't mutate stored
	bytes. Imports only stdlib + baseproof/storage (portability).
*/
package artifactstore

import (
	"context"
	"sync"

	"github.com/baseproof/baseproof/storage"
)

// MemoryBackend is a thread-safe in-memory Backend.
type MemoryBackend struct {
	mu sync.RWMutex
	m  map[string][]byte
}

// NewMemoryBackend creates an empty in-memory backend.
func NewMemoryBackend() *MemoryBackend { return &MemoryBackend{m: make(map[string][]byte)} }

var _ Backend = (*MemoryBackend)(nil)

func (b *MemoryBackend) Put(_ context.Context, key string, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	b.mu.Lock()
	b.m[key] = cp
	b.mu.Unlock()
	return nil
}

func (b *MemoryBackend) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.RLock()
	data, ok := b.m[key]
	b.mu.RUnlock()
	if !ok {
		return nil, storage.ErrContentNotFound
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

func (b *MemoryBackend) Has(_ context.Context, key string) (bool, error) {
	b.mu.RLock()
	_, ok := b.m[key]
	b.mu.RUnlock()
	return ok, nil
}

func (b *MemoryBackend) Delete(_ context.Context, key string) error {
	b.mu.Lock()
	delete(b.m, key)
	b.mu.Unlock()
	return nil
}
