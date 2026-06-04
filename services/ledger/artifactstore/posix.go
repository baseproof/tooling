/*
FILE PATH:

	artifactstore/posix.go

DESCRIPTION:

	PosixBackend — a filesystem Backend (dev, the scale harness, single-node
	deployments). Each object is one file at <root>/<algo>/<shard>/<digest>,
	sharded by the first two hex chars of the digest to avoid pathologically
	large directories. Writes are durable: temp file -> fsync -> atomic rename,
	so a crash never leaves a half-written object under a real CID key. Imports
	only stdlib + baseproof/storage (portability).
*/
package artifactstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/baseproof/baseproof/storage"
)

// PosixBackend stores objects as files under Root.
type PosixBackend struct {
	root string
}

// NewPosixBackend creates (and mkdir -p's) a filesystem backend rooted at root.
func NewPosixBackend(root string) (*PosixBackend, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("artifactstore/posix: empty root")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("artifactstore/posix: mkdir root: %w", err)
	}
	return &PosixBackend{root: root}, nil
}

var _ Backend = (*PosixBackend)(nil)

// objPath maps a CID key ("sha256:hexdigest") to a sharded file path. An
// unexpected key without a ":" is filed under "raw/" so it still round-trips.
func (b *PosixBackend) objPath(key string) string {
	algo, digest, found := strings.Cut(key, ":")
	if !found {
		algo, digest = "raw", key
	}
	shard := "00"
	if len(digest) >= 2 {
		shard = digest[:2]
	}
	return filepath.Join(b.root, algo, shard, digest)
}

func (b *PosixBackend) Put(_ context.Context, key string, data []byte) error {
	p := b.objPath(key)
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("artifactstore/posix: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("artifactstore/posix: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed; cleans up on any error path
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("artifactstore/posix: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("artifactstore/posix: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("artifactstore/posix: close: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("artifactstore/posix: rename: %w", err)
	}
	return nil
}

func (b *PosixBackend) Get(_ context.Context, key string) ([]byte, error) {
	data, err := os.ReadFile(b.objPath(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, storage.ErrContentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("artifactstore/posix: read: %w", err)
	}
	return data, nil
}

func (b *PosixBackend) Has(_ context.Context, key string) (bool, error) {
	_, err := os.Stat(b.objPath(key))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("artifactstore/posix: stat: %w", err)
	}
	return true, nil
}

func (b *PosixBackend) Delete(_ context.Context, key string) error {
	err := os.Remove(b.objPath(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil // idempotent
	}
	if err != nil {
		return fmt.Errorf("artifactstore/posix: remove: %w", err)
	}
	return nil
}
