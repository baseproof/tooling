/*
FILE PATH: cmd/ledger-reader/horizon_appender.go

horizonAppenderBackend adapts a cosigned-horizon reader to tessera's
AppenderBackend for the OBJECT-STORE read front.

tessera.ReadOnlyAppender sources Head from a POSIX <dir>/checkpoint file — the
shared-filesystem deployment. An S3/GCS read front has no such file (it has no
shared filesystem at all), so Head and IntegratedSize come from the published
cosigned horizon instead — the SAME anchor the inclusion handler defaults its
tree size to when Postgres is off. Writes are rejected: a read front never
appends or publishes.
*/
package main

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/tessera"
)

// horizonAppenderBackend satisfies tessera.AppenderBackend over an
// api.HorizonReader — the proof adapter computes inclusion proofs from the object
// store tiles (its TileReader) and only consults the backend for the tree
// head/size, which the cosigned horizon provides PG-free.
type horizonAppenderBackend struct{ horizon api.HorizonReader }

var _ tessera.AppenderBackend = (*horizonAppenderBackend)(nil)

func newHorizonAppenderBackend(h api.HorizonReader) *horizonAppenderBackend {
	return &horizonAppenderBackend{horizon: h}
}

// AppendLeaf is rejected — the read front never writes.
func (b *horizonAppenderBackend) AppendLeaf(context.Context, []byte) (uint64, error) {
	return 0, tessera.ErrReadOnly
}

// PublishCosignedCheckpoint is rejected — only the writer's builder loop authors
// and publishes checkpoints.
func (b *horizonAppenderBackend) PublishCosignedCheckpoint(context.Context, types.CosignedTreeHead) error {
	return tessera.ErrReadOnly
}

// Head returns the committed head from the published cosigned horizon. Surfaces
// the horizon reader's wrapped os.ErrNotExist verbatim before the first
// checkpoint is published, matching tessera.ReadOnlyAppender.Head.
func (b *horizonAppenderBackend) Head() (types.TreeHead, error) {
	head, _, err := b.horizon.ReadHorizon(context.Background())
	if err != nil {
		return types.TreeHead{}, fmt.Errorf("ledger-reader: horizon head: %w", err)
	}
	return head.TreeHead, nil
}

// IntegratedSize is the cosigned head's TreeSize — the conservative bound a
// non-writer observes (a reader cannot see in-flight tile state past the
// published checkpoint, which is exactly the right bound).
func (b *horizonAppenderBackend) IntegratedSize(ctx context.Context) (uint64, error) {
	head, _, err := b.horizon.ReadHorizon(ctx)
	if err != nil {
		return 0, fmt.Errorf("ledger-reader: horizon integrated size: %w", err)
	}
	return head.TreeSize, nil
}
