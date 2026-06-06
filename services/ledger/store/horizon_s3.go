/*
FILE PATH: store/horizon_s3.go

S3-shared cosigned-checkpoint horizon (publish + read).

For the K8s / horizontally-scalable topology the horizon cannot live on a writer
pod's local filesystem: every stateless reader pod — and a restarted writer —
must read the SAME published CosignedTreeHead. So the singleton writer publishes
it to the shared object store (SeaweedFS/S3) and readers read it from there;
content-addressed/immutable enough to sit behind a CDN.

Same object key as the POSIX path ("cosigned-checkpoint", the full
json(CosignedTreeHead)), so POSIX single-node and S3 multi-pod deployments use
one name. S3 PutObject is atomic and read-after-write consistent on modern
S3/SeaweedFS, replacing the POSIX temp+rename.
*/
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// cosignedCheckpointKey is the LOGICAL object key for the published horizon.
// Mirrors the POSIX <TesseraStorageDir>/cosigned-checkpoint filename. It is a
// FIXED name, so when multiple logs share one bucket it would be a single global
// key — the last writer clobbers every other log's horizon. The *bytestore.S3
// adapter prepends the per-log Namespace to this (and every raw PutObject /
// GetObject) key, so the actual object is <namespace>/cosigned-checkpoint and no
// two logs ever collide. This file passes the logical name; the namespacing is
// transparent here by design (one chokepoint in the adapter, impossible to skip).
const cosignedCheckpointKey = "cosigned-checkpoint"

// S3CheckpointPublisher publishes the cosigned-checkpoint horizon to a shared
// object store. Satisfies CheckpointPublisher (used by the reconciler's
// HorizonPublisher).
type S3CheckpointPublisher struct{ obj objectPutGetter }

// NewS3CheckpointPublisher publishes the horizon to obj (a *bytestore.S3).
func NewS3CheckpointPublisher(obj objectPutGetter) *S3CheckpointPublisher {
	return &S3CheckpointPublisher{obj: obj}
}

// PublishCosignedCheckpoint writes json(head) to the shared checkpoint key.
// PutObject returns on a durable ack, so a published horizon is readable by
// every pod (the gate the reconciler advances the frontier on).
func (p *S3CheckpointPublisher) PublishCosignedCheckpoint(ctx context.Context, head sdktypes.CosignedTreeHead) error {
	// Canonical wire shape (lowercase-hex), the cross-version trust-anchor contract.
	body, err := json.Marshal(sdktypes.FromCosignedTreeHead(head))
	if err != nil {
		return fmt.Errorf("store/horizon-s3: marshal cosigned head: %w", err)
	}
	if err := p.obj.PutObject(ctx, cosignedCheckpointKey, body); err != nil {
		return fmt.Errorf("store/horizon-s3: publish checkpoint: %w", err)
	}
	// Per-tree_size archive (1.1a): durably retain this cosigned head (with its
	// witness cosignatures) so historical heads stay fetchable PG-free after the
	// latest advances — the anchor for cold-seq inclusion proofs. Never overwritten
	// across sizes. Mirrors the POSIX dual-write in tessera/embedded_appender.go.
	if head.TreeSize > 0 {
		if err := p.obj.PutObject(ctx, checkpointArchiveKey(head.TreeSize), body); err != nil {
			return fmt.Errorf("store/horizon-s3: archive checkpoint %d: %w", head.TreeSize, err)
		}
	}
	return nil
}

// checkpointArchiveKey is the LOGICAL object key for the per-tree_size archived
// cosigned head — the never-overwritten copy published beside the latest
// cosigned-checkpoint. MUST match the writer + readers: tessera
// checkpointArchiveDir="checkpoints" and api/horizon.go checkpointArchiveObject.
// The *bytestore.S3 adapter prepends the per-log namespace (as for
// cosignedCheckpointKey), so two logs sharing a bucket never collide.
func checkpointArchiveKey(size uint64) string {
	return "checkpoints/" + strconv.FormatUint(size, 10)
}

// receiptArchiveKey is the LOGICAL object key for the per-checkpoint dense
// receipt-commitment archive (1.2a) — the bytes ArchiveReceiptRanger reconstructs
// ReceiptRoot + inclusion proofs from, PG-free. Parallel to checkpointArchiveKey;
// the *bytestore.S3 adapter prepends the per-log namespace, so two logs sharing a
// bucket never collide.
func receiptArchiveKey(coveringSize uint64) string {
	return "receipts/" + strconv.FormatUint(coveringSize, 10)
}

// S3HorizonReader reads the published horizon from the shared object store. It
// satisfies api.HorizonReader structurally: ReadHorizon returns the parsed head
// AND the exact published bytes (so the proof handler bundles the bytes a client
// re-verifies). A pre-genesis miss is os.ErrNotExist (caller → 503).
type S3HorizonReader struct{ obj objectPutGetter }

// NewS3HorizonReader reads the horizon from obj (a *bytestore.S3).
func NewS3HorizonReader(obj objectPutGetter) *S3HorizonReader {
	return &S3HorizonReader{obj: obj}
}

// ReadHorizon returns (parsed head, raw bytes, err).
func (r *S3HorizonReader) ReadHorizon(ctx context.Context) (*sdktypes.CosignedTreeHead, []byte, error) {
	raw, err := r.obj.GetObject(ctx, cosignedCheckpointKey)
	if errors.Is(err, bytestore.ErrNotFound) {
		return nil, nil, os.ErrNotExist // pre-genesis: no checkpoint published yet
	}
	if err != nil {
		return nil, nil, err
	}
	var w sdktypes.WireCosignedTreeHead
	if uErr := json.Unmarshal(raw, &w); uErr != nil {
		return nil, nil, fmt.Errorf("store/horizon-s3: decode cosigned checkpoint: %w", uErr)
	}
	head, cErr := w.ToCosignedTreeHead()
	if cErr != nil {
		return nil, nil, fmt.Errorf("store/horizon-s3: decode cosigned checkpoint: %w", cErr)
	}
	return &head, raw, nil
}

// ReadReceiptCommits reads the archived dense receipt-commitment blob for the
// checkpoint at coveringSize from the shared object store — PG-free. A checkpoint
// whose receipts were never archived → os.ErrNotExist. Satisfies ReceiptCommitReader
// (the source ArchiveReceiptRanger reconstructs receipt proofs from). Returns the
// raw bytes verbatim; DecodeReceiptCommits validates framing.
func (r *S3HorizonReader) ReadReceiptCommits(ctx context.Context, coveringSize uint64) ([]byte, error) {
	raw, err := r.obj.GetObject(ctx, receiptArchiveKey(coveringSize))
	if errors.Is(err, bytestore.ErrNotFound) {
		return nil, os.ErrNotExist // checkpoint's receipts never archived
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// ReadRotationChain reads the archived witness-rotation chain blob from the shared
// object store — PG-free. A never-rotated network (no chain archived) → os.ErrNotExist.
// Satisfies RotationChainReader (the source ArchiveRotationChainFetcher reconstructs
// the SDK's FetchWitnessRotationChain seam from).
func (r *S3HorizonReader) ReadRotationChain(ctx context.Context) ([]byte, error) {
	raw, err := r.obj.GetObject(ctx, rotationChainKey())
	if errors.Is(err, bytestore.ErrNotFound) {
		return nil, os.ErrNotExist // never rotated
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// ReadCheckpointAt reads the archived cosigned head at the given tree size from
// the shared object store — PG-free. A size never archived → os.ErrNotExist.
// Satisfies api.CheckpointArchiveReader structurally (the S3 deployment's
// per-size read path, mirroring the POSIX tileBackendHorizon).
func (r *S3HorizonReader) ReadCheckpointAt(ctx context.Context, size uint64) (*sdktypes.CosignedTreeHead, []byte, error) {
	raw, err := r.obj.GetObject(ctx, checkpointArchiveKey(size))
	if errors.Is(err, bytestore.ErrNotFound) {
		return nil, nil, os.ErrNotExist // size never archived
	}
	if err != nil {
		return nil, nil, err
	}
	var w sdktypes.WireCosignedTreeHead
	if uErr := json.Unmarshal(raw, &w); uErr != nil {
		return nil, nil, fmt.Errorf("store/horizon-s3: decode cosigned checkpoint: %w", uErr)
	}
	head, cErr := w.ToCosignedTreeHead()
	if cErr != nil {
		return nil, nil, fmt.Errorf("store/horizon-s3: decode cosigned checkpoint: %w", cErr)
	}
	return &head, raw, nil
}
