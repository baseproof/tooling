/*
FILE PATH: store/checkpoint_index.go

Object-store index of PUBLISHED cosigned-checkpoint tree sizes — the PG-free
ENUMERATION a receipt-proof head resolver needs.

WHY: a receipt proof binds an entry to the FIRST cosigned checkpoint covering it
(api/receipt.go: CosignedSizeAtOrAbove(seq+1) then CosignedSizeBelow for the delta
range), so the read front must ENUMERATE published checkpoints, not just read one by
size. The PG TreeHeadStore answers this from tree_heads; a PG-off reader cannot. The
object store holds each cosigned head at checkpoints/<size> (horizon_s3.go) but the
byte-store abstraction has NO LIST, so the published sizes are unrecoverable without a
written index.

DESIGN: a BUCKETED index keyed by size-range so it scales to the 15-year / 10B-entry
envelope without an unbounded single object. Bucket b holds the ASCENDING sizes in
[b<<shift, (b+1)<<shift), framed exactly like the rotation index (1-byte version +
8-byte big-endian sizes). The singleton checkpoint writer appends each published size
to its bucket (monotonic ⇒ almost always the current/highest bucket); a reader
binary-searches one or two buckets to answer at-or-above / below. The *bytestore.S3
adapter namespaces every key per-log, so two logs sharing a bucket never collide.
*/
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// checkpointIndexShift sets the bucket span: bucket b covers sizes in
// [b<<shift, (b+1)<<shift). 1<<16 = 65536 sizes/bucket — at 500 TPS a bucket spans a
// few hundred entries' worth of cosign cycles, so each object stays a few KB while the
// bucket COUNT stays small (10B/65536 ≈ 150k objects over 15 years).
const checkpointIndexShift = 16

// checkpointIndexVersion prefixes each bucket blob (framing-compatible with the
// rotation index). A corrupt or unknown version is REJECTED, never read as "no sizes".
const checkpointIndexVersion byte = 1

// checkpointIndexBucketKey is the LOGICAL object key for a bucket. The *bytestore.S3
// adapter prepends the per-log namespace, so two logs sharing a bucket never collide.
func checkpointIndexBucketKey(bucket uint64) string {
	return "checkpoint-index/" + strconv.FormatUint(bucket, 10)
}

// encodeCheckpointIndex serializes ascending sizes: 1-byte version + 8-byte BE sizes.
func encodeCheckpointIndex(sizes []uint64) []byte {
	out := make([]byte, 1+len(sizes)*8)
	out[0] = checkpointIndexVersion
	for i, s := range sizes {
		binary.BigEndian.PutUint64(out[1+i*8:], s)
	}
	return out
}

// decodeCheckpointIndex validates version + framing and parses the ascending sizes. A
// bad version or a body that is not a whole number of 8-byte sizes is REJECTED.
func decodeCheckpointIndex(raw []byte) ([]uint64, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("store/checkpoint-index: empty bucket blob")
	}
	if raw[0] != checkpointIndexVersion {
		return nil, fmt.Errorf("store/checkpoint-index: unsupported version %d (want %d)", raw[0], checkpointIndexVersion)
	}
	body := raw[1:]
	if len(body)%8 != 0 {
		return nil, fmt.Errorf("store/checkpoint-index: corrupt bucket: %d body bytes not a multiple of 8", len(body))
	}
	sizes := make([]uint64, len(body)/8)
	for i := range sizes {
		sizes[i] = binary.BigEndian.Uint64(body[i*8:])
	}
	return sizes, nil
}

// S3CheckpointSizeIndex maintains + reads the bucketed index of published cosigned
// checkpoint sizes over a shared object store.
type S3CheckpointSizeIndex struct{ obj objectPutGetter }

// NewS3CheckpointSizeIndex builds the index over obj (a *bytestore.S3).
func NewS3CheckpointSizeIndex(obj objectPutGetter) *S3CheckpointSizeIndex {
	return &S3CheckpointSizeIndex{obj: obj}
}

// bucketSizes reads the ascending sizes in a bucket. A never-written bucket is the
// EMPTY slice (not an error), so a gap between checkpoints reads as "no sizes here".
func (x *S3CheckpointSizeIndex) bucketSizes(ctx context.Context, bucket uint64) ([]uint64, error) {
	raw, err := x.obj.GetObject(ctx, checkpointIndexBucketKey(bucket))
	if errors.Is(err, bytestore.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeCheckpointIndex(raw)
}

// Append records size in its bucket. Idempotent (a re-published size is a no-op) and
// order-defensive (size is inserted in ascending position, so the bucket stays sorted
// regardless of call order). Read-modify-write of ONE small bucket object; the
// singleton writer publishes monotonically, so this almost always touches the highest
// bucket only.
func (x *S3CheckpointSizeIndex) Append(ctx context.Context, size uint64) error {
	bucket := size >> checkpointIndexShift
	sizes, err := x.bucketSizes(ctx, bucket)
	if err != nil {
		return fmt.Errorf("store/checkpoint-index: read bucket %d: %w", bucket, err)
	}
	i := sort.Search(len(sizes), func(i int) bool { return sizes[i] >= size })
	if i < len(sizes) && sizes[i] == size {
		return nil // already indexed — idempotent on republish / crash-retry
	}
	sizes = append(sizes, 0)
	copy(sizes[i+1:], sizes[i:])
	sizes[i] = size
	if err := x.obj.PutObject(ctx, checkpointIndexBucketKey(bucket), encodeCheckpointIndex(sizes)); err != nil {
		return fmt.Errorf("store/checkpoint-index: write bucket %d: %w", bucket, err)
	}
	return nil
}

// AtOrAbove returns the smallest published size >= minSize, scanning buckets UPWARD
// from minSize's bucket through maxSize's bucket (maxSize bounds the scan — the latest
// published horizon size). false when no published checkpoint covers minSize yet.
func (x *S3CheckpointSizeIndex) AtOrAbove(ctx context.Context, minSize, maxSize uint64) (uint64, bool, error) {
	if maxSize < minSize {
		return 0, false, nil
	}
	startB, endB := minSize>>checkpointIndexShift, maxSize>>checkpointIndexShift
	for b := startB; b <= endB; b++ {
		sizes, err := x.bucketSizes(ctx, b)
		if err != nil {
			return 0, false, err
		}
		if i := sort.Search(len(sizes), func(i int) bool { return sizes[i] >= minSize }); i < len(sizes) {
			// Defensive cap: the smallest size >= minSize can sit in maxSize's bucket
			// but past maxSize — a checkpoint not yet covered by the published horizon.
			if sizes[i] > maxSize {
				return 0, false, nil
			}
			return sizes[i], true, nil
		}
	}
	return 0, false, nil
}

// Below returns the largest published size < size, scanning buckets DOWNWARD from
// size's bucket. false when no earlier checkpoint exists (size at/below the first).
// In practice the previous checkpoint is one cosign cycle earlier (same or adjacent
// bucket), so this reads one or two buckets.
func (x *S3CheckpointSizeIndex) Below(ctx context.Context, size uint64) (uint64, bool, error) {
	if size == 0 {
		return 0, false, nil
	}
	for b := size >> checkpointIndexShift; ; b-- {
		sizes, err := x.bucketSizes(ctx, b)
		if err != nil {
			return 0, false, err
		}
		if i := sort.Search(len(sizes), func(i int) bool { return sizes[i] >= size }); i > 0 {
			return sizes[i-1], true, nil // largest entry < size in this bucket
		}
		if b == 0 {
			return 0, false, nil
		}
	}
}
