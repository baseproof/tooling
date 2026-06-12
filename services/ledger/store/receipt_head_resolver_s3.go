/*
FILE PATH: store/receipt_head_resolver_s3.go

PG-free api.ReceiptHeadResolver for the cold (PG-off) read front.

The receipt-proof handler (api/receipt.go) resolves the published checkpoint a
receipt binds to via three queries: the smallest cosigned size covering the entry
(CosignedSizeAtOrAbove), the previous published size that starts the delta range
(CosignedSizeBelow), and the cosigned head at a size (GetBySize). The writer answers
these from Postgres (TreeHeadStore); a PG-off reader answers them from the object
store alone: the checkpoint-size INDEX enumerates published sizes, the S3 horizon
reader caps the scan (latest published) and reads a head by size from the per-size
archive. With the index durable-before-horizon (horizon_s3.go) and the receipt
commitments durable-before-horizon (builder/checkpoint_loop.go), every entry a
published head covers has a reconstructable receipt proof, no Postgres in the path.
*/
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	sdktypes "github.com/baseproof/baseproof/types"
)

// S3ReceiptHeadResolver answers the receipt-proof head queries (api.ReceiptHeadResolver)
// from the object store alone.
type S3ReceiptHeadResolver struct {
	index   *S3CheckpointSizeIndex
	horizon *S3HorizonReader
}

// NewS3ReceiptHeadResolver composes the resolver from the checkpoint-size index (the
// enumeration) and the S3 horizon reader (the scan cap + per-size head read).
func NewS3ReceiptHeadResolver(index *S3CheckpointSizeIndex, horizon *S3HorizonReader) *S3ReceiptHeadResolver {
	return &S3ReceiptHeadResolver{index: index, horizon: horizon}
}

// latestSize returns the most recently published horizon size — the upper bound for
// the at-or-above scan. 0 (no checkpoint published yet) ⇒ nothing covers any seq.
func (r *S3ReceiptHeadResolver) latestSize(ctx context.Context) (uint64, error) {
	head, _, err := r.horizon.ReadHorizon(ctx)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return head.TreeSize, nil
}

// CosignedSizeAtOrAbove returns the smallest PUBLISHED checkpoint size >= minSize.
// minSigs is satisfied by construction: only cosigned (K-of-N) heads are ever
// published/archived/indexed, so every indexed size already meets quorum — no
// per-head signature filter is needed (or possible PG-free without reading each head).
func (r *S3ReceiptHeadResolver) CosignedSizeAtOrAbove(ctx context.Context, minSize uint64, _ int) (uint64, bool, error) {
	maxSize, err := r.latestSize(ctx)
	if err != nil {
		return 0, false, err
	}
	return r.index.AtOrAbove(ctx, minSize, maxSize)
}

// CosignedSizeBelow returns the largest published checkpoint size < size.
func (r *S3ReceiptHeadResolver) CosignedSizeBelow(ctx context.Context, size uint64, _ int) (uint64, bool, error) {
	return r.index.Below(ctx, size)
}

// GetBySize returns the cosigned head archived at size (with its witness signatures),
// in the apitypes shape the receipt handler re-encodes (api/receipt.go round-trips it
// through HeadToSDK). A size the index named but the archive lacks is a real
// inconsistency → error (never a fabricated head); a genuinely absent size is the
// handler's not-found.
func (r *S3ReceiptHeadResolver) GetBySize(ctx context.Context, size uint64) (*CosignedTreeHead, error) {
	head, _, err := r.horizon.ReadCheckpointAt(ctx, size)
	if err != nil {
		return nil, fmt.Errorf("store/receipt-head-s3: checkpoint at %d: %w", size, err)
	}
	return sdkHeadToAPI(head), nil
}

// sdkHeadToAPI converts a parsed cosigned head to the apitypes shape the receipt
// handler consumes — the inverse of HeadToSDK. Only the four root/size fields and the
// witness SIGNATURES (as marshaled WitnessSignature JSON, which HeadToSDK unmarshals
// back) are load-bearing for the handler's re-encode; the per-signer convenience
// fields (Signer/SigAlgo/CreatedAt) are left zero, exactly as HeadToSDK ignores them.
func sdkHeadToAPI(h *sdktypes.CosignedTreeHead) *CosignedTreeHead {
	if h == nil {
		return nil
	}
	sigs := make([]TreeHeadSignature, 0, len(h.Signatures))
	for i := range h.Signatures {
		raw, err := json.Marshal(h.Signatures[i])
		if err != nil {
			continue
		}
		sigs = append(sigs, TreeHeadSignature{Signature: raw})
	}
	return &CosignedTreeHead{
		TreeSize:    h.TreeSize,
		RootHash:    h.RootHash,
		SMTRoot:     h.SMTRoot,
		ReceiptRoot: h.ReceiptRoot,
		Signatures:  sigs,
	}
}
