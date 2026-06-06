package api

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/types"
)

// CheckpointFetcher exposes the ledger's cosigned-head reads through the SDK's
// log/bundle.BundleFetcher.FetchCosignedHead contract, so external consumers
// (bundle builders, verifiers) compose against a uniform SDK type instead of a
// ledger-local interface.
//
// The per-size archive (CheckpointArchiveReader) is the substrate for TIGHT
// covering — returning the smallest cosigned head that commits seq, which yields
// the smallest cold-read inclusion proof (wired in 1.1b). Today FetchCosignedHead
// returns the latest cosigned horizon, which the SDK documents as a valid cover
// ("the most-recent head >= seq via /v1/tree/horizon").
type CheckpointFetcher struct {
	horizon HorizonReader
	archive CheckpointArchiveReader // optional; reserved for tight-cover resolution (1.1b)
}

// NewCheckpointFetcher builds the SDK-conformant checkpoint fetcher over the
// horizon (required) and the per-size archive (optional, for tight covering).
func NewCheckpointFetcher(horizon HorizonReader, archive CheckpointArchiveReader) *CheckpointFetcher {
	return &CheckpointFetcher{horizon: horizon, archive: archive}
}

// FetchCosignedHead returns the witness-cosigned tree head under which entry
// seq's inclusion / SMT proofs are valid — matching the signature of
// log/bundle.BundleFetcher.FetchCosignedHead. Any cosigned head with
// TreeSize > seq is a valid cover; this returns the latest cosigned horizon
// (object store, PG-free). A seq at/beyond the horizon (not yet committed) is an
// error, never a fabricated head.
func (f *CheckpointFetcher) FetchCosignedHead(ctx context.Context, seq uint64) (types.CosignedTreeHead, error) {
	head, _, err := f.horizon.ReadHorizon(ctx)
	if err != nil {
		return types.CosignedTreeHead{}, err
	}
	if head == nil {
		return types.CosignedTreeHead{}, fmt.Errorf("api: no cosigned horizon available")
	}
	if seq >= head.TreeSize {
		return types.CosignedTreeHead{}, fmt.Errorf("api: seq %d not yet committed (cosigned horizon tree size %d)", seq, head.TreeSize)
	}
	return *head, nil
}
