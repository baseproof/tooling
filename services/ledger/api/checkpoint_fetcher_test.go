package api

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// sdkBundleFetcher embeds *CheckpointFetcher (the real FetchCosignedHead) and
// stubs the other BundleFetcher methods. The compile-time assertion below proves
// the ledger's checkpoint read satisfies the SDK seam — THIS is what the reshape
// is about: external consumers compose against bundle.BundleFetcher, not a
// ledger-local interface.
type sdkBundleFetcher struct{ *CheckpointFetcher }

func (sdkBundleFetcher) FetchBootstrap(context.Context) (*network.BootstrapDocument, error) {
	return nil, nil
}
func (sdkBundleFetcher) FetchEntry(context.Context, uint64) ([]byte, time.Time, error) {
	return nil, time.Time{}, nil
}
func (sdkBundleFetcher) FetchInclusionProof(context.Context, uint64, uint64) (types.MerkleProof, error) {
	return types.MerkleProof{}, nil
}
func (sdkBundleFetcher) FetchSMTProof(context.Context, uint64, [32]byte) (types.SMTProof, error) {
	return types.SMTProof{}, nil
}
func (sdkBundleFetcher) FetchWitnessSetHash(context.Context, types.CosignedTreeHead) ([32]byte, error) {
	return [32]byte{}, nil
}

// Compile-time conformance: the ledger's FetchCosignedHead fits bundle.BundleFetcher.
var _ bundle.BundleFetcher = sdkBundleFetcher{}

// TestCheckpointFetcher_FetchCosignedHead: the SDK-conformant fetcher returns the
// cosigned horizon for a committed seq (PG-free), and refuses a seq at/beyond the
// horizon rather than fabricating a head.
func TestCheckpointFetcher_FetchCosignedHead(t *testing.T) {
	stub := &stubTileBackend{tiles: map[string][]byte{
		"cosigned-checkpoint": publishedCheckpoint(t, 100),
	}}
	f := NewCheckpointFetcher(NewTileBackendHorizon(stub), nil)

	head, err := f.FetchCosignedHead(context.Background(), 42)
	if err != nil {
		t.Fatalf("FetchCosignedHead(42): %v", err)
	}
	if head.TreeSize != 100 {
		t.Errorf("TreeSize = %d, want the cosigned horizon 100", head.TreeSize)
	}

	if _, err := f.FetchCosignedHead(context.Background(), 100); err == nil {
		t.Fatal("FetchCosignedHead(100) on a size-100 tree returned nil error; want 'not yet committed'")
	}
}
