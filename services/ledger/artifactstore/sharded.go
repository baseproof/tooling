/*
FILE PATH:

	artifactstore/sharded.go

DESCRIPTION:

	Phase 3 — sharded (large-artifact) push/fetch over the Store, delegating to
	the SDK's storage.PushSharded / storage.FetchSharded (the IPFS/UnixFS DAG).
	Large content (32 MB+ judicial PDFs) is split into fixed DefaultChunkSize
	chunks — each one ordinary ContentStore.Push — so nothing ever crosses a
	single push or HTTP body as one lump, and per-chunk + manifest verify-on-read
	holds on the way back.
*/
package artifactstore

import (
	"context"

	"github.com/baseproof/baseproof/storage"
)

// DefaultChunkSize is the fixed sharding chunk: 8 MiB. Above the S3 5 MiB
// multipart minimum, 1:1 part-mappable, and ~80 GB of headroom at the
// 10,000-part limit — far beyond the 32 MB PDF case. It is carried in the
// ContentManifest, so it is self-describing and can evolve without breaking old
// manifests.
const DefaultChunkSize uint32 = 8 << 20

// PushSharded chunks data at DefaultChunkSize, stores every chunk + a
// ContentManifest, and returns the manifest CID.
func (s *Store) PushSharded(ctx context.Context, data []byte) (storage.CID, error) {
	return storage.PushSharded(ctx, s, data, DefaultChunkSize, storage.AlgoSHA256)
}

// FetchSharded reassembles content addressed by a manifest CID, verifying the
// manifest and every chunk on read.
func (s *Store) FetchSharded(ctx context.Context, manifestCID storage.CID) ([]byte, error) {
	return storage.FetchSharded(ctx, s, manifestCID)
}
