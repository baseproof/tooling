package store

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/types"
)

// rotEl builds a representative self-proving rotation element committed at the given
// tree size (all four sub-parts populated, so round-trip fidelity is exercised).
func rotEl(committedAt uint64, tag byte) bundle.RotationElement {
	return bundle.RotationElement{
		Record:         []byte{tag, tag + 1, tag + 2},
		InclusionProof: types.MerkleProof{LeafPosition: uint64(tag), LeafHash: [32]byte{tag}, Siblings: [][32]byte{{tag + 1}}, TreeSize: committedAt},
		SMTProof:       types.SMTProof{Key: [32]byte{tag}, Siblings: [][32]byte{{tag + 2}}, BranchDepths: []uint16{uint16(tag)}, BranchPrefixes: [][32]byte{{tag + 3}}},
		CommittingHead: types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: committedAt, RootHash: [32]byte{tag, 0xAA}, ReceiptRoot: [32]byte{tag, 0xBB}}},
	}
}

// fakeRotationChainReader serves a fixed blob (or a miss).
type fakeRotationChainReader struct {
	blob []byte
	err  error
}

func (f fakeRotationChainReader) ReadRotationChain(context.Context) ([]byte, error) {
	return f.blob, f.err
}

// TestRotationChain_RoundTripFidelity: encode→decode preserves every field of every
// element (the archive is lossless — a survived proof stays a valid proof).
func TestRotationChain_RoundTripFidelity(t *testing.T) {
	chain := []bundle.RotationElement{rotEl(10, 0x10), rotEl(20, 0x20), rotEl(30, 0x30)}
	raw, err := encodeRotationChain(chain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeRotationChain(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(got, chain) {
		t.Fatal("round-trip lost or altered a rotation element field")
	}
}

// TestArchiveRotationChainFetcher_FiltersToAnchor: the SDK seam returns only
// rotations committed at or before asOfTreeSize (a later rotation is not part of the
// evolution the proof replays).
func TestArchiveRotationChainFetcher_FiltersToAnchor(t *testing.T) {
	chain := []bundle.RotationElement{rotEl(10, 0x10), rotEl(20, 0x20), rotEl(30, 0x30)}
	raw, _ := encodeRotationChain(chain)
	f := NewArchiveRotationChainFetcher(fakeRotationChainReader{blob: raw})

	got, err := f.FetchWitnessRotationChain(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].CommittingHead.TreeSize != 10 || got[1].CommittingHead.TreeSize != 20 {
		t.Fatalf("want rotations committed <=20 (sizes 10,20), got %d elements", len(got))
	}
	// asOf before the first rotation → empty.
	if early, _ := f.FetchWitnessRotationChain(context.Background(), 5); len(early) != 0 {
		t.Fatalf("want empty chain for anchor before first rotation, got %d", len(early))
	}
}

// TestArchiveRotationChainFetcher_NeverRotated: an archive miss is the common
// never-rotated case — the SDK's empty chain, NOT an error.
func TestArchiveRotationChainFetcher_NeverRotated(t *testing.T) {
	f := NewArchiveRotationChainFetcher(fakeRotationChainReader{err: os.ErrNotExist})
	got, err := f.FetchWitnessRotationChain(context.Background(), 100)
	if err != nil {
		t.Fatalf("never-rotated must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty chain, got %d", len(got))
	}
}

// TestArchiveRotationChainFetcher_Corruption: a damaged archive is an error, never
// silently treated as "no rotations".
func TestArchiveRotationChainFetcher_Corruption(t *testing.T) {
	if _, err := decodeRotationChain(nil); err == nil {
		t.Fatal("empty blob must be rejected")
	}
	if _, err := decodeRotationChain([]byte{0xFF, '[', ']'}); err == nil {
		t.Fatal("bad version must be rejected")
	}
	if _, err := decodeRotationChain([]byte{rotationArchiveVersion, '{', 'x'}); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}

// TestRotationChainArchiveWriter_WriteRead: what the writer PUTs is what the fetcher
// reads back, intact (write→read consistency over the standard object-store interface).
func TestRotationChainArchiveWriter_WriteRead(t *testing.T) {
	chain := []bundle.RotationElement{rotEl(10, 0x10), rotEl(20, 0x20)}
	put := &capturePutter{}
	if err := NewRotationChainArchiveWriter(put).ArchiveRotationChain(context.Background(), chain); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if put.key != rotationChainKey() {
		t.Fatalf("write key = %q, want %q", put.key, rotationChainKey())
	}
	f := NewArchiveRotationChainFetcher(fakeRotationChainReader{blob: put.body})
	got, err := f.FetchWitnessRotationChain(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, chain) {
		t.Fatal("written chain did not read back intact")
	}
}

// TestRotationChainArchiveWriter_NoOpWhenUnwired: a nil object store is a no-op
// (non-S3 deployments wire nil).
func TestRotationChainArchiveWriter_NoOpWhenUnwired(t *testing.T) {
	if err := NewRotationChainArchiveWriter(nil).ArchiveRotationChain(context.Background(), nil); err != nil {
		t.Fatalf("nil obj must be a no-op, got %v", err)
	}
}
