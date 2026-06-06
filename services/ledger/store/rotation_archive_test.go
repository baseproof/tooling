package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"
)

// fakeRotationIndexReader serves a fixed index blob (or a miss).
type fakeRotationIndexReader struct {
	blob []byte
	err  error
}

func (f fakeRotationIndexReader) ReadRotationIndex(context.Context) ([]byte, error) {
	return f.blob, f.err
}

// fakeEntryBytes maps seq → canonical record bytes.
type fakeEntryBytes struct{ rec map[uint64][]byte }

func (f fakeEntryBytes) FetchEntryBytes(_ context.Context, seq uint64) ([]byte, time.Time, error) {
	return f.rec[seq], time.Time{}, nil
}

// fakeInclusion returns a proof anchored at the requested treeSize for leaf seq. It
// models the real generator: TreeSize=treeSize, LeafPosition=seq, LeafHash ZERO (the
// fetcher binds it from the record).
type fakeInclusion struct{}

func (fakeInclusion) FetchInclusionProof(_ context.Context, seq, treeSize uint64) (*types.MerkleProof, error) {
	return &types.MerkleProof{LeafPosition: seq, TreeSize: treeSize, Siblings: [][32]byte{{0xAB}}}, nil
}

// TestRotationIndex_RoundTrip: the index encodes/decodes losslessly.
func TestRotationIndex_RoundTrip(t *testing.T) {
	seqs := []uint64{7, 42, 1000}
	got, err := decodeRotationIndex(encodeRotationIndex(seqs))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 3 || got[0] != 7 || got[1] != 42 || got[2] != 1000 {
		t.Fatalf("round-trip altered the index: %v", got)
	}
}

// TestRotationChainFetcher_BindsToAnchorContract is the cryptographic crux: every
// rebuilt element satisfies witness.VerifyRotationInclusion's bindings AT the anchor
// — proof.TreeSize == asOfTreeSize, LeafHash == OnLogEntryLeafHash(record),
// LeafPosition == seq. (A fixed-chain archive could not do this for an arbitrary
// anchor — the reason 1.2b was reworked.)
func TestRotationChainFetcher_BindsToAnchorContract(t *testing.T) {
	const logDID = "did:web:log.example"
	recA, recB := []byte("rotation-A"), []byte("rotation-B")
	idx := encodeRotationIndex([]uint64{5, 9})
	f := NewArchiveRotationChainFetcher(
		fakeRotationIndexReader{blob: idx},
		fakeEntryBytes{rec: map[uint64][]byte{5: recA, 9: recB}},
		fakeInclusion{}, logDID)

	const anchor = 100
	chain, err := f.FetchWitnessRotationChain(context.Background(), anchor)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("want 2 elements, got %d", len(chain))
	}
	for i, want := range []struct {
		seq uint64
		rec []byte
	}{{5, recA}, {9, recB}} {
		el := chain[i]
		if el.InclusionProof.TreeSize != anchor {
			t.Fatalf("el[%d] proof.TreeSize %d != anchor %d", i, el.InclusionProof.TreeSize, anchor)
		}
		if el.InclusionProof.LeafPosition != want.seq {
			t.Fatalf("el[%d] proof.LeafPosition %d != seq %d", i, el.InclusionProof.LeafPosition, want.seq)
		}
		if el.InclusionProof.LeafHash != envelope.OnLogEntryLeafHash(want.rec) {
			t.Fatalf("el[%d] LeafHash not bound to the record", i)
		}
		if string(el.Record) != string(want.rec) {
			t.Fatalf("el[%d] record mismatch", i)
		}
	}
}

// TestRotationChainFetcher_ExcludesBeyondAnchor: a rotation at seq >= asOfTreeSize is
// not yet a leaf in that tree and must be excluded.
func TestRotationChainFetcher_ExcludesBeyondAnchor(t *testing.T) {
	const logDID = "did:web:log.example"
	idx := encodeRotationIndex([]uint64{5, 50, 200}) // 200 is beyond a size-100 tree
	f := NewArchiveRotationChainFetcher(
		fakeRotationIndexReader{blob: idx},
		fakeEntryBytes{rec: map[uint64][]byte{5: {1}, 50: {2}, 200: {3}}},
		fakeInclusion{}, logDID)
	chain, err := f.FetchWitnessRotationChain(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("want 2 (seqs 5,50; 200 excluded), got %d", len(chain))
	}
}

// TestRotationChainFetcher_NeverRotated: an index miss is the common never-rotated
// case — empty chain, not an error.
func TestRotationChainFetcher_NeverRotated(t *testing.T) {
	f := NewArchiveRotationChainFetcher(
		fakeRotationIndexReader{err: os.ErrNotExist}, fakeEntryBytes{}, fakeInclusion{}, "did:web:log.example")
	chain, err := f.FetchWitnessRotationChain(context.Background(), 100)
	if err != nil {
		t.Fatalf("never-rotated must not error: %v", err)
	}
	if len(chain) != 0 {
		t.Fatalf("want empty chain, got %d", len(chain))
	}
}

// TestRotationIndex_Corruption: a damaged index is an error, never silently empty.
func TestRotationIndex_Corruption(t *testing.T) {
	if _, err := decodeRotationIndex(nil); err == nil {
		t.Fatal("empty must be rejected")
	}
	if _, err := decodeRotationIndex([]byte{0xFF, 0, 0, 0, 0, 0, 0, 0, 1}); err == nil {
		t.Fatal("bad version must be rejected")
	}
	if _, err := decodeRotationIndex([]byte{rotationArchiveVersion, 0, 1, 2}); err == nil {
		t.Fatal("non-8-multiple body must be rejected")
	}
}

// TestRotationIndexArchiveWriter_WriteRead: the writer's index reads back identically,
// over the standard object-store interface.
func TestRotationIndexArchiveWriter_WriteRead(t *testing.T) {
	put := &capturePutter{}
	seqs := []uint64{5, 9}
	if err := NewRotationIndexArchiveWriter(put).ArchiveRotationIndex(context.Background(), seqs); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if put.key != rotationChainKey() {
		t.Fatalf("write key = %q, want %q", put.key, rotationChainKey())
	}
	got, err := decodeRotationIndex(put.body)
	if err != nil || len(got) != 2 || got[0] != 5 || got[1] != 9 {
		t.Fatalf("index did not read back: %v err=%v", got, err)
	}
}
