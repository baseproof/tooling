package tessera

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
)

// fakeEntryTileBackend is a path-agnostic TileBackend: it returns the one
// configured bundle for any requested path (so the FetchEntryBundle partial/full
// path selection is exercised without the test pinning exact tile paths), or an
// os.ErrNotExist when miss is set (to drive the read-failure branch).
type fakeEntryTileBackend struct {
	bundle []byte
	miss   bool
}

func (f *fakeEntryTileBackend) ReadTileByPath(context.Context, string) ([]byte, error) {
	if f.miss {
		return nil, os.ErrNotExist
	}
	return f.bundle, nil
}

// hashBundle encodes hashes in the c2sp.org/tlog-tiles entry-bundle wire format
// ([uint16 big-endian length][data] × N) that ParseEntryBundle reads.
func hashBundle(hashes [][32]byte) []byte {
	var buf, lp []byte
	lp = make([]byte, 2)
	for _, h := range hashes {
		binary.BigEndian.PutUint16(lp, uint16(len(h)))
		buf = append(buf, lp...)
		buf = append(buf, h[:]...)
	}
	return buf
}

// TestSeqHashFromEntryTile_ResolvesEachOffset is the core +/- for 1.3d: every
// seq in the tree resolves to the exact 32-byte hash stored at its offset in the
// entry tile — no Postgres involved.
func TestSeqHashFromEntryTile_ResolvesEachOffset(t *testing.T) {
	var hashes [][32]byte
	for i := 0; i < 5; i++ {
		var h [32]byte
		h[0], h[31] = byte(i+1), byte(0xA0+i)
		hashes = append(hashes, h)
	}
	tr := NewTileReader(&fakeEntryTileBackend{bundle: hashBundle(hashes)}, 8)
	const treeSize = 5 // bundle 0 is the frontier, partial width 5

	for seq := uint64(0); seq < treeSize; seq++ {
		got, found, err := SeqHashFromEntryTile(context.Background(), tr, treeSize, seq)
		if err != nil || !found {
			t.Fatalf("seq %d: found=%v err=%v; want a resolved hash", seq, found, err)
		}
		if got != hashes[seq] {
			t.Fatalf("seq %d: got %x…, want %x…", seq, got[:4], hashes[seq][:4])
		}
	}
}

// TestSeqHashFromEntryTile_BeyondHorizon_NotFound — seq at/after treeSize is a
// genuine not-found (no error) and must not touch the backend.
func TestSeqHashFromEntryTile_BeyondHorizon_NotFound(t *testing.T) {
	tr := NewTileReader(&fakeEntryTileBackend{miss: true, bundle: hashBundle([][32]byte{{1}})}, 8)
	for _, seq := range []uint64{1, 2, 99} {
		got, found, err := SeqHashFromEntryTile(context.Background(), tr, 1, seq)
		if err != nil || found || got != [32]byte{} {
			t.Fatalf("seq %d beyond horizon=1: want (zero,false,nil), got (%x…,%v,%v)", seq, got[:4], found, err)
		}
	}
}

// TestSeqHashFromEntryTile_BundleMissing_Errors — a seq within the horizon whose
// bundle is unreadable is a transport error, not a not-found.
func TestSeqHashFromEntryTile_BundleMissing_Errors(t *testing.T) {
	tr := NewTileReader(&fakeEntryTileBackend{miss: true}, 8)
	if _, found, err := SeqHashFromEntryTile(context.Background(), tr, 10, 3); err == nil || found {
		t.Fatalf("missing bundle: want (found=false, error), got found=%v err=%v", found, err)
	}
}

// TestSeqHashFromEntryTile_NonHashLeaf_Errors — the resolver is hash-only-tile
// specific; a leaf that isn't 32 bytes is rejected rather than silently truncated
// or padded into a bogus hash.
func TestSeqHashFromEntryTile_NonHashLeaf_Errors(t *testing.T) {
	lp := make([]byte, 2)
	binary.BigEndian.PutUint16(lp, 16) // 16-byte leaf, not 32
	bundle := append(lp, make([]byte, 16)...)
	tr := NewTileReader(&fakeEntryTileBackend{bundle: bundle}, 8)
	if _, found, err := SeqHashFromEntryTile(context.Background(), tr, 1, 0); err == nil || found {
		t.Fatalf("16-byte leaf: want (found=false, error), got found=%v err=%v", found, err)
	}
}
