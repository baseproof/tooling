/*
FILE PATH:

	tessera/entry_reader.go

DESCRIPTION:

	Tessera tile-format helpers retained in the tessera package after
	the byte store was relocated to bytestore/. Wire bytes (entry
	payloads) are no longer this file's concern — see bytestore/ for
	the EntryReader / EntryWriter / Memory / GCS surface.

	What stays here:
	  - EntriesPerTile constant (shard lifecycle, archive reader).
	  - ParseEntryBundle (c2sp.org/tlog-tiles tile body parser, used
	    by the archive reader and proof adapter).

	Everything else moved to bytestore/ in Phase D of the
	WAL/Shipper alignment series.
*/
package tessera

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// EntriesPerTile is the number of entries packed into a single
// Tessera tile. Used by shard lifecycle and the archive reader.
const EntriesPerTile = 256

// ParseEntryBundle extracts the raw data blob for entry at `offset`
// within a Tessera entry tile. The tile format is:
//
//	[uint16 big-endian length][data bytes] × N
//
// With hash-only tiles, each entry is exactly 32 bytes (SHA-256 hash).
// Used by lifecycle/archive_reader.go for frozen shards and by
// proof_adapter.go for hash extraction during proof computation.
//
// Returns the data bytes for the entry at the given offset (0-indexed).
func ParseEntryBundle(tileData []byte, offset uint64) ([]byte, error) {
	pos := 0
	for i := uint64(0); i <= offset; i++ {
		if pos+2 > len(tileData) {
			return nil, fmt.Errorf("tessera/entry_reader: tile truncated at entry %d (need length prefix at byte %d, tile is %d bytes)",
				i, pos, len(tileData))
		}
		entryLen := int(binary.BigEndian.Uint16(tileData[pos : pos+2]))
		pos += 2
		if pos+entryLen > len(tileData) {
			return nil, fmt.Errorf("tessera/entry_reader: tile truncated at entry %d (need %d bytes at offset %d, tile is %d bytes)",
				i, entryLen, pos, len(tileData))
		}
		if i == offset {
			return tileData[pos : pos+entryLen], nil
		}
		pos += entryLen
	}
	return nil, fmt.Errorf("tessera/entry_reader: offset %d not found in tile", offset)
}

// SeqHashFromEntryTile resolves a leaf sequence to its 32-byte canonical hash
// (envelope.EntryIdentity) by reading the entry tile from the object store —
// no Postgres. treeSize (the cosigned horizon) bounds the lookup (seq >=
// treeSize → found=false, a genuine not-found rather than an error) and fixes
// the frontier bundle's partial width so the last, not-yet-full bundle is read
// from its tile/entries/<N>.p/<w> path. Earlier (full) bundles use width 0 →
// the full tile/entries/<N> path.
//
// Used by the PG-off read front so GET /v1/entries/{seq}/raw resolves seq→hash
// without the entry_index table: the reader serves the bytes via a bytestore
// redirect keyed on (seq, hash).
func SeqHashFromEntryTile(ctx context.Context, tr *TileReader, treeSize, seq uint64) (hash [32]byte, found bool, err error) {
	if tr == nil {
		return hash, false, fmt.Errorf("tessera/entry_reader: nil TileReader")
	}
	if seq >= treeSize {
		return hash, false, nil
	}

	bundleIndex := seq / EntriesPerTile
	offset := seq % EntriesPerTile

	// The frontier bundle (the one holding the horizon's last leaf) is partial
	// when treeSize is not a multiple of EntriesPerTile; FetchEntryBundle needs
	// its width to locate the tile/entries/<N>.p/<w> object. Every earlier
	// bundle is full → width 0.
	var width uint8
	if bundleIndex == treeSize/EntriesPerTile {
		width = uint8(treeSize % EntriesPerTile)
	}

	data, err := tr.FetchEntryBundle(ctx, bundleIndex, width)
	if err != nil {
		return hash, false, fmt.Errorf("tessera/entry_reader: read entry bundle %d: %w", bundleIndex, err)
	}
	leaf, err := ParseEntryBundle(data, offset)
	if err != nil {
		return hash, false, fmt.Errorf("tessera/entry_reader: parse entry bundle %d offset %d: %w", bundleIndex, offset, err)
	}
	if len(leaf) != sha256.Size {
		return hash, false, fmt.Errorf("tessera/entry_reader: entry-tile leaf at seq %d is %d bytes, want %d (hash-only tile expected)",
			seq, len(leaf), sha256.Size)
	}
	copy(hash[:], leaf)
	return hash, true, nil
}
