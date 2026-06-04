/*
FILE PATH: tessera/leafhash.go

LeafHash — THE canonical leaf-data↔leaf-hash boundary.

The ledger keeps an entry's CANONICAL HASH (the leaf DATA) in the WAL
(seq_index) and the byte store, and appends that same 32-byte value to Tessera
via AppendLeaf. Tessera commits the RFC 6962 Merkle LEAF HASH of it —
H(0x00 || data) — in its level-0 tiles and Merkle tree.

These are two representations of the same entry. Any code that holds the leaf
DATA and needs to line it up with what Tessera committed (the integrity
WAL/Tessera detector; cross-log verifiers; a future re-verifier) MUST convert
through this one function. Re-deriving H(0x00||...) inline is precisely how the
integrity detector ended up comparing data against HashLeaf(data) and
false-positiving every cycle. Name it once; route everything through here.
*/
package tessera

import "github.com/transparency-dev/merkle/rfc6962"

// LeafHash returns the RFC 6962 Merkle leaf hash Tessera commits for the given
// leaf DATA: H(0x00 || data). This is the single source of the leaf-data →
// leaf-hash conversion across the ledger.
func LeafHash(data []byte) [32]byte {
	var out [32]byte
	copy(out[:], rfc6962.DefaultHasher.HashLeaf(data))
	return out
}
