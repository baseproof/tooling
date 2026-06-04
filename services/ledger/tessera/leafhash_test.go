package tessera

import (
	"crypto/sha256"
	"testing"
)

// TestLeafHash pins THE leaf-data↔leaf-hash boundary against an INDEPENDENT
// computation: the RFC 6962 Merkle leaf hash is H(0x00 || data). Every consumer
// that compares leaf DATA (WAL/byte store) to what Tessera committed (tiles)
// routes through LeafHash; this test fixes that contract so it can't drift.
func TestLeafHash(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("hello"),
		make([]byte, 32), // a 32-byte canonical hash (the real leaf-data shape)
	} {
		want := sha256.Sum256(append([]byte{0x00}, data...))
		if got := LeafHash(data); got != want {
			t.Errorf("LeafHash(%x) = %x, want H(0x00||data) = %x", data, got, want)
		}
	}
}
