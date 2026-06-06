package bytestore

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// The entry key must LEAD with the hash shard so writes spread across object-store
// partitions instead of hot-spotting a monotonic seq prefix.
func TestLayoutKey_ShardShape(t *testing.T) {
	hash := sha256.Sum256([]byte("entry"))
	key := layoutKey("entries", 0x81a, hash)

	want := fmt.Sprintf("entries/%02x/%016x/%x", hash[0], uint64(0x81a), hash[:])
	if key != want {
		t.Fatalf("layoutKey = %q, want %q", key, want)
	}
	parts := strings.Split(key, "/")
	if len(parts) != 4 {
		t.Fatalf("key %q: want 4 segments (prefix/shard/seq/hash), got %d", key, len(parts))
	}
	if parts[1] != fmt.Sprintf("%02x", hash[0]) {
		t.Errorf("shard segment = %q, want %02x (the hash lead byte)", parts[1], hash[0])
	}
}

// Distinct entries spread roughly uniformly across the 256 shard prefixes even
// when their SEQUENCES are perfectly sequential — the worst case for a
// seq-leading key. This is the property that keeps S3/GCS off a hot partition.
func TestLayoutKey_ShardsSpreadOverSequentialSeqs(t *testing.T) {
	const n = 4096
	shardCount := map[string]int{}
	for seq := uint64(0); seq < n; seq++ {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], seq)
		hash := sha256.Sum256(b[:]) // distinct, uniform content hash per entry
		shard := strings.Split(layoutKey("entries", seq, hash), "/")[1]
		shardCount[shard]++
	}
	// 4096 entries over 256 shards ⇒ essentially every shard appears. A
	// seq-leading key would instead produce 4096 lexically-adjacent prefixes
	// (one hot partition); the hash shard gives ~256 evenly-used prefixes.
	if len(shardCount) < 250 {
		t.Fatalf("only %d distinct shard prefixes for %d sequential entries — keys are not spreading",
			len(shardCount), n)
	}
	// Roughly uniform (mean ≈ 16/shard). No shard should hold a wildly
	// disproportionate share; 4× the mean is already very generous slack.
	maxPer := 0
	for _, c := range shardCount {
		if c > maxPer {
			maxPer = c
		}
	}
	if maxPer > 64 {
		t.Errorf("a shard holds %d of %d entries — distribution too skewed", maxPer, n)
	}
}

// The shard is independent of the sequence: the same content at two different
// seqs lands in the same shard, and adjacent seqs with different content land in
// (almost surely) different shards — so neighbours are not co-located.
func TestLayoutKey_ShardIsHashDerivedNotSeq(t *testing.T) {
	hash := sha256.Sum256([]byte("same-content"))
	s1 := strings.Split(layoutKey("entries", 1, hash), "/")[1]
	s2 := strings.Split(layoutKey("entries", 999999, hash), "/")[1]
	if s1 != s2 {
		t.Errorf("same hash gave different shards across seqs: %q vs %q", s1, s2)
	}
	if want := fmt.Sprintf("%02x", hash[0]); s1 != want {
		t.Errorf("shard = %q, want hash-derived %q", s1, want)
	}
}
