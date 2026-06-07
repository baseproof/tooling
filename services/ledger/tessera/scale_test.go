/*
FILE PATH: tessera/scale_test.go

At-scale, EXHAUSTIVE per-entry validation of the object-store proof substrate the
read front depends on: build a real embedded tessera tree of SCALE_N entries
(default 30000), ship every tile to an in-memory object store via TileShipper,
then for EVERY entry verify — from the OBJECT store alone, no POSIX —

 1. its RFC 6962 inclusion proof against the head root (the /v1/tree/inclusion
    path), and
 2. its entry-tile seq→hash matches the leaf that was appended (the /raw
    seq→hash fallback path).

This is the all-entries version of proof_adapter_test's sampled check: nothing is
spot-checked — all SCALE_N entries are proven, exercising the full tile delta the
shipper produced. Skipped under -short; run explicitly, e.g.:

	GOWORK=off go test ./tessera/ -run TestObjectStore_AllEntriesAtScale -timeout 40m
	SCALE_N=30000 GOWORK=off go test ./tessera/ -run TestObjectStore_AllEntriesAtScale -timeout 40m -v
*/
package tessera

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// scaleLeaf is the deterministic 32-byte leaf for index i (reproducible, no RNG).
func scaleLeaf(i int) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return sha256.Sum256(b[:])
}

func TestObjectStore_AllEntriesAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test: skipped under -short")
	}
	n := 30000
	if v := os.Getenv("SCALE_N"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 {
			n = x
		}
	}
	app, dir, _ := newTestEmbeddedAppender(t)
	ctx := context.Background()

	// 1. Append SCALE_N leaves CONCURRENTLY — AppendLeaf blocks until its entry
	//    integrates, so a serial loop is batch-latency bound; concurrency fills the
	//    batcher. Record the appender-assigned seq→leaf (seqs are assigned in
	//    sequencing order, not submission order) so verification binds each seq to
	//    the exact leaf the log stored at it.
	t0 := time.Now()
	var (
		mu        sync.Mutex
		seqLeaf   = make(map[uint64][32]byte, n)
		appendErr error
	)
	sem := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			ld := scaleLeaf(i)
			seq, err := app.AppendLeaf(ctx, ld[:])
			mu.Lock()
			if err != nil {
				if appendErr == nil {
					appendErr = err
				}
			} else {
				seqLeaf[seq] = ld
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if appendErr != nil {
		t.Fatalf("AppendLeaf: %v", appendErr)
	}
	if len(seqLeaf) != n {
		t.Fatalf("appended %d distinct seqs, want %d (seq collision?)", len(seqLeaf), n)
	}
	t.Logf("appended %d leaves in %s", n, time.Since(t0))

	// 2. Wait for Tessera to integrate all of them.
	deadline := time.Now().Add(25 * time.Minute)
	var head struct {
		TreeSize uint64
		RootHash [32]byte
	}
	for time.Now().Before(deadline) {
		if h, err := app.Head(); err == nil && h.TreeSize >= uint64(n) {
			head.TreeSize, head.RootHash = h.TreeSize, h.RootHash
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if head.TreeSize < uint64(n) {
		t.Fatalf("integration never reached tree_size=%d (got %d); dir=%s", n, head.TreeSize, dir)
	}
	t.Logf("integrated to tree_size=%d in %s", head.TreeSize, time.Since(t0))

	// 3. Ship EVERY tile to a fresh in-memory object store.
	posix, err := NewPOSIXTileBackend(dir)
	if err != nil {
		t.Fatalf("NewPOSIXTileBackend: %v", err)
	}
	obj := newFakeObjectStore()
	shipper, err := NewTileShipper(ctx, posix, obj, nil)
	if err != nil {
		t.Fatalf("NewTileShipper: %v", err)
	}
	tShip := time.Now()
	if err := shipper.ShipUpTo(ctx, head.TreeSize); err != nil {
		t.Fatalf("ShipUpTo(%d): %v", head.TreeSize, err)
	}
	t.Logf("shipped %d tile objects for %d entries in %s", len(obj.keys()), n, time.Since(tShip))

	// 4. Serve + verify ALL entries from the OBJECT store alone.
	objReader := NewTileReader(NewObjectTileBackend(obj), 8192)
	adapter := NewTesseraAdapter(ctx, app, objReader, nil)
	hasher := rfc6962.DefaultHasher

	tVerify := time.Now()
	for seq := uint64(0); seq < uint64(n); seq++ {
		// (1) inclusion proof verifies against the head root.
		raw, err := adapter.RawInclusionProof(seq, head.TreeSize)
		if err != nil {
			t.Fatalf("RawInclusionProof(seq=%d) from object store: %v", seq, err)
		}
		hexHashes, _ := raw.(map[string]any)["hashes"].([]string)
		siblings := make([][]byte, len(hexHashes))
		for j, h := range hexHashes {
			b, derr := hexDecodeFixed(h)
			if derr != nil {
				t.Fatalf("decode sibling for seq=%d: %v", seq, derr)
			}
			siblings[j] = b
		}
		ld := seqLeaf[seq]
		if err := proof.VerifyInclusion(hasher, seq, head.TreeSize, hasher.HashLeaf(ld[:]), siblings, head.RootHash[:]); err != nil {
			t.Fatalf("VerifyInclusion(seq=%d/%d) from OBJECT store: %v", seq, n, err)
		}

		// (2) entry-tile seq→hash matches the appended leaf.
		gotHash, found, herr := SeqHashFromEntryTile(ctx, objReader, head.TreeSize, seq)
		if herr != nil || !found {
			t.Fatalf("SeqHashFromEntryTile(seq=%d) = (found %v, err %v)", seq, found, herr)
		}
		if gotHash != ld {
			t.Fatalf("entry-tile seq→hash seq=%d: object %x != appended %x", seq, gotHash, ld)
		}

		if seq > 0 && seq%5000 == 0 {
			t.Logf("verified %d/%d entries (%s elapsed)", seq, n, time.Since(tVerify))
		}
	}
	t.Logf("PASS: all %d entries' inclusion + entry-tile seq→hash verified from the OBJECT store in %s (total %s)",
		n, time.Since(tVerify), time.Since(t0))
}
