package store

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
)

// stubGatherer serves a fixed commitment set (no PG).
type stubGatherer struct {
	commits []smt.ReceiptCommitment
	err     error
}

func (s stubGatherer) commitsInRange(_ context.Context, _, _ uint64) ([]smt.ReceiptCommitment, error) {
	return s.commits, s.err
}

// capturePutter records the last PutObject (key, body) and never reads.
type capturePutter struct {
	key  string
	body []byte
	err  error
}

func (c *capturePutter) PutObject(_ context.Context, key string, body []byte) error {
	c.key, c.body = key, body
	return c.err
}
func (c *capturePutter) GetObject(context.Context, string) ([]byte, error) { return nil, nil }
func (c *capturePutter) HeadObject(context.Context, string) (bool, error)  { return false, nil }

// TestReceiptArchiveWriter_WriteReadConsistency is the end-to-end archive loop: what
// the writer PUTs at receipts/<coveringSize> is exactly what the ArchiveReceiptRanger
// reads back to reconstruct the IDENTICAL cosigned ReceiptRoot — keys and bytes
// agree, PG-free.
func TestReceiptArchiveWriter_WriteReadConsistency(t *testing.T) {
	const logDID = "did:web:log.example"
	commits := []smt.ReceiptCommitment{rc(logDID, 5, 0x11), rc(logDID, 6, 0x22), rc(logDID, 7, 0x33)}
	want := smt.ReceiptRoot(commits)

	put := &capturePutter{}
	w := &ReceiptArchiveWriter{ranger: stubGatherer{commits: commits}, obj: put}

	// Covering size 8 → receipt range [5,7] (the loop passes treeSize, lastSize, cSeq).
	if err := w.ArchiveReceiptCommits(context.Background(), 8, 5, 7); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if put.key != receiptArchiveKey(8) {
		t.Fatalf("write key = %q, want %q", put.key, receiptArchiveKey(8))
	}

	// Read the written bytes back through the ranger's reader at the SAME covering
	// size and reconstruct — must equal the cosigned root.
	reader := &fakeReceiptCommitReader{blobs: map[uint64][]byte{8: put.body}}
	got, err := NewArchiveReceiptRanger(reader, logDID).ReceiptRoot(context.Background(), 5, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("written archive reconstructs a DIFFERENT ReceiptRoot than the cosigned set")
	}
}

// TestReceiptArchiveWriter_NoOpWhenUnwired: a nil ranger/obj makes archiving a
// no-op (the composition root wires it unconditionally; non-S3 deployments pass nil).
func TestReceiptArchiveWriter_NoOpWhenUnwired(t *testing.T) {
	if err := NewReceiptArchiveWriter(nil, &capturePutter{}).ArchiveReceiptCommits(context.Background(), 8, 5, 7); err != nil {
		t.Fatalf("nil ranger must be a no-op, got %v", err)
	}
}

// TestReceiptArchiveWriter_PutErrorPropagates: a put error is returned (the loop
// withholds the horizon on it — fail-closed) — and a gather error short-circuits
// before any write.
func TestReceiptArchiveWriter_PutErrorPropagates(t *testing.T) {
	w := &ReceiptArchiveWriter{ranger: stubGatherer{commits: nil}, obj: &capturePutter{err: errors.New("s3 down")}}
	if err := w.ArchiveReceiptCommits(context.Background(), 8, 5, 7); err == nil {
		t.Fatal("put error must propagate")
	}
	g := &ReceiptArchiveWriter{ranger: stubGatherer{err: errors.New("pg down")}, obj: &capturePutter{}}
	if err := g.ArchiveReceiptCommits(context.Background(), 8, 5, 7); err == nil {
		t.Fatal("gather error must propagate")
	}
}
