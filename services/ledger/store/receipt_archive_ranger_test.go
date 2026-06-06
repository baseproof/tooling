package store

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/types"
)

// fakeReceiptCommitReader serves pre-encoded commitment blobs by covering size.
type fakeReceiptCommitReader struct{ blobs map[uint64][]byte }

func (f *fakeReceiptCommitReader) ReadReceiptCommits(ctx context.Context, coveringSize uint64) ([]byte, error) {
	b, ok := f.blobs[coveringSize]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

// TestArchiveReceiptRanger_ReconstructsVerifiableProof: the archive ranger
// reconstructs the EXACT cosigned ReceiptRoot and an inclusion proof that verifies
// against it — PG-free, from object storage alone.
func TestArchiveReceiptRanger_ReconstructsVerifiableProof(t *testing.T) {
	const logDID = "did:web:log.example"
	// Checkpoint covering size 8 → receipt range [5,7].
	commits := []smt.ReceiptCommitment{rc(logDID, 5, 0x11), rc(logDID, 6, 0x22), rc(logDID, 7, 0x33)}
	want := smt.ReceiptRoot(commits)
	rg := NewArchiveReceiptRanger(
		&fakeReceiptCommitReader{blobs: map[uint64][]byte{8: EncodeReceiptCommits(commits)}}, logDID)

	got, err := rg.ReceiptRoot(context.Background(), 5, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("archive ReceiptRoot != cosigned ReceiptRoot")
	}
	proof, err := rg.ReceiptInclusionProof(context.Background(), 5, 7, 6)
	if err != nil {
		t.Fatal(err)
	}
	if err := smt.VerifyReceiptInclusion(proof, want); err != nil {
		t.Fatalf("archive proof fails against cosigned root: %v", err)
	}
}

// TestArchiveReceiptRanger_TargetAbsent: a target absent from the archived range is
// the honest negative (ErrReceiptLeafNotFound), not a fabricated proof.
func TestArchiveReceiptRanger_TargetAbsent(t *testing.T) {
	const logDID = "did:web:log.example"
	commits := []smt.ReceiptCommitment{rc(logDID, 5, 1), rc(logDID, 7, 3)} // no seq 6
	rg := NewArchiveReceiptRanger(
		&fakeReceiptCommitReader{blobs: map[uint64][]byte{8: EncodeReceiptCommits(commits)}}, logDID)
	if _, err := rg.ReceiptInclusionProof(context.Background(), 5, 7, 6); !errors.Is(err, smt.ErrReceiptLeafNotFound) {
		t.Fatalf("want ErrReceiptLeafNotFound, got %v", err)
	}
}

// TestArchiveReceiptRanger_ArchiveMissing: a never-archived checkpoint surfaces
// os.ErrNotExist (the caller degrades / 404s), never a wrong root.
func TestArchiveReceiptRanger_ArchiveMissing(t *testing.T) {
	rg := NewArchiveReceiptRanger(&fakeReceiptCommitReader{blobs: map[uint64][]byte{}}, "did:web:log.example")
	if _, err := rg.ReceiptInclusionProof(context.Background(), 5, 7, 6); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist, got %v", err)
	}
}

// TestArchiveReceiptRanger_FeedsSDKSection: SectionGatherer-seam conformance — the
// archive-derived proof feeds the SDK's EncodeReceiptProof to produce the
// receipt_proof section bytes PG-free (the exact output the v2 gather supplies).
func TestArchiveReceiptRanger_FeedsSDKSection(t *testing.T) {
	const logDID = "did:web:log.example"
	commits := []smt.ReceiptCommitment{rc(logDID, 5, 1), rc(logDID, 6, 2), rc(logDID, 7, 3)}
	rg := NewArchiveReceiptRanger(
		&fakeReceiptCommitReader{blobs: map[uint64][]byte{8: EncodeReceiptCommits(commits)}}, logDID)
	proof, err := rg.ReceiptInclusionProof(context.Background(), 5, 7, 6)
	if err != nil {
		t.Fatal(err)
	}
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{ReceiptRoot: smt.ReceiptRoot(commits), TreeSize: 8}}
	section, err := bundle.EncodeReceiptProof(proof, head)
	if err != nil {
		t.Fatalf("EncodeReceiptProof: %v", err)
	}
	if len(section) == 0 {
		t.Fatal("empty receipt_proof section")
	}
}
