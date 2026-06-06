package store

import (
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

func rc(logDID string, seq uint64, b byte) smt.ReceiptCommitment {
	return smt.ReceiptCommitment{
		Position:    types.LogPosition{LogDID: logDID, Sequence: seq},
		ReceiptHash: [32]byte{b},
	}
}

// TestReceiptCommits_RoundTrip_ReconstructsRoot is the cryptographic crux: the
// archived commitment set reconstructs the EXACT ReceiptRoot the cosigned head
// commits, and an inclusion proof from the reconstructed set verifies against it.
func TestReceiptCommits_RoundTrip_ReconstructsRoot(t *testing.T) {
	const logDID = "did:web:log.example"
	commits := []smt.ReceiptCommitment{
		rc(logDID, 5, 0x11),
		rc(logDID, 6, 0x00), // zero-receipt entry (empty-set sentinel hash)
		rc(logDID, 7, 0x22),
	}
	want := smt.ReceiptRoot(commits)

	got, err := DecodeReceiptCommits(logDID, EncodeReceiptCommits(commits))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if smt.ReceiptRoot(got) != want {
		t.Fatal("archived commitment set reconstructs a DIFFERENT ReceiptRoot")
	}
	proof, err := smt.GenerateReceiptInclusionProof(got, types.LogPosition{LogDID: logDID, Sequence: 6})
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}
	if err := smt.VerifyReceiptInclusion(proof, want); err != nil {
		t.Fatalf("reconstructed inclusion proof fails against the cosigned root: %v", err)
	}
}

// TestReceiptCommits_OrderIndependent: a re-ordered archive reconstructs the same
// root (smt.ReceiptRoot sorts by (LogDID, Sequence)), so serialization order is
// not a correctness dependency.
func TestReceiptCommits_OrderIndependent(t *testing.T) {
	const logDID = "did:web:log.example"
	a := []smt.ReceiptCommitment{rc(logDID, 5, 1), rc(logDID, 6, 2), rc(logDID, 7, 3)}
	b := []smt.ReceiptCommitment{rc(logDID, 7, 3), rc(logDID, 5, 1), rc(logDID, 6, 2)}
	ra, _ := DecodeReceiptCommits(logDID, EncodeReceiptCommits(a))
	rb, _ := DecodeReceiptCommits(logDID, EncodeReceiptCommits(b))
	if smt.ReceiptRoot(ra) != smt.ReceiptRoot(rb) {
		t.Fatal("re-ordered archive reconstructs a different root")
	}
}

// TestReceiptCommits_DroppedCommitment_DiffersRoot is the +/- completeness guard:
// a set missing a commitment must NOT reconstruct the full root — proving the
// round-trip test is not trivially passing.
func TestReceiptCommits_DroppedCommitment_DiffersRoot(t *testing.T) {
	const logDID = "did:web:log.example"
	full := []smt.ReceiptCommitment{rc(logDID, 5, 1), rc(logDID, 6, 2), rc(logDID, 7, 3)}
	fullRoot := smt.ReceiptRoot(full)
	partial, _ := DecodeReceiptCommits(logDID, EncodeReceiptCommits(full[:2]))
	if smt.ReceiptRoot(partial) == fullRoot {
		t.Fatal("a set missing a commitment must NOT reconstruct the full root")
	}
}

// TestDecodeReceiptCommits_Corruption: corruption is rejected, never silently
// truncated into a wrong (but valid-looking) root.
func TestDecodeReceiptCommits_Corruption(t *testing.T) {
	const logDID = "did:web:log.example"
	good := EncodeReceiptCommits([]smt.ReceiptCommitment{rc(logDID, 5, 1)})

	if _, err := DecodeReceiptCommits(logDID, good[:len(good)-1]); err == nil {
		t.Fatal("truncated blob must be rejected")
	}
	bad := append([]byte{}, good...)
	bad[0] = 0xFF
	if _, err := DecodeReceiptCommits(logDID, bad); err == nil {
		t.Fatal("unsupported version must be rejected")
	}
	if _, err := DecodeReceiptCommits(logDID, nil); err == nil {
		t.Fatal("empty blob must be rejected")
	}
}
