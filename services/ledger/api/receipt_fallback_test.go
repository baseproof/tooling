package api

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
)

type stubProver struct {
	proof  *smt.ReceiptInclusionProof
	err    error
	called *bool
}

func (s stubProver) ReceiptInclusionProof(ctx context.Context, fromSeq, toSeq, targetSeq uint64) (*smt.ReceiptInclusionProof, error) {
	if s.called != nil {
		*s.called = true
	}
	return s.proof, s.err
}

// TestFallbackReceiptProver_DegradesToArchive: a primary (PG) infrastructure error
// falls through to the archive, which serves the proof.
func TestFallbackReceiptProver_DegradesToArchive(t *testing.T) {
	want := &smt.ReceiptInclusionProof{}
	p := &FallbackReceiptProver{
		Primary:  stubProver{err: os.ErrNotExist}, // PG/infra failure
		Fallback: stubProver{proof: want},         // archive serves
	}
	got, err := p.ReceiptInclusionProof(context.Background(), 5, 7, 6)
	if err != nil {
		t.Fatalf("want fallback success, got %v", err)
	}
	if got != want {
		t.Fatal("did not return the archive proof")
	}
}

// TestFallbackReceiptProver_PreservesGenuineNotFound: a genuine "no receipt for this
// seq" is authoritative — the fallback must NOT be consulted (no masking).
func TestFallbackReceiptProver_PreservesGenuineNotFound(t *testing.T) {
	fbCalled := false
	p := &FallbackReceiptProver{
		Primary:  stubProver{err: smt.ErrReceiptLeafNotFound},
		Fallback: stubProver{proof: &smt.ReceiptInclusionProof{}, called: &fbCalled},
	}
	_, err := p.ReceiptInclusionProof(context.Background(), 5, 7, 6)
	if !errors.Is(err, smt.ErrReceiptLeafNotFound) {
		t.Fatalf("want ErrReceiptLeafNotFound, got %v", err)
	}
	if fbCalled {
		t.Fatal("fallback must NOT be consulted on a genuine not-found")
	}
}

// TestFallbackReceiptProver_BothFail: when both fail, both causes are visible
// (errors.Join) so operators see PG-down AND archive-miss.
func TestFallbackReceiptProver_BothFail(t *testing.T) {
	pgErr := errors.New("pg down")
	arErr := os.ErrNotExist
	p := &FallbackReceiptProver{
		Primary:  stubProver{err: pgErr},
		Fallback: stubProver{err: arErr},
	}
	_, err := p.ReceiptInclusionProof(context.Background(), 5, 7, 6)
	if !errors.Is(err, pgErr) || !errors.Is(err, arErr) {
		t.Fatalf("want joined error with both causes, got %v", err)
	}
}
