package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/apitypes"
)

type fakeReceiptHeads struct {
	atOrAbove func(min uint64) (uint64, bool)
	below     func(size uint64) (uint64, bool)
	head      *apitypes.CosignedTreeHead
}

func (f *fakeReceiptHeads) CosignedSizeAtOrAbove(_ context.Context, min uint64, _ int) (uint64, bool, error) {
	s, ok := f.atOrAbove(min)
	return s, ok, nil
}
func (f *fakeReceiptHeads) CosignedSizeBelow(_ context.Context, size uint64, _ int) (uint64, bool, error) {
	s, ok := f.below(size)
	return s, ok, nil
}
func (f *fakeReceiptHeads) GetBySize(_ context.Context, _ uint64) (*apitypes.CosignedTreeHead, error) {
	return f.head, nil
}

type fakeReceiptProver struct {
	proof          *smt.ReceiptInclusionProof
	err            error
	from, to, targ uint64
}

func (f *fakeReceiptProver) ReceiptInclusionProof(_ context.Context, from, to, target uint64) (*smt.ReceiptInclusionProof, error) {
	f.from, f.to, f.targ = from, to, target
	return f.proof, f.err
}

func receiptReq(seq string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/receipt/proof/"+seq, nil)
	r.SetPathValue("seq", seq)
	return r
}

// Happy path: the handler resolves the first covering checkpoint (size 10, prev
// 5 ⇒ receipt range [5,9]), builds the proof for seq 6, and returns the v2
// receipt_proof section + the cosigned head it binds to.
func TestReceiptProofHandler_HappyPath(t *testing.T) {
	const logDID = "did:web:receipt.test"
	commits := []smt.ReceiptCommitment{
		{Position: types.LogPosition{LogDID: logDID, Sequence: 5}, ReceiptHash: sha256.Sum256([]byte("r5"))},
		{Position: types.LogPosition{LogDID: logDID, Sequence: 6}, ReceiptHash: sha256.Sum256([]byte("r6"))},
		{Position: types.LogPosition{LogDID: logDID, Sequence: 7}, ReceiptHash: sha256.Sum256([]byte("r7"))},
	}
	root := smt.ReceiptRoot(commits)
	proof, err := smt.GenerateReceiptInclusionProof(commits, types.LogPosition{LogDID: logDID, Sequence: 6})
	if err != nil {
		t.Fatal(err)
	}
	if err := smt.VerifyReceiptInclusion(proof, root); err != nil {
		t.Fatalf("sanity: %v", err)
	}

	prover := &fakeReceiptProver{proof: proof}
	heads := &fakeReceiptHeads{
		atOrAbove: func(min uint64) (uint64, bool) { return 10, true }, // first covering checkpoint
		below:     func(uint64) (uint64, bool) { return 5, true },      // prev checkpoint ⇒ range [5,9]
		head:      &apitypes.CosignedTreeHead{TreeSize: 10, ReceiptRoot: root},
	}
	h := NewReceiptProofHandler(&ReceiptDeps{Heads: heads, Receipts: prover, MinSigs: 2})

	rec := httptest.NewRecorder()
	h(rec, receiptReq("6"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if prover.from != 5 || prover.to != 9 || prover.targ != 6 {
		t.Fatalf("range = [%d,%d] target %d, want [5,9] target 6", prover.from, prover.to, prover.targ)
	}
	var resp struct {
		ReceiptProof json.RawMessage           `json:"receipt_proof"`
		Checkpoint   apitypes.CosignedTreeHead `json:"checkpoint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.ReceiptProof) == 0 || string(resp.ReceiptProof) == "null" {
		t.Error("receipt_proof section empty")
	}
	if resp.Checkpoint.TreeSize != 10 {
		t.Errorf("checkpoint tree_size = %d, want 10", resp.Checkpoint.TreeSize)
	}
}

// No cosigned checkpoint covers the seq yet ⇒ 404.
func TestReceiptProofHandler_NoCoveringCheckpoint(t *testing.T) {
	heads := &fakeReceiptHeads{
		atOrAbove: func(uint64) (uint64, bool) { return 0, false },
		below:     func(uint64) (uint64, bool) { return 0, false },
	}
	h := NewReceiptProofHandler(&ReceiptDeps{Heads: heads, Receipts: &fakeReceiptProver{}, MinSigs: 2})
	rec := httptest.NewRecorder()
	h(rec, receiptReq("42"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// The seq is a gap (no receipt committed) ⇒ smt.ErrReceiptLeafNotFound ⇒ 404.
func TestReceiptProofHandler_GapNotFound(t *testing.T) {
	heads := &fakeReceiptHeads{
		atOrAbove: func(uint64) (uint64, bool) { return 10, true },
		below:     func(uint64) (uint64, bool) { return 5, true },
		head:      &apitypes.CosignedTreeHead{TreeSize: 10},
	}
	prover := &fakeReceiptProver{err: smt.ErrReceiptLeafNotFound}
	h := NewReceiptProofHandler(&ReceiptDeps{Heads: heads, Receipts: prover, MinSigs: 2})
	rec := httptest.NewRecorder()
	h(rec, receiptReq("3"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// A non-numeric seq ⇒ 400.
func TestReceiptProofHandler_BadSeq(t *testing.T) {
	h := NewReceiptProofHandler(&ReceiptDeps{Heads: &fakeReceiptHeads{}, Receipts: &fakeReceiptProver{}, MinSigs: 2})
	rec := httptest.NewRecorder()
	h(rec, receiptReq("notanumber"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
