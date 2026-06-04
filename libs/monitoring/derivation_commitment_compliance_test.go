package monitoring

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/smt"
	sdkmon "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

const dcLogDID = "did:web:ledger.example"

// fakeBulk is an in-memory CommitmentBulkFetcher with full control over the
// bytes returned (so tests can exercise the advancement-time integrity check,
// which a verify-on-read store would mask).
type fakeBulk map[string][]byte

func (f fakeBulk) Fetch(_ context.Context, cid storage.CID) ([]byte, error) {
	if b, ok := f[cid.String()]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("not found: %s", cid)
}

// buildRef constructs a self-consistent ref over `n` leaf mutations and stores
// its blob in bulk so the advancement path can fetch+decode it.
func buildRef(bulk fakeBulk, startSeq uint64, n int) storage.SMTDerivationCommitmentRef {
	muts := make([]types.LeafMutation, n)
	for i := range muts {
		muts[i] = types.LeafMutation{
			LeafKey:         [32]byte{byte(startSeq), byte(i)},
			NewOriginTip:    types.LogPosition{LogDID: dcLogDID, Sequence: startSeq + uint64(i)},
			NewAuthorityTip: types.LogPosition{LogDID: dcLogDID, Sequence: startSeq + uint64(i)},
		}
	}
	blob, _ := storage.MarshalCommitmentMutations(muts)
	cid := storage.Compute(blob)
	bulk[cid.String()] = blob
	return storage.SMTDerivationCommitmentRef{
		LogRangeStart: types.LogPosition{LogDID: dcLogDID, Sequence: startSeq},
		LogRangeEnd:   types.LogPosition{LogDID: dcLogDID, Sequence: startSeq + 9},
		MutationCount: uint32(n),
		MutationsCID:  cid,
		HashAlgo:      cid.Algorithm,
	}
}

// fakeCommitmentVerifier records each call (ref + the prior's leaf count at call time, to
// observe chaining) and returns a configured outcome per ref.
type fakeCommitmentVerifier struct {
	out map[string]struct {
		res *verifier.FraudProofResult
		err error
	}
	calls []struct {
		cid        string
		priorCount int
	}
}

func newFakeCommitmentVerifier() *fakeCommitmentVerifier {
	return &fakeCommitmentVerifier{out: map[string]struct {
		res *verifier.FraudProofResult
		err error
	}{}}
}

func (f *fakeCommitmentVerifier) valid(ref storage.SMTDerivationCommitmentRef) {
	f.out[ref.MutationsCID.String()] = struct {
		res *verifier.FraudProofResult
		err error
	}{res: &verifier.FraudProofResult{Valid: true}}
}

func (f *fakeCommitmentVerifier) outcome(ref storage.SMTDerivationCommitmentRef, res *verifier.FraudProofResult, err error) {
	f.out[ref.MutationsCID.String()] = struct {
		res *verifier.FraudProofResult
		err error
	}{res: res, err: err}
}

func (f *fakeCommitmentVerifier) fn(ctx context.Context, ref storage.SMTDerivationCommitmentRef, _ verifier.CommitmentBulkFetcher, prior smt.LeafStore, _ types.EntryFetcher, _ builder.SchemaResolver, _ string) (*verifier.FraudProofResult, error) {
	n, _ := prior.Count(ctx)
	f.calls = append(f.calls, struct {
		cid        string
		priorCount int
	}{ref.MutationsCID.String(), n})
	o := f.out[ref.MutationsCID.String()]
	return o.res, o.err
}

func runDC(cfg DerivationCommitmentComplianceConfig) []sdkmon.Alert {
	a, _ := CheckDerivationCommitmentCompliance(context.Background(), cfg, time.Unix(1000, 0))
	return a
}

func TestDerivationCommitment_EmptyRefs_NoOp(t *testing.T) {
	if a := runDC(DerivationCommitmentComplianceConfig{}); a != nil {
		t.Fatalf("no refs (unwired) must no-op, got %+v", a)
	}
}

func TestDerivationCommitment_NoBulkStore_Warning(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	a := runDC(DerivationCommitmentComplianceConfig{Refs: []storage.SMTDerivationCommitmentRef{ref}})
	if countSeverity(a, sdkmon.Warning) != 1 {
		t.Fatalf("refs without a content store must Warn once, got %+v", a)
	}
}

func TestDerivationCommitment_ValidCommitment_NoAlert(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 2)
	fv := newFakeCommitmentVerifier()
	fv.valid(ref)
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if len(a) != 0 {
		t.Fatalf("a valid commitment must raise no alerts, got %+v", a)
	}
}

func TestDerivationCommitment_NotValid_Critical(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	fv := newFakeCommitmentVerifier()
	// Five divergent leaves — also exercises the detail-cap in fraudDetails.
	proofs := make([]verifier.FraudProof, 5)
	for i := range proofs {
		proofs[i] = verifier.FraudProof{LeafKey: [32]byte{byte(i)}}
	}
	fv.outcome(ref, &verifier.FraudProofResult{Valid: false, Proofs: proofs}, nil)
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("a non-replaying commitment must raise one Critical, got %+v", a)
	}
}

// A verifier that returns (nil, nil) is treated as a non-Valid verdict (Critical),
// never silently passed.
func TestDerivationCommitment_NilResult_Critical(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	fv := newFakeCommitmentVerifier()
	fv.outcome(ref, nil, nil)
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("a nil verdict must be treated as Critical, got %+v", a)
	}
}

// A Valid commitment whose blob passes its digest but does not decode as
// mutations cannot advance the chain — a Warning.
func TestDerivationCommitment_AdvancementDecodeFailure_Warning(t *testing.T) {
	bulk := fakeBulk{}
	garbage := []byte("not-valid-mutation-bytes")
	cid := storage.Compute(garbage)
	bulk[cid.String()] = garbage
	ref := storage.SMTDerivationCommitmentRef{
		LogRangeStart: types.LogPosition{LogDID: dcLogDID, Sequence: 10},
		LogRangeEnd:   types.LogPosition{LogDID: dcLogDID, Sequence: 19},
		MutationCount: 1,
		MutationsCID:  cid,
		HashAlgo:      cid.Algorithm,
	}
	fv := newFakeCommitmentVerifier()
	fv.valid(ref)
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("advancement decode failure must Warn, got %+v", a)
	}
}

// A Valid commitment whose blob has gone missing at advancement time cannot
// advance — a Warning.
func TestDerivationCommitment_AdvancementFetchError_Warning(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	fv := newFakeCommitmentVerifier()
	fv.valid(ref)
	delete(bulk, ref.MutationsCID.String()) // blob disappears between verify and advance
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Warning) != 1 {
		t.Fatalf("advancement fetch error must Warn, got %+v", a)
	}
}

// errEntryFetcher fails every entry fetch (the verifier needs entries to replay).
type errEntryFetcher struct{}

func (errEntryFetcher) Fetch(_ context.Context, _ types.LogPosition) (*types.EntryWithMetadata, error) {
	return nil, errors.New("no entries available to replay")
}

// With Verify nil the monitor wires the real verifier.VerifyDerivationCommitmentRef.
// The off-log blob verifies, but the replay cannot fetch the range's entries —
// and the SDK verifier treats an unfetchable entry as an OMISSION (it skips it,
// per its "ledger may have omitted it" contract) rather than an error. The
// replay then reproduces none of the committed mutations, so it diverges from
// the claimed PostSMTRoot and the monitor surfaces a Critical. This pins the
// real verifier's wiring + behavior (the integration the SDK intended).
func TestDerivationCommitment_DefaultVerifierWired(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs:      []storage.SMTDerivationCommitmentRef{ref},
		BulkStore: bulk,
		Fetcher:   errEntryFetcher{},
		LogDID:    dcLogDID,
		// Verify left nil → real verifier.VerifyDerivationCommitmentRef.
	})
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("real verifier replay divergence must raise one Critical, got %+v", a)
	}
}

// A Valid commitment whose blob exceeds the size bound for its MutationCount
// cannot advance — a Warning.
func TestDerivationCommitment_AdvancementOversizeBlob_Warning(t *testing.T) {
	bulk := fakeBulk{}
	big := make([]byte, storage.MaxCommitmentMutationsBytes(0)+1)
	cid := storage.Compute(big)
	bulk[cid.String()] = big
	ref := storage.SMTDerivationCommitmentRef{
		LogRangeStart: types.LogPosition{LogDID: dcLogDID, Sequence: 10},
		LogRangeEnd:   types.LogPosition{LogDID: dcLogDID, Sequence: 19},
		MutationCount: 0,
		MutationsCID:  cid,
		HashAlgo:      cid.Algorithm,
	}
	fv := newFakeCommitmentVerifier()
	fv.valid(ref)
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Warning) != 1 {
		t.Fatalf("advancement oversize blob must Warn, got %+v", a)
	}
}

func TestDerivationCommitment_IntegrityViolation_Critical(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	fv := newFakeCommitmentVerifier()
	fv.outcome(ref, nil, fmt.Errorf("blob: %w", storage.ErrIntegrityViolation))
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("a MutationsCID integrity violation must raise one Critical, got %+v", a)
	}
}

func TestDerivationCommitment_InfraError_Warning(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	fv := newFakeCommitmentVerifier()
	fv.outcome(ref, nil, errors.New("entry fetcher unreachable"))
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("an infrastructure verify error must Warn (not Critical), got %+v", a)
	}
}

// The chained prior is built from genesis: after a Valid commitment its
// mutations are applied, so the NEXT ref's verification sees the advanced prior.
// Also proves ascending-range ordering regardless of input order.
func TestDerivationCommitment_ChainsPriorAcrossCommitments(t *testing.T) {
	bulk := fakeBulk{}
	ref1 := buildRef(bulk, 10, 2) // applies 2 leaves
	ref2 := buildRef(bulk, 20, 3)
	fv := newFakeCommitmentVerifier()
	fv.valid(ref1)
	fv.valid(ref2)

	// Supplied out of order; the monitor sorts by range before replaying.
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref2, ref1}, BulkStore: bulk, Verify: fv.fn,
	})
	if len(a) != 0 {
		t.Fatalf("two valid commitments must raise no alerts, got %+v", a)
	}
	if len(fv.calls) != 2 {
		t.Fatalf("want 2 verify calls, got %d", len(fv.calls))
	}
	// ref1 verified first against an empty prior; ref2 against the prior advanced
	// by ref1's 2 mutations.
	if fv.calls[0].cid != ref1.MutationsCID.String() || fv.calls[0].priorCount != 0 {
		t.Errorf("first call should be ref1 with empty prior; got %+v", fv.calls[0])
	}
	if fv.calls[1].cid != ref2.MutationsCID.String() || fv.calls[1].priorCount != 2 {
		t.Errorf("second call should be ref2 with prior advanced to 2 leaves; got %+v", fv.calls[1])
	}
}

// A Valid commitment whose blob no longer matches its MutationsCID at
// advancement time cannot advance the chain — a Warning, never a false fraud
// Critical.
func TestDerivationCommitment_AdvancementIntegrityFailure_Warning(t *testing.T) {
	bulk := fakeBulk{}
	ref := buildRef(bulk, 10, 1)
	// Corrupt the stored blob so applyCommittedMutations' digest check fails.
	bulk[ref.MutationsCID.String()] = []byte("tampered-after-the-fact")
	fv := newFakeCommitmentVerifier()
	fv.valid(ref)
	a := runDC(DerivationCommitmentComplianceConfig{
		Refs: []storage.SMTDerivationCommitmentRef{ref}, BulkStore: bulk, Verify: fv.fn,
	})
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("an advancement-time integrity failure must Warn (not Critical), got %+v", a)
	}
}
