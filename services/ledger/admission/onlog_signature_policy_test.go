/*
FILE PATH: admission/onlog_signature_policy_test.go

Tests for the Part II.6 part 2 amendment-aware
SignaturePolicyResolver. In-memory fixtures only — no DB, no I/O —
so they run in every `go test ./...` invocation without DSN gating.

Coverage matches the file's documented contract:

  - Constructor validation (nil source, nil sizes, empty logDID,
    malformed bootstrap).
  - Genesis-only path (no amendments) returns the bootstrap policy.
  - Amendment-present path returns the amendment policy at current
    tree size (asOf == tree_size, inclusive boundary).
  - Amendment at a FUTURE position is not yet in effect.
  - Source error propagates as ErrSignaturePolicyResolverFailed.
  - TreeSize error propagates as ErrSignaturePolicyResolverFailed.
  - RequireHybridAfter pre-deadline → no MinSigsFromSchemeGroup.
  - RequireHybridAfter post-deadline → MinSigsFromSchemeGroup["pq"]=1.
  - RequireHybridAfter elapsed but no PQ algos admitted → Validate
    error surfaces as ErrSignaturePolicyResolverFailed.
  - TTL cache: source called once across N rapid Currents.
  - Tree size 0 (empty log) → genesis in effect.
  - Records returned by source are decoupled from sort order.
*/
package admission_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// ─────────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────────

// signaturePolicyBootstrap returns a minimal BootstrapDocument whose
// GenesisSignaturePolicy is valid. `hybridAfter == nil` (no PQ
// requirement) is the common case; tests that exercise the
// hybrid-after path pass a non-nil pointer.
func signaturePolicyBootstrap(
	t *testing.T,
	allowed []uint16,
	minSigs uint8,
	hybridAfter *int64,
) network.BootstrapDocument {
	t.Helper()
	return network.BootstrapDocument{
		ProtocolVersion:             "1",
		ExchangeDID:                 "did:web:test.example",
		NetworkName:                 "test-net-onlog-sigpolicy",
		GenesisWitnessSet:           []string{"did:key:zwitness1"},
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: "0101010101010101010101010101010101010101010101010101010101010101"},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: true, CostMode: "uncharged",
		},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  allowed,
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   minSigs,
			RequireHybridAfter:      hybridAfter,
		},
	}
}

const testLogDID = "did:web:onlog-sigpolicy.test"

// fakeSizeProvider implements TreeSizeProvider with a stored value
// (and optional injected error).
type fakeSizeProvider struct {
	size uint64
	err  error
}

func (f *fakeSizeProvider) LatestTreeSize(context.Context) (uint64, error) {
	return f.size, f.err
}

// amendmentRecord builds an unsorted slice of SignaturePolicyRecord for
// a given (pos, minSigs) sequence — handy for table-driven tests.
func amendmentRecord(seq uint64, allowed []uint16, minSigs uint8) network.SignaturePolicyRecord {
	return network.SignaturePolicyRecord{
		EffectivePos: types.LogPosition{LogDID: testLogDID, Sequence: seq},
		Policy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  allowed,
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   minSigs,
		},
	}
}

// ─────────────────────────────────────────────────────────────────────
// Constructor validation
// ─────────────────────────────────────────────────────────────────────

func TestNewOnLogSignaturePolicyResolver_RejectsNilSource(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	_, err := admission.NewOnLogSignaturePolicyResolver(
		nil, &fakeSizeProvider{}, doc, testLogDID, [32]byte{}, 0,
	)
	if err == nil {
		t.Fatal("nil source must be rejected")
	}
}

func TestNewOnLogSignaturePolicyResolver_RejectsNilSizes(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	_, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		nil, doc, testLogDID, [32]byte{}, 0,
	)
	if err == nil {
		t.Fatal("nil sizes must be rejected")
	}
}

func TestNewOnLogSignaturePolicyResolver_RejectsEmptyLogDID(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	_, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{}, doc, "", [32]byte{}, 0,
	)
	if err == nil {
		t.Fatal("empty logDID must be rejected")
	}
}

func TestNewOnLogSignaturePolicyResolver_RejectsMalformedBootstrap(t *testing.T) {
	// MinSignaturesPerEntry = 0 is invalid; the construction MUST fail
	// before any admission cycle runs.
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 0, nil)
	_, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{}, doc, testLogDID, [32]byte{}, 0,
	)
	if err == nil {
		t.Fatal("malformed bootstrap (MinValidSigs=0) must be rejected at construction")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Genesis-only path (no amendments)
// ─────────────────────────────────────────────────────────────────────

func TestOnLogSignaturePolicyResolver_NoAmendments_ReturnsGenesis(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 2, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{0xCA}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, allowed, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if policy.MinValidSigs != 2 {
		t.Errorf("MinValidSigs = %d, want 2 (genesis)", policy.MinValidSigs)
	}
	if _, ok := allowed[envelope.SigAlgoECDSA]; !ok {
		t.Errorf("allowed-set missing SigAlgoECDSA")
	}
	if len(policy.MinSigsFromSchemeGroup) != 0 {
		t.Errorf("genesis without RequireHybridAfter must not require PQ; got %+v",
			policy.MinSigsFromSchemeGroup)
	}
}

// Tree size 0 (empty log) → genesis applies. The asOf is pos(0), which
// equals the genesis record's own EffectivePos (inclusive).
func TestOnLogSignaturePolicyResolver_TreeSizeZero_GenesisApplies(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{size: 0}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current at tree_size=0: %v", err)
	}
	if policy.MinValidSigs != 1 {
		t.Errorf("MinValidSigs = %d, want 1 (genesis at empty log)", policy.MinValidSigs)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Amendment in effect (at-or-before current tree size)
// ─────────────────────────────────────────────────────────────────────

func TestOnLogSignaturePolicyResolver_Amendment_TakesEffect(t *testing.T) {
	// Genesis = MinValidSigs=1; amendment at pos(50) = MinValidSigs=3.
	// Current tree size = 100 → amendment in effect.
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) {
			return []network.SignaturePolicyRecord{
				amendmentRecord(50, []uint16{envelope.SigAlgoECDSA}, 3),
			}, nil
		},
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if policy.MinValidSigs != 3 {
		t.Errorf("MinValidSigs = %d, want 3 (amendment in effect)", policy.MinValidSigs)
	}
}

func TestOnLogSignaturePolicyResolver_Amendment_AtBoundary_Inclusive(t *testing.T) {
	// asOf == amendment EffectivePos → amendment IS in effect
	// (inclusive boundary, per SDK signature_policy walker contract).
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) {
			return []network.SignaturePolicyRecord{
				amendmentRecord(50, []uint16{envelope.SigAlgoECDSA}, 4),
			}, nil
		},
		&fakeSizeProvider{size: 50}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current at tree_size=50: %v", err)
	}
	if policy.MinValidSigs != 4 {
		t.Errorf("MinValidSigs = %d, want 4 (amendment at asOf == EffectivePos, inclusive)",
			policy.MinValidSigs)
	}
}

// Amendment at a FUTURE position is not in effect at current tree size.
func TestOnLogSignaturePolicyResolver_FutureAmendment_NotYetInEffect(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) {
			// Amendment scheduled for pos(500). Current tree size = 100.
			return []network.SignaturePolicyRecord{
				amendmentRecord(500, []uint16{envelope.SigAlgoECDSA}, 9),
			}, nil
		},
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if policy.MinValidSigs != 1 {
		t.Errorf("MinValidSigs = %d, want 1 (genesis; future amendment not yet in effect)",
			policy.MinValidSigs)
	}
}

// Multiple amendments in arbitrary order — the resolver sorts and
// picks the most recent at-or-before asOf.
func TestOnLogSignaturePolicyResolver_MultipleAmendments_PicksLatest(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) {
			// Deliberately out-of-order.
			return []network.SignaturePolicyRecord{
				amendmentRecord(200, []uint16{envelope.SigAlgoECDSA}, 4),
				amendmentRecord(50, []uint16{envelope.SigAlgoECDSA}, 2),
				amendmentRecord(100, []uint16{envelope.SigAlgoECDSA}, 3),
			}, nil
		},
		&fakeSizeProvider{size: 150}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if policy.MinValidSigs != 3 {
		t.Errorf("MinValidSigs = %d, want 3 (amendment at pos(100) is most recent ≤ 150)",
			policy.MinValidSigs)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Error propagation
// ─────────────────────────────────────────────────────────────────────

func TestOnLogSignaturePolicyResolver_SourceError_RoutesToResolverFailure(t *testing.T) {
	boom := errors.New("query api unavailable")
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, boom },
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	_, _, err = r.Current(context.Background())
	if !errors.Is(err, admission.ErrSignaturePolicyResolverFailed) {
		t.Fatalf("got %v; want wraps ErrSignaturePolicyResolverFailed", err)
	}
	// MUST NOT route as a policy reject — those are 403; resolver
	// failures are 500. The error mapping discipline depends on these
	// staying distinct.
	if errors.Is(err, admission.ErrSignaturePolicyFailed) {
		t.Errorf("resolver failure must NOT satisfy ErrSignaturePolicyFailed; got %v", err)
	}
}

func TestOnLogSignaturePolicyResolver_TreeSizeError_RoutesToResolverFailure(t *testing.T) {
	boom := errors.New("tree-head store down")
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{err: boom}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	_, _, err = r.Current(context.Background())
	if !errors.Is(err, admission.ErrSignaturePolicyResolverFailed) {
		t.Fatalf("got %v; want wraps ErrSignaturePolicyResolverFailed", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// RequireHybridAfter (Plan §I.7) — timestamp-driven PQ requirement
// ─────────────────────────────────────────────────────────────────────

func TestOnLogSignaturePolicyResolver_HybridAfter_NotYetReached(t *testing.T) {
	// RequireHybridAfter = wall-clock + 1 hour. No PQ requirement.
	future := time.Now().Add(time.Hour).Unix()
	doc := signaturePolicyBootstrap(t,
		[]uint16{envelope.SigAlgoECDSA, envelope.SigAlgoMLDSA65}, 1, &future)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(policy.MinSigsFromSchemeGroup) != 0 {
		t.Errorf("pre-deadline must NOT require PQ; got %+v",
			policy.MinSigsFromSchemeGroup)
	}
}

func TestOnLogSignaturePolicyResolver_HybridAfter_Reached(t *testing.T) {
	// RequireHybridAfter = wall-clock - 1 minute. PQ now required.
	past := time.Now().Add(-time.Minute).Unix()
	doc := signaturePolicyBootstrap(t,
		[]uint16{envelope.SigAlgoECDSA, envelope.SigAlgoMLDSA65}, 1, &past)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got := policy.MinSigsFromSchemeGroup["pq"]; got != 1 {
		t.Errorf("post-deadline MinSigsFromSchemeGroup[pq] = %d, want 1", got)
	}
}

// RequireHybridAfter reached but the allow-list admits NO PQ algos →
// the translated policy fails Validate (an unsatisfiable group
// requirement). The resolver surfaces this as a resolver-failure
// sentinel — operator misconfiguration must NOT 403 every entry.
func TestOnLogSignaturePolicyResolver_HybridAfter_NoPQAllowed_Misconfiguration(t *testing.T) {
	past := time.Now().Add(-time.Minute).Unix()
	// Only ECDSA (classical) — no PQ admitted.
	doc := signaturePolicyBootstrap(t,
		[]uint16{envelope.SigAlgoECDSA}, 1, &past)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		// Construction validates the bootstrap via the genesis-only
		// resolver, which does NOT enforce RequireHybridAfter — so
		// construction succeeds. The misconfiguration only surfaces
		// when the wall clock crosses RequireHybridAfter and the
		// translated policy fails Validate.
		t.Fatalf("constructor must accept the bootstrap (genesis-only validator); got %v", err)
	}
	_, _, err = r.Current(context.Background())
	if !errors.Is(err, admission.ErrSignaturePolicyResolverFailed) {
		t.Fatalf("post-deadline misconfiguration must surface as ErrSignaturePolicyResolverFailed; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// TTL cache
// ─────────────────────────────────────────────────────────────────────

func TestOnLogSignaturePolicyResolver_TTLCache_SourceCalledOnce(t *testing.T) {
	var calls atomic.Int64
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) {
			calls.Add(1)
			return nil, nil
		},
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, time.Hour,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, _, err := r.Current(context.Background()); err != nil {
			t.Fatalf("Current[%d]: %v", i, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("source called %d times, want 1 (TTL cache hit)", got)
	}
}

// TTL=0 disables caching — every Current re-walks.
func TestOnLogSignaturePolicyResolver_NoCache_SourceCalledEveryTime(t *testing.T) {
	var calls atomic.Int64
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) {
			calls.Add(1)
			return nil, nil
		},
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := r.Current(context.Background()); err != nil {
			t.Fatalf("Current[%d]: %v", i, err)
		}
	}
	if got := calls.Load(); got != 5 {
		t.Errorf("source called %d times, want 5 (no cache)", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Interface compliance — the resolver feeds the existing gate
// ─────────────────────────────────────────────────────────────────────

// The amendment-aware resolver MUST satisfy SignaturePolicyResolver so
// the SubmissionDeps wiring is a drop-in swap for the genesis-only
// resolver. This is a compile-time guarantee via the `var _` line in
// the production file, but explicit here serves as a regression
// fixture: a future refactor that changes the interface surface fails
// both at the production var AND at this test, which is more
// discoverable than a single compile error.
func TestOnLogSignaturePolicyResolver_SatisfiesInterface(t *testing.T) {
	doc := signaturePolicyBootstrap(t, []uint16{envelope.SigAlgoECDSA}, 1, nil)
	r, err := admission.NewOnLogSignaturePolicyResolver(
		func(context.Context) ([]network.SignaturePolicyRecord, error) { return nil, nil },
		&fakeSizeProvider{size: 100}, doc, testLogDID, [32]byte{}, 0,
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	var _ admission.SignaturePolicyResolver = r
	// Quick sanity: Current returns a non-zero MinValidSigs.
	policy, _, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if policy.MinValidSigs == 0 {
		t.Error("translated policy has MinValidSigs=0")
	}
}

// _ keeps types imported.
var _ = verifier.EntrySignaturePolicy{}
