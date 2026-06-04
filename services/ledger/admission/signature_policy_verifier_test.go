/*
FILE PATH: admission/signature_policy_verifier_test.go

Tests for the Part II.6 SignaturePolicy admission gate.

Scope:
  - NewGenesisSignaturePolicyResolver builds correctly from a
    network.BootstrapDocument; rejects malformed genesis policy.
  - VerifyEntrySignaturePolicy enforces (a) the algoID allow-list
    and (b) the EntrySignaturePolicy threshold via the SDK's
    Evaluate. Each rejection surfaces the correct typed sentinel.
  - The nil-resolver path is a clean no-op (gate disabled).
  - Group classification follows the SDK §I.11 convention
    (classical / pq).

These tests use in-memory fixtures only — no DB, no I/O — so they
run in every `go test ./...` invocation without DSN gating.
*/
package admission_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// validGenesisDoc returns a minimal BootstrapDocument with a valid
// GenesisSignaturePolicy admitting ECDSA + Ed25519 with a 1-of-N
// threshold — the canonical "founding network" baseline.
func validGenesisDoc(t *testing.T, allowed []uint16, minSigs uint8) network.BootstrapDocument {
	t.Helper()
	return network.BootstrapDocument{
		ProtocolVersion:             "1",
		ExchangeDID:                 "did:web:test.example",
		NetworkName:                 "test-net-sigpolicy",
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
		},
	}
}

// makeReport builds an attestation.SignatureReport with the supplied
// (algoID, valid) pairs. valid=true populates a SignatureResult with
// nil Err (treated as a valid signature by the gate); valid=false
// populates Err so the sig does NOT count toward MinValidSigs.
func makeReport(pairs []struct {
	algoID uint16
	valid  bool
}) *attestation.SignatureReport {
	report := &attestation.SignatureReport{
		Total:   len(pairs),
		Results: make([]attestation.SignatureResult, len(pairs)),
	}
	for i, p := range pairs {
		report.Results[i] = attestation.SignatureResult{
			SignerDID: "did:web:signer",
			AlgoID:    p.algoID,
		}
		if p.valid {
			report.ValidCount++
		} else {
			report.Results[i].Err = errors.New("invalid sig (test fixture)")
		}
	}
	return report
}

// dummyEntry builds an envelope.Entry stub the gate consumes. The
// gate only reads entry.Signatures[i].AlgoID for the allow-list
// check; everything else is irrelevant to the gate's contract.
func dummyEntry(algoIDs []uint16) *envelope.Entry {
	sigs := make([]envelope.Signature, len(algoIDs))
	for i, a := range algoIDs {
		sigs[i].AlgoID = a
		sigs[i].SignerDID = "did:web:signer"
		// SignatureBytes left empty — the gate does not re-verify;
		// the multi-sig gate produced the report we're consuming.
	}
	return &envelope.Entry{
		Header:     envelope.ControlHeader{SignerDID: "did:web:signer"},
		Signatures: sigs,
	}
}

// ─────────────────────────────────────────────────────────────────────
// NewGenesisSignaturePolicyResolver
// ─────────────────────────────────────────────────────────────────────

func TestNewGenesisSignaturePolicyResolver_HappyPath(t *testing.T) {
	doc := validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 1)
	r, err := admission.NewGenesisSignaturePolicyResolver(doc)
	if err != nil {
		t.Fatalf("NewGenesisSignaturePolicyResolver: %v", err)
	}
	policy, allowed, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if policy.MinValidSigs != 1 {
		t.Errorf("MinValidSigs = %d, want 1", policy.MinValidSigs)
	}
	if _, ok := allowed[envelope.SigAlgoECDSA]; !ok {
		t.Errorf("allowed set missing SigAlgoECDSA (0x%04x)", envelope.SigAlgoECDSA)
	}
	// SchemeGroups must classify ECDSA as classical.
	if group := policy.SchemeGroups[envelope.SigAlgoECDSA]; group != "classical" {
		t.Errorf("SigAlgoECDSA group = %q, want classical", group)
	}
}

func TestNewGenesisSignaturePolicyResolver_ClassifiesPQAndClassical(t *testing.T) {
	doc := validGenesisDoc(t, []uint16{
		envelope.SigAlgoECDSA,
		envelope.SigAlgoEd25519,
		envelope.SigAlgoMLDSA65,
		envelope.SigAlgoSLHDSA128s,
	}, 1)
	r, err := admission.NewGenesisSignaturePolicyResolver(doc)
	if err != nil {
		t.Fatalf("NewGenesisSignaturePolicyResolver: %v", err)
	}
	policy, _, _ := r.Current(context.Background())
	cases := map[uint16]string{
		envelope.SigAlgoECDSA:      "classical",
		envelope.SigAlgoEd25519:    "classical",
		envelope.SigAlgoMLDSA65:    "pq",
		envelope.SigAlgoSLHDSA128s: "pq",
	}
	for algo, want := range cases {
		if got := policy.SchemeGroups[algo]; got != want {
			t.Errorf("algo 0x%04x group = %q, want %q", algo, got, want)
		}
	}
}

func TestNewGenesisSignaturePolicyResolver_RejectsMinSigsOutOfRange(t *testing.T) {
	doc := validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 0) // 0 is invalid
	_, err := admission.NewGenesisSignaturePolicyResolver(doc)
	if err == nil {
		t.Fatal("MinSignaturesPerEntry=0 must be rejected by Validate")
	}
}

// ─────────────────────────────────────────────────────────────────────
// VerifyEntrySignaturePolicy — allow-list
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntrySignaturePolicy_NilResolver_GateDisabled(t *testing.T) {
	// nil resolver → gate is inert; returns nil regardless of inputs.
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), nil,
		dummyEntry([]uint16{envelope.SigAlgoECDSA}),
		makeReport([]struct {
			algoID uint16
			valid  bool
		}{{envelope.SigAlgoECDSA, true}}),
	)
	if err != nil {
		t.Errorf("nil resolver should be no-op; got %v", err)
	}
}

func TestVerifyEntrySignaturePolicy_AllowListAccept(t *testing.T) {
	r, _ := admission.NewGenesisSignaturePolicyResolver(
		validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA, envelope.SigAlgoEd25519}, 1),
	)
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r,
		dummyEntry([]uint16{envelope.SigAlgoECDSA}),
		makeReport([]struct {
			algoID uint16
			valid  bool
		}{{envelope.SigAlgoECDSA, true}}),
	)
	if err != nil {
		t.Errorf("ECDSA in allow-list should pass; got %v", err)
	}
}

func TestVerifyEntrySignaturePolicy_AllowListReject(t *testing.T) {
	// Genesis admits ECDSA only; entry uses Ed25519 (NOT admitted).
	r, _ := admission.NewGenesisSignaturePolicyResolver(
		validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 1),
	)
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r,
		dummyEntry([]uint16{envelope.SigAlgoEd25519}),
		makeReport([]struct {
			algoID uint16
			valid  bool
		}{{envelope.SigAlgoEd25519, true}}),
	)
	if !errors.Is(err, admission.ErrSignatureAlgoNotAllowed) {
		t.Fatalf("got %v; want wraps ErrSignatureAlgoNotAllowed", err)
	}
}

// A sig with an unallowed algoID that nominally "verified" still
// fails the allow-list. The gate rejects on the entry's declared
// signatures regardless of which ones cryptographically verified.
func TestVerifyEntrySignaturePolicy_AllowList_RejectsValidButForbiddenAlgo(t *testing.T) {
	r, _ := admission.NewGenesisSignaturePolicyResolver(
		validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 1),
	)
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r,
		dummyEntry([]uint16{envelope.SigAlgoECDSA, envelope.SigAlgoEIP191}),
		makeReport([]struct {
			algoID uint16
			valid  bool
		}{
			{envelope.SigAlgoECDSA, true},
			{envelope.SigAlgoEIP191, true}, // valid bytes, but NOT in allow-list
		}),
	)
	if !errors.Is(err, admission.ErrSignatureAlgoNotAllowed) {
		t.Fatalf("got %v; want wraps ErrSignatureAlgoNotAllowed", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// VerifyEntrySignaturePolicy — threshold (MinValidSigs)
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntrySignaturePolicy_ThresholdReject(t *testing.T) {
	// Genesis requires 2 valid sigs; entry has only 1 valid.
	r, _ := admission.NewGenesisSignaturePolicyResolver(
		validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 2),
	)
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r,
		dummyEntry([]uint16{envelope.SigAlgoECDSA, envelope.SigAlgoECDSA}),
		makeReport([]struct {
			algoID uint16
			valid  bool
		}{
			{envelope.SigAlgoECDSA, true},
			{envelope.SigAlgoECDSA, false}, // failed crypto → not counted
		}),
	)
	if !errors.Is(err, admission.ErrSignaturePolicyFailed) {
		t.Fatalf("got %v; want wraps ErrSignaturePolicyFailed", err)
	}
	// And the underlying SDK sentinel must be reachable via errors.Is.
	if !errors.Is(err, verifier.ErrPolicyMinValidSigs) {
		t.Errorf("expected unwrap to reach verifier.ErrPolicyMinValidSigs; got %v", err)
	}
}

func TestVerifyEntrySignaturePolicy_ThresholdAccept(t *testing.T) {
	r, _ := admission.NewGenesisSignaturePolicyResolver(
		validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 2),
	)
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r,
		dummyEntry([]uint16{envelope.SigAlgoECDSA, envelope.SigAlgoECDSA}),
		makeReport([]struct {
			algoID uint16
			valid  bool
		}{
			{envelope.SigAlgoECDSA, true},
			{envelope.SigAlgoECDSA, true},
		}),
	)
	if err != nil {
		t.Errorf("2/2 valid ECDSA at threshold=2 should pass; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// VerifyEntrySignaturePolicy — defensive guards
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntrySignaturePolicy_NilEntry_ProgrammerError(t *testing.T) {
	r, _ := admission.NewGenesisSignaturePolicyResolver(
		validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 1),
	)
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r, nil, &attestation.SignatureReport{},
	)
	if err == nil {
		t.Fatal("nil entry must surface as programmer error")
	}
}

func TestVerifyEntrySignaturePolicy_NilReport_ProgrammerError(t *testing.T) {
	r, _ := admission.NewGenesisSignaturePolicyResolver(
		validGenesisDoc(t, []uint16{envelope.SigAlgoECDSA}, 1),
	)
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r, dummyEntry([]uint16{envelope.SigAlgoECDSA}), nil,
	)
	if err == nil {
		t.Fatal("nil report must surface as programmer error")
	}
}

// erroringResolver returns the configured error from Current. Used
// to pin the resolver-failure routing contract.
type erroringResolver struct{ err error }

func (e *erroringResolver) Current(_ context.Context) (verifier.EntrySignaturePolicy, map[uint16]struct{}, error) {
	return verifier.EntrySignaturePolicy{}, nil, e.err
}

func TestVerifyEntrySignaturePolicy_ResolverError_DistinctSentinel(t *testing.T) {
	r := &erroringResolver{err: errors.New("network down")}
	err := admission.VerifyEntrySignaturePolicy(
		context.Background(), r,
		dummyEntry([]uint16{envelope.SigAlgoECDSA}),
		makeReport([]struct {
			algoID uint16
			valid  bool
		}{{envelope.SigAlgoECDSA, true}}),
	)
	if !errors.Is(err, admission.ErrSignaturePolicyResolverFailed) {
		t.Fatalf("got %v; want wraps ErrSignaturePolicyResolverFailed", err)
	}
	// MUST NOT route as a policy-reject sentinel — those are 403s,
	// resolver failures are 500s. The error mapping discipline
	// depends on these staying distinct.
	if errors.Is(err, admission.ErrSignaturePolicyFailed) {
		t.Errorf("resolver-failure sentinel must NOT also satisfy ErrSignaturePolicyFailed; got %v", err)
	}
	if errors.Is(err, admission.ErrSignatureAlgoNotAllowed) {
		t.Errorf("resolver-failure sentinel must NOT also satisfy ErrSignatureAlgoNotAllowed; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Error mapping integration
// ─────────────────────────────────────────────────────────────────────

func TestErrorMapping_SignaturePolicySentinels_RouteAs403(t *testing.T) {
	cases := []error{
		admission.ErrSignatureAlgoNotAllowed,
		admission.ErrSignaturePolicyFailed,
	}
	for _, sentinel := range cases {
		matched, status, _ := admission.MapSDKError(sentinel)
		if !matched {
			t.Errorf("MapSDKError missed sentinel %v", sentinel)
			continue
		}
		if status != 403 {
			t.Errorf("sentinel %v: got %d, want 403", sentinel, status)
		}
	}
}

// Resolver-failure sentinel MUST NOT be in the table — production
// routing falls through to the 500 default. A regression that adds
// it to the table would silently downgrade infrastructure failures
// to policy rejects (wrong HTTP status, wrong dashboard alert).
func TestErrorMapping_ResolverFailureSentinel_NotInTable(t *testing.T) {
	matched, _, _ := admission.MapSDKError(admission.ErrSignaturePolicyResolverFailed)
	if matched {
		t.Error("ErrSignaturePolicyResolverFailed is in sdkErrorTable; " +
			"infrastructure failures must route via the 500 default, NOT as a policy reject")
	}
}

// _ keeps types imported for fixtures that may grow in follow-up tests.
var _ = types.WitnessPublicKey{}
var _ = sha256.Sum256
