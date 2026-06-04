package admission_test

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// stubAlgoResolver returns a fixed algorithm policy (or error) for the gate tests.
type stubAlgoResolver struct {
	p   authz.AlgorithmPolicy
	err error
}

func (s stubAlgoResolver) Current(context.Context) (authz.AlgorithmPolicy, error) {
	return s.p, s.err
}

func algoEntry(algos ...uint16) *envelope.Entry {
	sigs := make([]envelope.Signature, len(algos))
	for i, a := range algos {
		sigs[i] = envelope.Signature{AlgoID: a}
	}
	return &envelope.Entry{Signatures: sigs}
}

func policyOf(pairs ...any) authz.AlgorithmPolicy {
	// pairs: algoID(uint16), state(AlgorithmLifecycleState), repeated.
	var recs []authz.AlgorithmRecord
	for i := 0; i < len(pairs); i += 2 {
		recs = append(recs, authz.AlgorithmRecord{
			AlgoID:         pairs[i].(uint16),
			LifecycleState: pairs[i+1].(authz.AlgorithmLifecycleState),
		})
	}
	return authz.AlgorithmPolicy{Algorithms: recs}
}

func TestVerifyEntryAlgorithmPolicy(t *testing.T) {
	const ecdsa, ed25519, mldsa uint16 = 0x0001, 0x0002, 0x0007
	cases := []struct {
		name    string
		policy  authz.AlgorithmPolicy
		entry   *envelope.Entry
		wantErr bool
	}{
		{"active_admitted", policyOf(ecdsa, authz.AlgorithmActive), algoEntry(ecdsa), false},
		{"deprecated_admitted", policyOf(ecdsa, authz.AlgorithmDeprecated), algoEntry(ecdsa), false},
		{"forbidden_rejected", policyOf(ecdsa, authz.AlgorithmForbidden), algoEntry(ecdsa), true},
		{"absent_rejected", policyOf(ed25519, authz.AlgorithmActive), algoEntry(ecdsa), true},
		{
			"multisig_one_forbidden_rejects_whole_entry",
			policyOf(ecdsa, authz.AlgorithmActive, mldsa, authz.AlgorithmForbidden),
			algoEntry(ecdsa, mldsa),
			true,
		},
		{
			"multisig_all_admitted",
			policyOf(ecdsa, authz.AlgorithmActive, mldsa, authz.AlgorithmDeprecated),
			algoEntry(ecdsa, mldsa),
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := admission.VerifyEntryAlgorithmPolicy(context.Background(), stubAlgoResolver{p: tc.policy}, tc.entry)
			if tc.wantErr {
				if !errors.Is(err, admission.ErrAlgorithmForbidden) {
					t.Fatalf("want ErrAlgorithmForbidden, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyEntryAlgorithmPolicy_NilResolverDisablesGate(t *testing.T) {
	if err := admission.VerifyEntryAlgorithmPolicy(context.Background(), nil, algoEntry(0x0001)); err != nil {
		t.Fatalf("nil resolver should disable the gate, got %v", err)
	}
}

func TestVerifyEntryAlgorithmPolicy_ResolverError(t *testing.T) {
	err := admission.VerifyEntryAlgorithmPolicy(context.Background(),
		stubAlgoResolver{err: errors.New("db down")}, algoEntry(0x0001))
	if !errors.Is(err, admission.ErrAlgorithmPolicyResolverFailed) {
		t.Fatalf("want ErrAlgorithmPolicyResolverFailed, got %v", err)
	}
}

func TestGenesisAlgorithmPolicyFromBootstrap_AllActive(t *testing.T) {
	doc := network.BootstrapDocument{GenesisSignaturePolicy: network.SignaturePolicy{
		AllowedEntrySigSchemes:  []uint16{0x0001, 0x0007},
		AllowedCosignSchemeTags: []uint8{0x01},
		MinSignaturesPerEntry:   1,
	}}
	p := admission.GenesisAlgorithmPolicyFromBootstrap(doc)
	if err := p.Validate(); err != nil {
		t.Fatalf("synthesized genesis policy invalid: %v", err)
	}
	for _, a := range []uint16{0x0001, 0x0007} {
		if !p.IsActive(a) {
			t.Errorf("algo 0x%04x should be active at genesis", a)
		}
	}
}

// The amendment-aware resolver projects an on-log "forbid ECDSA" amendment over
// the synthesized genesis baseline — and only at/after the amendment's position.
func TestOnLogAlgorithmPolicyResolver_AmendmentForbidsAtAsOf(t *testing.T) {
	const logDID = "did:web:test.log"
	const ecdsa uint16 = 0x0001
	doc := network.BootstrapDocument{GenesisSignaturePolicy: network.SignaturePolicy{
		AllowedEntrySigSchemes:  []uint16{ecdsa},
		AllowedCosignSchemeTags: []uint8{0x01},
		MinSignaturesPerEntry:   1,
	}}
	// One amendment at sequence 5: ECDSA → forbidden (a forward lifecycle step).
	amendAt := uint64(5)
	source := func(context.Context) ([]authz.AlgorithmPolicyRecord, error) {
		return []authz.AlgorithmPolicyRecord{{
			EffectivePos: types.LogPosition{LogDID: logDID, Sequence: amendAt},
			Policy:       policyOf(ecdsa, authz.AlgorithmForbidden),
		}}, nil
	}

	mk := func(treeSize uint64) *admission.OnLogAlgorithmPolicyResolver {
		r, err := admission.NewOnLogAlgorithmPolicyResolver(
			source, &fakeSizeProvider{size: treeSize}, doc, logDID, [32]byte{}, 0 /* no cache */)
		if err != nil {
			t.Fatalf("NewOnLogAlgorithmPolicyResolver: %v", err)
		}
		return r
	}

	// Before the amendment takes effect: genesis baseline → ECDSA active.
	pBefore, err := mk(amendAt - 1).Current(context.Background())
	if err != nil {
		t.Fatalf("Current(before): %v", err)
	}
	if !pBefore.IsActive(ecdsa) {
		t.Fatalf("before amendment, ECDSA must be active (genesis baseline)")
	}

	// At/after the amendment position: ECDSA forbidden.
	pAfter, err := mk(amendAt + 3).Current(context.Background())
	if err != nil {
		t.Fatalf("Current(after): %v", err)
	}
	if pAfter.PermitsVerification(ecdsa) {
		t.Fatalf("after amendment, ECDSA must be forbidden (PermitsVerification=false)")
	}
}

// Lifecycle monotonicity is enforced by the SDK walker: an amendment that rolls
// ECDSA back from forbidden→active is rejected, surfaced as a resolver failure.
func TestOnLogAlgorithmPolicyResolver_RejectsLifecycleRollback(t *testing.T) {
	const logDID = "did:web:test.log"
	const ecdsa uint16 = 0x0001
	doc := network.BootstrapDocument{GenesisSignaturePolicy: network.SignaturePolicy{
		AllowedEntrySigSchemes:  []uint16{ecdsa},
		AllowedCosignSchemeTags: []uint8{0x01},
		MinSignaturesPerEntry:   1,
	}}
	source := func(context.Context) ([]authz.AlgorithmPolicyRecord, error) {
		return []authz.AlgorithmPolicyRecord{
			{EffectivePos: types.LogPosition{LogDID: logDID, Sequence: 3}, Policy: policyOf(ecdsa, authz.AlgorithmForbidden)},
			{EffectivePos: types.LogPosition{LogDID: logDID, Sequence: 6}, Policy: policyOf(ecdsa, authz.AlgorithmActive)}, // illegal rollback
		}, nil
	}
	r, err := admission.NewOnLogAlgorithmPolicyResolver(source, &fakeSizeProvider{size: 10}, doc, logDID, [32]byte{}, 0)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if _, err := r.Current(context.Background()); !errors.Is(err, admission.ErrAlgorithmPolicyResolverFailed) {
		t.Fatalf("want ErrAlgorithmPolicyResolverFailed on illegal rollback, got %v", err)
	}
}
