package api

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"

	"github.com/baseproof/tooling/services/ledger/admission"
)

type apiAlgoResolver struct{ p authz.AlgorithmPolicy }

func (r apiAlgoResolver) Current(context.Context) (authz.AlgorithmPolicy, error) { return r.p, nil }

type apiProtoResolver struct {
	p authz.ProtocolVersionAdmissionPolicy
}

func (r apiProtoResolver) Current(context.Context) (authz.ProtocolVersionAdmissionPolicy, error) {
	return r.p, nil
}

// The shared signature gate composes the algorithm-policy step (issue #201):
// once wired, an entry whose algorithm is forbidden is rejected — on BOTH
// submission paths, since both call verifyEntrySignaturesGated. Crypto is
// skipped here (legacy path, nil resolver → wire-integrity) to isolate the
// algorithm gate.
func TestVerifyEntrySignaturesGated_EnforcesAlgorithmPolicy(t *testing.T) {
	entry := &envelope.Entry{Signatures: []envelope.Signature{{AlgoID: envelope.SigAlgoECDSA}}}
	deps := &SubmissionDeps{
		Gates:    admission.Gates{MultiSig: false, AlgorithmPolicy: true},
		Identity: IdentityDeps{}, // nil DIDResolver → crypto short-circuits
		AlgorithmPolicyResolver: apiAlgoResolver{p: authz.AlgorithmPolicy{Algorithms: []authz.AlgorithmRecord{
			{AlgoID: envelope.SigAlgoECDSA, LifecycleState: authz.AlgorithmForbidden},
		}}},
	}
	if _, err := verifyEntrySignaturesGated(context.Background(), entry, nil, deps); !errors.Is(err, admission.ErrAlgorithmForbidden) {
		t.Fatalf("shared gate should reject a forbidden algorithm, got %v", err)
	}

	// Same entry, algorithm active → admitted.
	deps.AlgorithmPolicyResolver = apiAlgoResolver{p: authz.AlgorithmPolicy{Algorithms: []authz.AlgorithmRecord{
		{AlgoID: envelope.SigAlgoECDSA, LifecycleState: authz.AlgorithmActive},
	}}}
	if _, err := verifyEntrySignaturesGated(context.Background(), entry, nil, deps); err != nil {
		t.Fatalf("active algorithm should be admitted, got %v", err)
	}
}

// admitProtocolVersion: legacy rule when unwired, on-log policy when wired —
// the shared helper both submission paths call.
func TestAdmitProtocolVersion(t *testing.T) {
	cur := envelope.CurrentProtocolVersion()

	off := &SubmissionDeps{Gates: admission.Gates{}}
	if err := admitProtocolVersion(context.Background(), cur, off); err != nil {
		t.Fatalf("unwired + current version must pass (legacy rule): %v", err)
	}
	if err := admitProtocolVersion(context.Background(), cur+99, off); !errors.Is(err, admission.ErrProtocolVersionNotAdmitted) {
		t.Fatalf("unwired + non-current version must be rejected, got %v", err)
	}

	on := &SubmissionDeps{
		Gates: admission.Gates{ProtocolVersion: true},
		ProtocolVersionResolver: apiProtoResolver{p: authz.ProtocolVersionAdmissionPolicy{
			AdmittedVersions: []authz.ProtocolVersionRecord{{Version: cur, AdmittedFor: authz.ProtocolVersionReadOnly}},
		}},
	}
	if err := admitProtocolVersion(context.Background(), cur, on); !errors.Is(err, admission.ErrProtocolVersionNotAdmitted) {
		t.Fatalf("wired + read_only current version must reject writes, got %v", err)
	}

	on.ProtocolVersionResolver = apiProtoResolver{p: authz.ProtocolVersionAdmissionPolicy{
		AdmittedVersions: []authz.ProtocolVersionRecord{{Version: cur, AdmittedFor: authz.ProtocolVersionReadWrite}},
	}}
	if err := admitProtocolVersion(context.Background(), cur, on); err != nil {
		t.Fatalf("wired + read_write current version must pass, got %v", err)
	}
}
