package admission_test

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/admission"
)

type stubProtoResolver struct {
	p   authz.ProtocolVersionAdmissionPolicy
	err error
}

func (s stubProtoResolver) Current(context.Context) (authz.ProtocolVersionAdmissionPolicy, error) {
	return s.p, s.err
}

func protoPolicy(version uint16, state authz.ProtocolVersionAdmissionState) authz.ProtocolVersionAdmissionPolicy {
	return authz.ProtocolVersionAdmissionPolicy{
		AdmittedVersions: []authz.ProtocolVersionRecord{{Version: version, AdmittedFor: state}},
	}
}

func TestVerifyEntryProtocolVersion(t *testing.T) {
	const v uint16 = 1
	cases := []struct {
		name    string
		state   authz.ProtocolVersionAdmissionState
		wantErr bool
	}{
		{"write_only_admitted", authz.ProtocolVersionWriteOnly, false},
		{"read_write_admitted", authz.ProtocolVersionReadWrite, false},
		{"read_only_rejected", authz.ProtocolVersionReadOnly, true},
		{"forbidden_rejected", authz.ProtocolVersionForbidden, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := admission.VerifyEntryProtocolVersion(context.Background(), stubProtoResolver{p: protoPolicy(v, tc.state)}, v)
			if tc.wantErr {
				if !errors.Is(err, admission.ErrProtocolVersionNotAdmitted) {
					t.Fatalf("want ErrProtocolVersionNotAdmitted, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyEntryProtocolVersion_AbsentVersionRejected(t *testing.T) {
	// Policy admits version 1; a submission at version 2 is not in the policy.
	err := admission.VerifyEntryProtocolVersion(context.Background(),
		stubProtoResolver{p: protoPolicy(1, authz.ProtocolVersionReadWrite)}, 2)
	if !errors.Is(err, admission.ErrProtocolVersionNotAdmitted) {
		t.Fatalf("want ErrProtocolVersionNotAdmitted for an absent version, got %v", err)
	}
}

func TestVerifyEntryProtocolVersion_NilResolverDisablesGate(t *testing.T) {
	if err := admission.VerifyEntryProtocolVersion(context.Background(), nil, 99); err != nil {
		t.Fatalf("nil resolver should disable the gate, got %v", err)
	}
}

func TestVerifyEntryProtocolVersion_ResolverError(t *testing.T) {
	err := admission.VerifyEntryProtocolVersion(context.Background(),
		stubProtoResolver{err: errors.New("db down")}, 1)
	if !errors.Is(err, admission.ErrProtocolVersionResolverFailed) {
		t.Fatalf("want ErrProtocolVersionResolverFailed, got %v", err)
	}
}

func TestGenesisProtocolVersionPolicy_CurrentVersionWritable(t *testing.T) {
	p := admission.GenesisProtocolVersionPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("synthesized genesis policy invalid: %v", err)
	}
	if !p.PermitsWrite(envelope.CurrentProtocolVersion()) {
		t.Fatalf("current wire version must be write-admitted at genesis")
	}
}

// The amendment-aware resolver moves the current version to read_only at a
// position — writes pass before it, are rejected at/after it.
func TestOnLogProtocolVersionResolver_AmendmentToReadOnlyAtAsOf(t *testing.T) {
	const logDID = "did:web:test.log"
	cur := envelope.CurrentProtocolVersion()
	amendAt := uint64(7)
	source := func(context.Context) ([]authz.ProtocolVersionAdmissionRecord, error) {
		return []authz.ProtocolVersionAdmissionRecord{{
			EffectivePos: types.LogPosition{LogDID: logDID, Sequence: amendAt},
			Policy:       protoPolicy(cur, authz.ProtocolVersionReadOnly),
		}}, nil
	}
	mk := func(treeSize uint64) *admission.OnLogProtocolVersionResolver {
		r, err := admission.NewOnLogProtocolVersionResolver(source, &fakeSizeProvider{size: treeSize}, logDID, [32]byte{}, 0)
		if err != nil {
			t.Fatalf("NewOnLogProtocolVersionResolver: %v", err)
		}
		return r
	}

	pBefore, err := mk(amendAt - 1).Current(context.Background())
	if err != nil {
		t.Fatalf("Current(before): %v", err)
	}
	if !pBefore.PermitsWrite(cur) {
		t.Fatalf("before amendment, current version must permit writes (genesis baseline)")
	}

	pAfter, err := mk(amendAt + 2).Current(context.Background())
	if err != nil {
		t.Fatalf("Current(after): %v", err)
	}
	if pAfter.PermitsWrite(cur) {
		t.Fatalf("after read_only amendment, current version must NOT permit writes")
	}
	if !pAfter.PermitsRead(cur) {
		t.Fatalf("read_only must still permit reads")
	}
}
