package admission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/types"
)

func polRec(seq uint64, p authz.AdmissionPolicy) authz.AdmissionPolicyRecord {
	return authz.AdmissionPolicyRecord{
		EffectivePos: types.LogPosition{LogDID: "did:web:ctrl", Sequence: seq},
		Policy:       p,
	}
}

func TestOnLogAdmissionPolicy_GenesisAndChanges(t *testing.T) {
	ctx := context.Background()
	genesis := authz.AdmissionPolicy{GatingRequired: true, CostMode: authz.CostModeUncharged}

	// No on-log changes → genesis.
	pNone := NewOnLogAdmissionPolicy(
		func(context.Context) ([]authz.AdmissionPolicyRecord, error) { return nil, nil },
		genesis, 0)
	if got, err := pNone.Current(ctx); err != nil || got != genesis {
		t.Fatalf("genesis: %+v / %v", got, err)
	}

	// Latest on-log change wins (regardless of input order).
	flat := authz.AdmissionPolicy{GatingRequired: true, CostMode: authz.CostModeFlat, FlatUnits: 3}
	off := authz.AdmissionPolicy{GatingRequired: false, CostMode: authz.CostModeUncharged}
	pChg := NewOnLogAdmissionPolicy(
		func(context.Context) ([]authz.AdmissionPolicyRecord, error) {
			return []authz.AdmissionPolicyRecord{polRec(30, off), polRec(10, flat)}, nil
		}, genesis, 0)
	if got, _ := pChg.Current(ctx); got != off {
		t.Errorf("latest change: %+v want %+v", got, off)
	}

	// Source error propagates.
	boom := errors.New("query failed")
	pErr := NewOnLogAdmissionPolicy(
		func(context.Context) ([]authz.AdmissionPolicyRecord, error) { return nil, boom }, genesis, 0)
	if _, err := pErr.Current(ctx); !errors.Is(err, boom) {
		t.Errorf("source error: %v", err)
	}
}

func TestOnLogAdmissionPolicy_SecureDefaultFallback(t *testing.T) {
	ctx := context.Background()
	// An invalid/zero genesis falls back to SecureDefaultPolicy (default-require).
	p := NewOnLogAdmissionPolicy(
		func(context.Context) ([]authz.AdmissionPolicyRecord, error) { return nil, nil },
		authz.AdmissionPolicy{}, 0) // zero value: CostMode "" is invalid
	got, err := p.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != SecureDefaultPolicy || !got.GatingRequired {
		t.Errorf("fallback = %+v, want SecureDefaultPolicy (gating required)", got)
	}
}

func TestOnLogAdmissionPolicy_Cache(t *testing.T) {
	ctx := context.Background()
	genesis := SecureDefaultPolicy
	calls := 0
	src := func(context.Context) ([]authz.AdmissionPolicyRecord, error) {
		calls++
		return nil, nil
	}
	p := NewOnLogAdmissionPolicy(src, genesis, time.Hour)
	_, _ = p.Current(ctx)
	_, _ = p.Current(ctx)
	if calls != 1 {
		t.Errorf("cache: source called %d times, want 1", calls)
	}
}

func TestStaticAdmissionPolicy(t *testing.T) {
	p := StaticAdmissionPolicy{Policy: authz.AdmissionPolicy{GatingRequired: false, CostMode: authz.CostModeUncharged}}
	got, err := p.Current(context.Background())
	if err != nil || got.GatingRequired {
		t.Errorf("static: %+v / %v", got, err)
	}
}

func TestSecureDefaultPolicy_IsValidAndRequiresGating(t *testing.T) {
	if err := SecureDefaultPolicy.Validate(); err != nil {
		t.Fatalf("SecureDefaultPolicy invalid: %v", err)
	}
	if !SecureDefaultPolicy.GatingRequired {
		t.Error("SecureDefaultPolicy must require gating (default-require)")
	}
}
