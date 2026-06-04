package quorum_test

import (
	"errors"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/quorum"
)

// wk builds a witness key with a given cosign SchemeTag. ID is filled from a
// single byte so error messages are distinguishable; PublicKey is not validated
// by ValidateCosignSchemePolicy (it gates on the declared SchemeTag only).
func wk(idByte, scheme byte) types.WitnessPublicKey {
	var id [32]byte
	id[0] = idByte
	return types.WitnessPublicKey{ID: id, SchemeTag: scheme}
}

func TestValidateCosignSchemePolicy(t *testing.T) {
	const (
		ecdsa = signatures.SchemeECDSA // 0x01
		bls   = signatures.SchemeBLS   // 0x02
	)
	cases := []struct {
		name    string
		keys    []types.WitnessPublicKey
		allowed []uint8
		wantErr bool
	}{
		{
			name:    "all_ecdsa_under_ecdsa_policy_ok",
			keys:    []types.WitnessPublicKey{wk(1, ecdsa), wk(2, ecdsa), wk(3, ecdsa)},
			allowed: []uint8{ecdsa},
		},
		{
			name:    "bls_key_under_ecdsa_policy_rejected",
			keys:    []types.WitnessPublicKey{wk(1, ecdsa), wk(2, bls)},
			allowed: []uint8{ecdsa},
			wantErr: true,
		},
		{
			// THE gap: a network whose policy forbids ECDSA must NOT silently
			// admit ECDSA witnesses (pre-fix the ledger accepted them anyway).
			name:    "ecdsa_key_under_bls_only_policy_rejected",
			keys:    []types.WitnessPublicKey{wk(1, ecdsa)},
			allowed: []uint8{bls},
			wantErr: true,
		},
		{
			name:    "mixed_keys_under_mixed_policy_ok",
			keys:    []types.WitnessPublicKey{wk(1, ecdsa), wk(2, bls)},
			allowed: []uint8{ecdsa, bls},
		},
		{
			name:    "empty_policy_is_noop",
			keys:    []types.WitnessPublicKey{wk(1, ecdsa), wk(2, bls)},
			allowed: nil,
		},
		{
			name:    "empty_keys_ok",
			keys:    nil,
			allowed: []uint8{ecdsa},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := quorum.ValidateCosignSchemePolicy(tc.keys, tc.allowed)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected ErrCosignSchemeNotAllowed, got nil")
				}
				if !errors.Is(err, quorum.ErrCosignSchemeNotAllowed) {
					t.Fatalf("error does not wrap ErrCosignSchemeNotAllowed: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
