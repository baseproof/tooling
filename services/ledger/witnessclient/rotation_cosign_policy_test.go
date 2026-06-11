package witnessclient_test

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// ProcessRotation must reject a rotation whose NEW set introduces a witness
// using a cosign scheme the network does not admit
// (GenesisSignaturePolicy.AllowedCosignSchemeTags) — the same gate boot applies
// to the genesis set. The check runs AFTER cryptographic VerifyRotation and
// BEFORE the on-log append, so a nil appender never masks it: an allowed-policy
// rotation falls through to the appender error, a disallowed-policy rotation
// fails with ErrCosignSchemeNotAllowed first.
func TestProcessRotation_EnforcesCosignSchemePolicy(t *testing.T) {
	t.Parallel()

	const K, N = 2, 3
	netA := netID('A')

	// witnesstest mints an ECDSA (0x01) NewSet through a fully-consented rotation
	// that VerifyRotation accepts — so verification passes and only the
	// cosign-scheme policy distinguishes the two sub-cases below.
	oldA := witnesstest.NewSet(t, netA, N, K)
	rotation := witnesstest.MintRotation(t, netA, oldA, witnesstest.NewSet(t, netA, N, K), K)
	setA, err := cosign.NewWitnessKeySet(oldA.Keys, netA, K, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	newHandler := func(allowed []uint8) *witnessclient.RotationHandler {
		// db + appender nil: ProcessRotation reaches the policy gate (Step 2a)
		// before it touches either.
		return witnessclient.NewRotationHandler(nil, quorum.NewManager(setA), signatures.SchemeECDSA, "", nil).
			WithCosignSchemePolicy(allowed)
	}

	t.Run("disallowed_scheme_rejected", func(t *testing.T) {
		// Policy admits BLS only; the NewSet's ECDSA witnesses are inadmissible.
		_, err := newHandler([]uint8{signatures.SchemeBLS}).ProcessRotation(context.Background(), rotation)
		if !errors.Is(err, quorum.ErrCosignSchemeNotAllowed) {
			t.Fatalf("expected ErrCosignSchemeNotAllowed for an ECDSA NewSet under a BLS-only policy, got: %v", err)
		}
	})

	t.Run("allowed_scheme_passes_policy_gate", func(t *testing.T) {
		// Policy admits ECDSA; the rotation clears the policy gate and only then
		// fails on the (deliberately) unwired on-log appender — proving the gate
		// itself did not reject an admissible scheme.
		_, err := newHandler([]uint8{signatures.SchemeECDSA}).ProcessRotation(context.Background(), rotation)
		if err == nil {
			t.Fatal("expected the unwired-appender error after the policy gate, got nil")
		}
		if errors.Is(err, quorum.ErrCosignSchemeNotAllowed) {
			t.Fatalf("policy gate wrongly rejected an ECDSA NewSet under an ECDSA-allowed policy: %v", err)
		}
	})
}
