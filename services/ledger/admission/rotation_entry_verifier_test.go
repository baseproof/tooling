package admission_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/artifact"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/services/ledger/admission"
)

func TestVerifyRotationEntry(t *testing.T) {
	t.Parallel()

	// A well-formed rotation payload via the canonical SDK encoder.
	validRotation, err := verifier.EncodeRotationPayload(verifier.RotationPayload{
		SignerDID:    "did:web:example.com",
		NewPublicKey: bytes.Repeat([]byte{0xAB}, 33),
	})
	if err != nil {
		t.Fatalf("EncodeRotationPayload: %v", err)
	}

	cases := []struct {
		name       string
		payload    []byte
		wantReject bool
	}{
		{"nil entry payload", nil, false},
		{"valid rotation", validRotation, false},
		// Non-rotation payloads must pass through untouched — the ledger
		// does not own them.
		{"non-rotation json (different kind)", []byte(`{"kind":"something_else"}`), false},
		{"non-rotation json (no kind)", []byte(`{"schema_id":"` + artifact.PREGrantCommitmentSchemaID + `"}`), false},
		{"binary (non-json) payload", []byte{0x00, 0x01, 0x02, 0xFF}, false},
		// Declares the rotation kind but malformed → reject.
		{"rotation, empty signer_did",
			[]byte(`{"kind":"` + verifier.RotationPayloadKindV1 + `","new_public_key":"aabb"}`), true},
		{"rotation, empty new_public_key",
			[]byte(`{"kind":"` + verifier.RotationPayloadKindV1 + `","signer_did":"did:web:x"}`), true},
		{"rotation, bad hex new_public_key",
			[]byte(`{"kind":"` + verifier.RotationPayloadKindV1 + `","signer_did":"did:web:x","new_public_key":"zz"}`), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entry := &envelope.Entry{DomainPayload: tc.payload}
			err := admission.VerifyRotationEntry(entry)
			if tc.wantReject {
				if err == nil {
					t.Fatal("want ErrRotationEntryInvalid, got nil")
				}
				if !errors.Is(err, admission.ErrRotationEntryInvalid) {
					t.Errorf("err = %v; want errors.Is(.., ErrRotationEntryInvalid)", err)
				}
			} else if err != nil {
				t.Errorf("want nil (passthrough/valid), got %v", err)
			}
		})
	}
}

// TestVerifyRotationEntry_NilEntry confirms a nil entry is a no-op
// (admission may dispatch over filtered slices).
func TestVerifyRotationEntry_NilEntry(t *testing.T) {
	t.Parallel()
	if err := admission.VerifyRotationEntry(nil); err != nil {
		t.Errorf("VerifyRotationEntry(nil) = %v, want nil", err)
	}
}
