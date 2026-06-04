/*
FILE PATH: admission/rotation_entry_verifier.go

On-log entry-signer rotation admission gate.

An entry-signer rotation is written as a sequenced on-log entry whose
DomainPayload is the canonical verifier.RotationPayload wire
(kind=BP-ENTRY-SIGNER-ROTATION-PAYLOAD-V1, baseproof v1.33.0). The ledger sequences
these as first-class entries — but it must NOT sequence a malformed one,
because the position-authoritative rotation record is the sequenced
entry itself, and a garbage rotation would poison the consumer's
key-at-position evidence walk.

SCOPE — structure, not authority:
  - The ledger validates the rotation payload SHAPE (well-formed
    SignerDID + key bytes within caps) via verifier.DecodeRotationPayload.
  - It does NOT verify rotation AUTHORITY (was the rotation signed by the
    currently-active key for that DID?). That is the positional
    VerifyKeyAtPosition walk, which runs at the consumer (the Judicial
    Network), reading the entry's INTRINSIC sequenced position — never a
    position the payload names for itself.

This keeps the ledger dumb about payloads it does not own: only an entry
that DECLARES the rotation kind is gated; every other DomainPayload
(binary commitments, anchor JSON, plain submissions) passes through
untouched.
*/
package admission

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/verifier"
)

// ErrRotationEntryInvalid is returned when an entry declares the
// canonical entry-signer-rotation kind but its DomainPayload does not
// decode/validate as a verifier.RotationPayload. The HTTP layer maps
// this to 422.
var ErrRotationEntryInvalid = errors.New("admission: invalid entry-signer rotation payload")

// VerifyRotationEntry structurally validates an on-log entry-signer
// rotation entry before it consumes a Tessera sequence number. Returns
// nil for any entry that is not a rotation entry (passthrough) and for
// a well-formed one; returns ErrRotationEntryInvalid (wrapping the SDK
// cause) for an entry that declares the rotation kind but is malformed.
//
// The kind discriminator is read with a cheap probe rather than relying
// on DecodeRotationPayload's error vocabulary: a non-JSON DomainPayload
// (e.g. a binary commitment) makes DecodeRotationPayload return a JSON
// error, NOT ErrRotationKindMismatch, so "any decode error ⇒ reject"
// would wrongly reject legitimate non-rotation entries. Only payloads
// that actually declare BP-ENTRY-SIGNER-ROTATION-PAYLOAD-V1 are held to the codec.
func VerifyRotationEntry(entry *envelope.Entry) error {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return nil
	}

	var probe struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(entry.DomainPayload, &probe) != nil ||
		probe.Kind != verifier.RotationPayloadKindV1 {
		// Not a (recognizable) rotation entry — the ledger does not
		// own this payload; pass through.
		return nil
	}

	// It declares the rotation kind, so it MUST decode + validate
	// cleanly (DecodeRotationPayload runs RotationPayload.Validate:
	// non-empty SignerDID, non-empty NewPublicKey, key length caps,
	// well-formed hex).
	if _, err := verifier.DecodeRotationPayload(entry.DomainPayload); err != nil {
		return fmt.Errorf("%w: %w", ErrRotationEntryInvalid, err)
	}
	return nil
}
