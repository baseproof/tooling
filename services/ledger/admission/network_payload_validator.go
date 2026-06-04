/*
FILE PATH: admission/network_payload_validator.go

v1.32.0 SDK adoption — per-Kind structural validation hook for
the three new on-log network entry kinds:

  - WitnessEndpointDeclarationV1 (network/witness_endpoint_declaration.go)
  - WitnessIdentityLabelV1       (network/witness_identity_label.go)
  - AuditorRegistrationV1        (network/auditor_registration.go)

# WHAT THIS IS

The SDK ships each new payload type with a Validate() method
that enforces structural invariants (URL scheme, public-key
length, scope ≠ 0, PoP required for BLS, etc.). The submission
pipeline (api/submission.go:586-742) already runs
admission.VerifyRotationEntry as a structure-only gate for
BP-ENTRY-SIGNER-ROTATION-PAYLOAD-V1; this file mirrors that pattern for the
three new kinds.

# WHY VALIDATE AT THE LEDGER

The ledger's admission gate is generic in Kind by design
(SignaturePolicy + AttestationPolicy admit any signed entry).
Adding a kind-specific STRUCTURAL gate here is NOT a trust gate
— it's a malformed-payload firewall that converts a 422 at the
front door into a guarantee that downstream walkers (the SDK's
ResolveXxxAt) never see a poisoned record. Caller is JN's
verification/auditor_registry_walker.go and the ledger's own
gossipnet/auditor_scope_gate.go.

Reject reasons surface as HTTP 422 (ErrSchemaInvalid wrap) so
the operator publishing the entry sees the exact validation
failure rather than a generic "admission rejected".

# WHERE IT INTERPOSES

api/submission.go's prepareSubmission calls
VerifyNetworkPayloadEntry between step 4c (schema validation)
and step 4f (rotation entry validation). Non-network payloads
pass through untouched — the function decodes the entry's
DomainPayload, looks at the payload-kind discriminator, and
short-circuits when the kind is not one of the three network
kinds it gates.
*/
package admission

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
)

// ErrNetworkPayloadInvalid is the typed sentinel for structural
// rejection of WitnessEndpointDeclarationV1 /
// WitnessIdentityLabelV1 / AuditorRegistrationV1 payloads.
// Wraps the SDK's per-payload Validate error so callers can
// errors.Is() either layer.
var ErrNetworkPayloadInvalid = errors.New("admission: network payload structurally invalid")

// VerifyNetworkPayloadEntry runs the SDK's per-kind Validate()
// method on the four v1.33.0 network entry kinds. Non-network
// payloads (unknown kind, non-JSON, missing kind) pass through
// with no error.
//
// Surface contract mirrors VerifyRotationEntry: a non-nil
// error means the entry should be rejected with HTTP 422
// (ErrorClassEnvelopeRejected) and the SDK's structural error
// text MUST be conveyed to the operator so the malformed
// field is visible at the front door.
//
// v1.33.0 dispatch: kind probe first, then exactly one decoder.
// The SDK's Decode functions internally invoke each payload's
// Validate(), so a decoder error for a matching kind IS the
// structural rejection.
func VerifyNetworkPayloadEntry(entry *envelope.Entry) error {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return nil
	}

	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &probe); err != nil {
		// Non-JSON or otherwise unprobeable — out of scope for
		// this validator. The SDK's broader schema gate
		// (VerifyEntrySchema) handles malformed bytes.
		return nil
	}

	switch probe.Kind {
	case network.WitnessEndpointDeclarationKindV1:
		if _, err := network.DecodeWitnessEndpointDeclarationPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: WitnessEndpointDeclarationV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case network.WitnessIdentityLabelKindV1:
		if _, err := network.DecodeWitnessIdentityLabelPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: WitnessIdentityLabelV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case network.AuditorRegistrationKindV1:
		if _, err := network.DecodeAuditorRegistrationPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: AuditorRegistrationV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case network.AuditorScopeAmendmentKindV1:
		if _, err := network.DecodeAuditorScopeAmendmentPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: AuditorScopeAmendmentV1: %s", ErrNetworkPayloadInvalid, err)
		}
	}
	return nil
}
