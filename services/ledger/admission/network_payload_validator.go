/*
FILE PATH: admission/network_payload_validator.go

v1.32.0 SDK adoption — per-Kind structural validation hook for
on-log entry kinds the SDK ships validating decoders for. Grown at
v0.0.5-rc1 (rc10) with the registry-expansion kinds:

  - ExchangeGenesisV1 + Destination{Provision,Amend,Retire}V1 (exchange/)
  - DelegationGrantV1                                  (delegation/)
  - CredentialAttestationV1                            (credential/)
  - NetworkBurnV1 — AUTHORSHIP-gated like rotation, see below

Original v1.32.0/v1.33.0 set:

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
	"github.com/baseproof/baseproof/credential"
	"github.com/baseproof/baseproof/delegation"
	"github.com/baseproof/baseproof/exchange"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/witness"
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
	case exchange.ExchangeGenesisKindV1:
		if _, err := exchange.DecodeExchangeGenesisPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: ExchangeGenesisV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case exchange.DestinationProvisionKindV1:
		if _, err := exchange.DecodeDestinationProvisionPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: DestinationProvisionV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case exchange.DestinationAmendKindV1:
		if _, err := exchange.DecodeDestinationAmendPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: DestinationAmendV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case exchange.DestinationRetireKindV1:
		if _, err := exchange.DecodeDestinationRetirePayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: DestinationRetireV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case delegation.DelegationGrantKindV1:
		if _, err := delegation.DecodeDelegationGrantPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: DelegationGrantV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case credential.CredentialAttestationKindV1:
		if _, err := credential.DecodeCredentialAttestationPayload(entry.DomainPayload); err != nil {
			return fmt.Errorf("%w: CredentialAttestationV1: %s", ErrNetworkPayloadInvalid, err)
		}
	case network.NetworkBurnKindV1:
		// rc10 — the SECOND authorship gate, same rebuild-law reasoning as
		// rotation below: the burn projection (and /v1/burn, and every v2
		// proof's burn_attestation) is a cache of the log, so the only
		// legitimate author of an on-log burn record is the burn ceremony's
		// door (baseproof/tooling#110 — collects the K-of-N witness
		// cosignatures the SDK's VerifyBurn demands, then submits through
		// its own appender). Until that door exists nothing may author a
		// burn; when it lands, it bypasses this gate by construction, like
		// ProcessRotation. A well-formed externally-POSTed burn — EVEN A
		// VALIDLY QUORUM-SIGNED ONE — is refused here so rebuilds never
		// have to adjudicate who put it there. The SDK walker's quorum
		// verification (ResolveBurnAt/VerifyBurn) stays the
		// defense-in-depth layer for every verifier outside this door.
		return fmt.Errorf("%w: NetworkBurnV1: burn records are authored only by the burn ceremony's door (baseproof/tooling#110) — external submission is refused outright",
			ErrNetworkPayloadInvalid)
	case witness.WitnessRotationPayloadKindV1:
		// PRE-6 D1 — the AUTHORSHIP gate (upgraded from the structural gate):
		// externally-submitted rotation records are refused OUTRIGHT. The
		// rebuild contract decides this, not taste: witness_sets is a cache of
		// the log, so a well-formed-but-unauthorized rotation that sequenced
		// inertly would make a future rebuild either replay it (rebuilt state
		// ≠ live state) or need an off-log author allowlist to skip it. The
		// ONLY legitimate author of an on-log rotation record is the rotation
		// door's appender (ProcessRotation → wal.Committer.Submit, which
		// bypasses this admission gate by construction) — so every rotation
		// record on the log is authoritative and rebuilds stay deterministic.
		// Operators rotate via POST /v1/network/rotation, the single intent
		// entry point. Same fail-closed-sequencing class as #76: a
		// sequenced-but-unauthorized record is log pollution wearing valid
		// syntax. Non-rotation entries pay exactly the kind probe.
		//
		// #107 (foreign rotation ingestion) names this gate a HARD
		// dependency: witness_sets ← our log ONLY is the domestic half of
		// the federation two-projection symmetry (foreign_witness_sets ←
		// each peer's log only). Weaken this arm and the rebuild law is
		// broken at home before federation even starts.
		return fmt.Errorf("%w: WitnessRotationV1: rotation records are authored only by the rotation door's appender — submit the finalized rotation to POST /v1/network/rotation instead",
			ErrNetworkPayloadInvalid)
	}
	return nil
}
