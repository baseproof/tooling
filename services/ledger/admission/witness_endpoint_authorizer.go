/*
FILE PATH: admission/witness_endpoint_authorizer.go

PRE-12 witness-endpoint enrollment — the admission AUTHORIZATION gate.

This is the security fix that closes the decode-only hole at
network_payload_validator.go (VerifyNetworkPayloadEntry STRUCTURALLY
validates a WitnessEndpointDeclarationV1 entry but never checks WHO
authored it). Without it, an attacker could publish a declaration for a
real witness's PubKeyID pointing at attacker-controlled URLs — hijacking
the dial-list. Closing it is what makes the on-log witness-endpoint
resolver trustworthy, which is the prerequisite that justifies the
PRE-11 LEDGER_WITNESS_ENDPOINTS deletion.

THE FIX — three orthogonal axes (zero new crypto):

  - VERIFY    (algo-dispatched): every signature on the entry verifies
    via the SDK verifier registry. ECDSA recovers the key;
    other algos resolve it. Reuses VerifyEntryAllSignatures-
    WithVerifier.
  - AUTHORIZE (algo-blind):      the declared PubKeyID is in the
    authorized witness set — constitution GenesisWitnessSet at
    bootstrap, the on-log WitnessKeySet (genesis + rotations)
    in steady state. Never reads the signature scheme.
  - BIND:                        an authorized witness PubKeyID is itself
    a signer of the entry (self-declaration). Submission is
    orthogonal to possession: Signatures[0] is the relayer
    (script / operator / the witness itself); the witness's
    attestation is one of the entry's signatures.

A hijack is UNCONSTRUCTIBLE: an attacker holds no witness private key, so
no entry can carry a verifying attestation under the target PubKeyID.

SCOPE: did:key-expressible witnesses ride the entry Signatures section,
verified by the VerifierRegistry — ECDSA (the genesis topology) today,
Ed25519 / ML-DSA / SLH-DSA the moment a witness uses one. BLS is the lone
exception BY DESIGN: its value is aggregation at finality, so it has no entry
algoID. A BLS witness instead attests via a PurposeWitnessEndpoint cosign
signature in the declaration payload, verified by the SINGLE existing cosign
BLS verifier (cosign.BLSAggregateVerifier) — never a second entry verifier,
which would duplicate the BLS chokepoint (Derive-Never-Restate). That path is
the item-6 follow-up; until it lands a BLS-only declaration finds no matching
entry signer and is refused (fail-closed).
*/
package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/witness"
)

var (
	// ErrWitnessEnrollmentUnauthorized: the declared PubKeyID is not an
	// authorized witness (absent from genesis ∪ on-log rotations).
	ErrWitnessEnrollmentUnauthorized = errors.New("admission: witness-endpoint declaration for a non-authorized PubKeyID")
	// ErrWitnessEnrollmentAttestationInvalid: a signature on the entry
	// does not verify (or the payload does not decode).
	ErrWitnessEnrollmentAttestationInvalid = errors.New("admission: witness-endpoint declaration attestation signature invalid")
	// ErrWitnessEnrollmentUnattested: no signature on the entry is from
	// the declared witness PubKeyID (submission is not possession).
	ErrWitnessEnrollmentUnattested = errors.New("admission: witness-endpoint declaration not self-attested by the declared witness")
)

// AuthorizeWitnessEndpointDeclaration enforces VERIFY + AUTHORIZE + BIND for
// a WitnessEndpointDeclarationV1 entry. Returns nil iff the declaration is
// self-attested by an authorized witness whose signature verifies; otherwise
// one of the sentinels above (all fail-closed).
//
//   - verifier is the production *did.VerifierRegistry (algo-dispatched).
//   - authorized is the witness PubKeyID set the network trusts:
//     witness.KeysFromDIDs over the constitution's GenesisWitnessSet, unioned
//     with the on-log witness-rotation chain. An empty set authorizes nobody
//     (fail-closed — every declaration is refused).
//
// Caller: the submission pipeline, alongside VerifyNetworkPayloadEntry's
// structural gate, ONLY when the entry's payload kind is
// WitnessEndpointDeclarationV1.
func AuthorizeWitnessEndpointDeclaration(
	ctx context.Context,
	entry *envelope.Entry,
	verifier attestation.SignatureVerifier,
	authorized map[[32]byte]struct{},
) error {
	if entry == nil {
		return fmt.Errorf("%w: nil entry", ErrWitnessEnrollmentAttestationInvalid)
	}
	decl, err := network.DecodeWitnessEndpointDeclarationPayload(entry.DomainPayload)
	if err != nil {
		// Defensive: the structural gate already ran; still fail-closed.
		return fmt.Errorf("%w: decode: %v", ErrWitnessEnrollmentAttestationInvalid, err)
	}

	// AUTHORIZE (algo-blind): the declared witness must be trusted.
	if _, ok := authorized[decl.PubKeyID]; !ok {
		return fmt.Errorf("%w: PubKeyID %x", ErrWitnessEnrollmentUnauthorized, decl.PubKeyID[:8])
	}

	// VERIFY (algo-dispatched): every signature on the entry verifies.
	if _, err := VerifyEntryAllSignaturesWithVerifier(ctx, entry, verifier); err != nil {
		return fmt.Errorf("%w: %v", ErrWitnessEnrollmentAttestationInvalid, err)
	}

	// BIND: an authorized witness PubKeyID is itself a signer — the
	// declaration is SELF-attested, not relayed under a borrowed identity.
	for i := range entry.Signatures {
		keys, kerr := witness.KeysFromDIDs([]string{entry.Signatures[i].SignerDID})
		if kerr != nil || len(keys) == 0 {
			continue // non-secp256k1 signer (the relayer, or a BLS did) — skip
		}
		if keys[0].ID == decl.PubKeyID {
			return nil // attested + authorized + bound
		}
	}
	return fmt.Errorf("%w: PubKeyID %x", ErrWitnessEnrollmentUnattested, decl.PubKeyID[:8])
}

// AuthorizeNetworkPayloadEntry runs the authorization gate for network-payload
// entry kinds that require one. Today only WitnessEndpointDeclarationV1 is
// authority-gated (PRE-12 enrollment); every other kind (and any non-network
// payload) returns nil. Mirrors VerifyNetworkPayloadEntry's kind-probe dispatch
// and is called alongside it in the submission pipeline (step 4h).
//
// verifier is the production *did.VerifierRegistry; authorized is the witness
// PubKeyID set (witness.KeysFromDIDs over GenesisWitnessSet, ∪ on-log
// rotations). For the gated kinds a nil verifier or empty set fails closed.
func AuthorizeNetworkPayloadEntry(
	ctx context.Context,
	entry *envelope.Entry,
	verifier attestation.SignatureVerifier,
	authorized map[[32]byte]struct{},
) error {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return nil
	}
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &probe); err != nil {
		return nil // non-JSON / unprobeable — out of scope (the schema gate handles it)
	}
	switch probe.Kind {
	case network.WitnessEndpointDeclarationKindV1:
		return AuthorizeWitnessEndpointDeclaration(ctx, entry, verifier, authorized)
	}
	return nil
}
