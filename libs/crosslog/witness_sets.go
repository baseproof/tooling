/*
FILE PATH: libs/crosslog/witness_sets.go

BuildWitnessSets resolves each configured source/peer log's
witness DIDs into a *cosign.WitnessKeySet keyed by log DID — the
per-source-log map every cross-log verification path reads
(anchor.VerifyCrossLog, in the SDK).

# WITNESS SCHEME SUPPORT

The SDK ships TWO witness signature schemes
(crypto/signatures/scheme_tags.go):

  - SchemeECDSA (0x01)  — secp256k1 ECDSA on the canonical
    tree-head digest. Default for all
    v1.x networks; resolved from did:key
    multicodec by witness.KeysFromDIDs.
  - SchemeBLS   (0x02)  — BLS12-381 G2 aggregate. Operationally
    rare today; requires per-key proof-of-
    possession (PoP) bytes the did:key
    multicodec does not carry.

This package supports BOTH per-log: a WitnessSetSpec carries
both ECDSA did:keys AND optional raw BLS public keys + PoPs. A
log's witness set may mix schemes — cosign.Verify dispatches
per-signature on SchemeTag — though most operational deployments
stay homogeneous (all ECDSA or all BLS) for verification cost.

# PRODUCTION WIRING

For BLS-enabled networks, callers MUST pass a real
BLSAggregateVerifier (cosign.NewProductionBLSVerifier()) to
BuildWitnessSets. The verifier is shared across all log keysets
in the returned map — gnark's pairing operations are expensive
to construct, so amortizing one verifier across N keysets is
the operationally correct shape.

For ECDSA-only deployments (the default — every v1.x network
today), pass nil for the BLS verifier. NewWitnessKeySet falls
through to NewECDSAWitnessKeySet semantics — a stray BLS-tagged
signature would be REJECTED at verify time with the SDK's
ErrBLSVerifierRequired (it cannot count toward quorum).

# GOAL ALIGNMENT

  - #12 post-quantum migration path — BLS support here is the
    bridge: when a network migrates to BLS witnesses (or to
    PQ-aggregate schemes that the SDK ships in a future
    version), the crosslog plane doesn't need to be re-plumbed.
  - #13 witness rotation without breaking historical bundles —
    each log's keyset is fixed at boot from its config; rotation
    is observed via re-running BuildWitnessSets after a fresh
    config load (the auditor's hot-reload boundary). Historical
    bundles use the HTTPWitnessSetResolver (libs/bundle/) keyed
    by SetHash, NOT this map.
*/
package crosslog

import (
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// WitnessSetSpec is one source/peer log's witness topology.
//
// WitnessDIDs are did:key secp256k1 identifiers — the default
// shape. witness.KeysFromDIDs resolves each to a 33-byte
// compressed public key with SchemeTag=SchemeECDSA.
//
// BLSWitnesses, when non-empty, declares ADDITIONAL or
// ALTERNATIVE BLS-G2 witnesses for this log. Each entry carries
// the raw 96-byte compressed G2 public key + the 48-byte
// proof-of-possession over that key (BLSPoPDomainTag — see
// SDK signatures/bls.go). The SDK's cosign.NewWitnessKeySet
// verifies every PoP at construction so a rogue key cannot
// admit itself to the set.
//
// A log running ECDSA-only sets BLSWitnesses to nil. A log
// running BLS-only sets WitnessDIDs to nil. A mixed-scheme log
// populates both. cosign.Verify dispatches per-signature on
// SchemeTag, so an ECDSA cosignature and a BLS cosignature on
// the same head both count toward quorum.
//
// QuorumK applies to the COMBINED set: len(WitnessDIDs) +
// len(BLSWitnesses) keys total, with K-of-N required at verify
// time.
type WitnessSetSpec struct {
	LogDID       string       `json:"log_did"`
	WitnessDIDs  []string     `json:"witness_dids,omitempty"`
	BLSWitnesses []BLSWitness `json:"bls_witnesses,omitempty"`
	QuorumK      int          `json:"quorum_k"`
}

// BLSWitness carries the raw bytes for one BLS-G2 witness key
// plus its proof-of-possession. did:key cannot carry a PoP, so
// BLS keys are declared explicitly.
//
// PublicKey: 96-byte compressed G2 public key.
// ProofOfPossession: 48-byte BLS signature over PublicKey under
//
//	the BLSPoPDomainTag. Required for BLS keys.
//
// ID: 32-byte stable identifier the bundle's
//
//	CosignedTreeHead.Signatures[i].PubKeyID references.
type BLSWitness struct {
	ID                [32]byte `json:"id"`
	PublicKey         []byte   `json:"public_key"`
	ProofOfPossession []byte   `json:"proof_of_possession"`
}

// BuildWitnessSets resolves each spec into a *cosign.WitnessKeySet
// keyed by log DID. All sets bind to networkID.
//
// blsVerifier:
//   - nil — ECDSA-only mode. Specs with non-empty BLSWitnesses
//     are rejected (the SDK's NewWitnessKeySet would fail
//     loudly; we surface a precise error here at the call
//     site).
//   - non-nil (typically cosign.NewProductionBLSVerifier()) —
//     mixed-scheme mode. BLS keys' PoPs are verified at set
//     construction.
//
// Returns an error on:
//   - duplicate / empty LogDID
//   - unresolvable did:key witness DID
//   - BLS witness present but blsVerifier == nil
//   - SDK NewWitnessKeySet rejection (invalid quorum, duplicate
//     key IDs, PoP failure, etc.)
//
// An empty spec slice yields an empty (non-nil) map.
func BuildWitnessSets(
	sets []WitnessSetSpec,
	networkID cosign.NetworkID,
	blsVerifier cosign.BLSAggregateVerifier,
) (map[string]*cosign.WitnessKeySet, error) {
	out := make(map[string]*cosign.WitnessKeySet, len(sets))
	for i, s := range sets {
		if s.LogDID == "" {
			return nil, fmt.Errorf("crosslog: witness set[%d]: log_did required", i)
		}
		if _, dup := out[s.LogDID]; dup {
			return nil, fmt.Errorf("crosslog: duplicate witness set for %q", s.LogDID)
		}
		if len(s.BLSWitnesses) > 0 && blsVerifier == nil {
			return nil, fmt.Errorf(
				"crosslog: %q declares %d BLS witnesses but blsVerifier is nil; "+
					"pass cosign.NewProductionBLSVerifier() to BuildWitnessSets",
				s.LogDID, len(s.BLSWitnesses))
		}

		keys, err := assembleKeys(s)
		if err != nil {
			return nil, fmt.Errorf("crosslog: %q: %w", s.LogDID, err)
		}

		ks, err := cosign.NewWitnessKeySet(keys, networkID, s.QuorumK, blsVerifier)
		if err != nil {
			return nil, fmt.Errorf("crosslog: %q keyset: %w", s.LogDID, err)
		}
		out[s.LogDID] = ks
	}
	return out, nil
}

// BuildWitnessSetsECDSAOnly is the legacy-shape entry point for
// callers that ONLY use ECDSA witnesses (the default for every
// v1.x network). Equivalent to BuildWitnessSets(..., nil) —
// kept as a self-documenting helper so a call site reading
// `BuildWitnessSetsECDSAOnly(specs, netID)` immediately tells
// the reader "no BLS in this deployment".
//
// Specs with non-empty BLSWitnesses are rejected (per
// BuildWitnessSets's nil-verifier contract).
func BuildWitnessSetsECDSAOnly(
	sets []WitnessSetSpec,
	networkID cosign.NetworkID,
) (map[string]*cosign.WitnessKeySet, error) {
	return BuildWitnessSets(sets, networkID, nil)
}

// BuildWitnessSetsForPolicy builds the per-log witness keysets, selecting
// the cosignature verifier from the network's SIGNATURE POLICY instead of
// a hardcoded choice. Callers resolve allowedCosignSchemeTags from
// network.ResolveSignaturePolicyAt (or the genesis policy synthesized from
// the bootstrap document) and pass it here:
//
//   - policy admits SchemeBLS (0x02) → mixed-scheme mode: a
//     cosign.NewProductionBLSVerifier() is constructed and threaded, so BLS
//     witnesses verify (PoPs checked at set construction).
//   - otherwise (the default — every ECDSA-only network) → ECDSA-only mode,
//     byte-identical to BuildWitnessSetsECDSAOnly. The gnark BLS verifier
//     (expensive to construct) is NOT built when the policy forbids BLS.
//
// FAIL-CLOSED on an admitted scheme the auditor cannot verify: if the
// policy admits any cosign scheme that is neither ECDSA nor BLS (e.g. a
// future post-quantum tag the SDK's cosign verify-dispatch does not yet
// handle), this returns an error rather than silently building a keyset
// that would UNDER-COUNT every cosignature in that scheme toward quorum.
// Surfacing it loudly is the "support all admitted algorithms / do not
// fail silently" contract at this seam.
func BuildWitnessSetsForPolicy(
	sets []WitnessSetSpec,
	networkID cosign.NetworkID,
	allowedCosignSchemeTags []uint8,
) (map[string]*cosign.WitnessKeySet, error) {
	blsAdmitted := false
	for _, tag := range allowedCosignSchemeTags {
		switch tag {
		case signatures.SchemeECDSA:
		case signatures.SchemeBLS:
			blsAdmitted = true
		default:
			return nil, fmt.Errorf(
				"crosslog: signature policy admits cosign scheme 0x%02x the auditor "+
					"cannot verify (only ECDSA=0x01 and BLS=0x02 are buildable); refusing "+
					"to build a keyset that would silently under-count that scheme toward quorum",
				tag)
		}
	}
	if blsAdmitted {
		return BuildWitnessSets(sets, networkID, cosign.NewProductionBLSVerifier())
	}
	return BuildWitnessSetsECDSAOnly(sets, networkID)
}

// assembleKeys merges WitnessDIDs (resolved via
// witness.KeysFromDIDs as ECDSA) with BLSWitnesses (raw bytes
// projected into types.WitnessPublicKey with SchemeTag=BLS) into
// the flat slice cosign.NewWitnessKeySet wants.
func assembleKeys(s WitnessSetSpec) ([]types.WitnessPublicKey, error) {
	var combined []types.WitnessPublicKey

	if len(s.WitnessDIDs) > 0 {
		ecdsa, err := witness.KeysFromDIDs(s.WitnessDIDs)
		if err != nil {
			return nil, fmt.Errorf("witness DIDs: %w", err)
		}
		combined = append(combined, ecdsa...)
	}

	for j, b := range s.BLSWitnesses {
		if len(b.PublicKey) == 0 {
			return nil, fmt.Errorf("bls_witnesses[%d]: public_key required", j)
		}
		if len(b.ProofOfPossession) == 0 {
			return nil, fmt.Errorf("bls_witnesses[%d]: proof_of_possession required for BLS key", j)
		}
		var zero [32]byte
		if b.ID == zero {
			return nil, fmt.Errorf("bls_witnesses[%d]: id must be non-zero", j)
		}
		combined = append(combined, types.WitnessPublicKey{
			ID:                b.ID,
			PublicKey:         append([]byte(nil), b.PublicKey...), // defensive copy
			SchemeTag:         signatures.SchemeBLS,
			ProofOfPossession: append([]byte(nil), b.ProofOfPossession...), // defensive copy
		})
	}

	return combined, nil
}
