/*
FILE PATH: libs/crosslog/network_records.go

v1.32.0 SDK adoption — configuration-row → SDK-record builder
helpers for the three new resolver inputs:

  - BuildAuditorRegistryFromConfig — config slice →
    network.AuditorRegistrationByPosition (the *ByPosition slice
    the SDK's ResolveAuditorAt + DefaultAuthoritativeResolver
    consume).

  - BuildKnownWitnessKeys — bootstrap genesis set + rotation chain
    → map[[32]byte]struct{} (the KnownWitnessKeys sanity-check set
    DefaultAuthoritativeResolver consults before any
    ResolveWitness lookup).

  - BuildLogWitnessSets — per-log witness spec slice → map[logDID]
    → []PubKeyID (the LogWitnessSets map the resolver's legacy
    WitnessEndpoints fallback path uses to assemble per-log
    witness URL lists).

# WHY THESE EXIST

Without these helpers, every consumer assembles the SDK's input
shapes by hand from its own config. The same patterns get
repeated in services/auditor/main.go,
services/witness/main.go, and any CLI tool — and each one drifts
its own way. These helpers move the dispatch logic ONCE into
libs/crosslog so every consumer plugs in the same way.

# PATTERN

Mirrors witness_sets.go:133-181's BuildWitnessSets +
BuildWitnessSetsECDSAOnly pair:

  - Public function accepts a config-row slice (Spec).
  - Validates per-row (empty fields, malformed bytes, etc.).
  - Returns the SDK's typed record slice / map.
  - Errors are wrapped with row index + identifier so the
    operator's deployment manifest line is identifiable.
*/
package crosslog

import (
	"fmt"
	"sort"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// AuditorSpec is one config row for an authorized auditor. Mirrors
// the SDK's network.AuditorRegistration shape with an explicit
// EffectiveSeq so the constructor can build the
// AuditorRegistrationByPosition slice in operator-defined order.
type AuditorSpec struct {
	// EffectiveSeq is the log sequence at which this registration
	// becomes effective. Used to populate
	// AuditorRegistrationRecord.EffectivePos. Operators publishing
	// to the network in a fixed boot order set EffectiveSeq=0, 1,
	// 2, ... — the resolver's asOf check then admits all of them
	// for any asOf > the last sequence.
	EffectiveSeq uint64

	// AuditorDID is the auditor's DID (typically did:web). Required.
	AuditorDID string

	// PublicKey is the auditor's signature-verification key
	// (compressed for ECDSA; raw for BLS). Required and non-empty.
	PublicKey []byte

	// SchemeTag identifies the signature scheme. 1=ECDSA, 2=BLS.
	// Must be non-zero (the SDK validator rejects scheme_tag=0
	// as "unspecified").
	SchemeTag byte

	// ProofOfPossession is the BLS PoP bytes (mandatory for BLS;
	// MUST be empty for ECDSA per the SDK's wire contract).
	ProofOfPossession []byte

	// FindingsURL is the auditor's findings-publishing URL.
	// Required and must be a non-empty https:// URL.
	FindingsURL string

	// Scope is the bitmask of authorized capability bits. Non-zero
	// required.
	Scope network.AuditorScope

	// RetiredAt, when set, retires the auditor as of that log
	// sequence. nil means "currently active".
	RetiredAt *uint64
}

// BuildAuditorRegistryFromConfig returns the SDK-shaped
// AuditorRegistrationByPosition slice from a config-row slice.
// Each spec is validated via the SDK's
// AuditorRegistration.Validate so a malformed row surfaces at
// boot, not at first resolver lookup.
//
// Empty input yields an empty (non-nil) slice. Caller passes the
// result to NewDefaultAuthoritativeResolver via
// ResolverInputs.Materialized.Auditors, OR to the gossipingest
// AuditorScopeGate via its registry-source closure.
func BuildAuditorRegistryFromConfig(specs []AuditorSpec) (network.AuditorRegistrationByPosition, error) {
	out := make(network.AuditorRegistrationByPosition, 0, len(specs))
	for i, s := range specs {
		reg := network.AuditorRegistration{
			AuditorDID:        s.AuditorDID,
			PublicKey:         append([]byte(nil), s.PublicKey...),
			SchemeTag:         s.SchemeTag,
			ProofOfPossession: append([]byte(nil), s.ProofOfPossession...),
			FindingsURL:       s.FindingsURL,
			Scope:             s.Scope,
			RetiredAt:         s.RetiredAt,
		}
		if err := reg.Validate(); err != nil {
			return nil, fmt.Errorf("crosslog: auditor_specs[%d] (DID=%q): %w",
				i, s.AuditorDID, err)
		}
		out = append(out, network.AuditorRegistrationRecord{
			EffectivePos: types.LogPosition{Sequence: s.EffectiveSeq},
			Payload:      reg,
		})
	}
	// B1 (#21): sort by EffectivePos ascending before return. The SDK's
	// ResolveAuditorAt returns ErrAuditorRecordsUnsorted on unsorted
	// input — gating that error to reason="unsorted (operator config
	// bug)" in the reconciler is correct surfacing but a manifest the
	// operator HAPPENED to declare in order should not require them to
	// also sort it lexicographically. Sort here once so EVERY caller of
	// this constructor passes the SDK's contract regardless of whether
	// the operator's input was pre-sorted.
	sort.Sort(out)
	return out, nil
}

// WitnessEndpointSpec is one config row for an on-log witness endpoint
// declaration — the witness-side twin of AuditorSpec. Mirrors the SDK's
// network.WitnessEndpointDeclaration shape with an explicit EffectiveSeq so the
// constructor builds the WitnessEndpointDeclarationByPosition slice in
// operator-defined order.
//
// For a BLS witness, PublicKey is the 96-byte compressed G2 key,
// ProofOfPossession the 48-byte G1 PoP, and PubKeyID MUST equal
// SHA-256(PublicKey) (the SDK's Validate binds them). For an ECDSA witness,
// PublicKey + ProofOfPossession MUST be empty (the secp256k1 key is recovered
// from the witness's did:key); such a row is accepted but contributes no BLS key
// — BLSWitnessesFromDeclarations skips non-BLS schemes.
type WitnessEndpointSpec struct {
	EffectiveSeq      uint64
	PubKeyID          [32]byte
	Endpoints         map[string]string
	SchemeTag         byte
	PublicKey         []byte
	ProofOfPossession []byte
	RetiredAt         *uint64
}

// BuildWitnessEndpointsFromConfig returns the SDK-shaped
// WitnessEndpointDeclarationByPosition slice from a config-row slice, validating
// each via the SDK's WitnessEndpointDeclaration.Validate (PubKeyID non-zero,
// endpoints well-formed, and the v1.54 scheme/key/PoP contract incl.
// SHA-256(PublicKey)==PubKeyID for BLS) so a malformed row surfaces at boot, not
// at first projection. Empty input yields an empty (non-nil) slice; the result
// is sorted by EffectivePos ascending (the SDK resolver's contract).
//
// This is the file-/config-based bootstrap source — the witness twin of
// BuildAuditorRegistryFromConfig. The on-log walker (MaterializeFromEntries over
// a log scan) is the drop-in that produces the same slice once the network has
// published endpoint declarations on-log; both feed BLSWitnessesFromDeclarations
// identically.
func BuildWitnessEndpointsFromConfig(specs []WitnessEndpointSpec) (network.WitnessEndpointDeclarationByPosition, error) {
	out := make(network.WitnessEndpointDeclarationByPosition, 0, len(specs))
	for i, s := range specs {
		endpoints := make(map[string]string, len(s.Endpoints))
		for k, v := range s.Endpoints {
			endpoints[k] = v
		}
		decl := network.WitnessEndpointDeclaration{
			PubKeyID:          s.PubKeyID,
			Endpoints:         endpoints,
			SchemeTag:         s.SchemeTag,
			PublicKey:         append([]byte(nil), s.PublicKey...),
			ProofOfPossession: append([]byte(nil), s.ProofOfPossession...),
			RetiredAt:         s.RetiredAt,
		}
		if err := decl.Validate(); err != nil {
			return nil, fmt.Errorf("crosslog: witness_endpoint_specs[%d] (pub_key_id=%x): %w",
				i, s.PubKeyID, err)
		}
		out = append(out, network.WitnessEndpointDeclarationRecord{
			EffectivePos: types.LogPosition{Sequence: s.EffectiveSeq},
			Payload:      decl,
		})
	}
	sort.Sort(out)
	return out, nil
}

// BuildKnownWitnessKeys assembles the KnownWitnessKeys sanity-check
// set for *discover.DefaultAuthoritativeResolver. The set is the
// union of:
//
//   - genesisKeys (the bootstrap document's genesis witness set)
//   - rotations[*] (each successive on-log witness-rotation record)
//
// Every PubKeyID that has ever cosigned a head reachable from
// genesis ends up in the set. The resolver consults the set
// BEFORE every ResolveWitness lookup; a PubKeyID not in the set
// is unresolvable (ErrWitnessKeyUnknown) — preventing a forged
// declaration for a never-rotated-in key from leaking out.
//
// rotations may be nil or empty (single-set deployments that
// have never rotated). genesisKeys MUST be non-empty — a
// resolver constructed without genesis keys can never resolve
// any witness.
func BuildKnownWitnessKeys(
	genesisKeys []types.WitnessPublicKey,
	rotations [][]types.WitnessPublicKey,
) (map[[32]byte]struct{}, error) {
	if len(genesisKeys) == 0 {
		return nil, fmt.Errorf(
			"crosslog: BuildKnownWitnessKeys: genesis witness set must be non-empty")
	}
	out := make(map[[32]byte]struct{}, len(genesisKeys))
	for _, k := range genesisKeys {
		out[k.ID] = struct{}{}
	}
	for _, rot := range rotations {
		for _, k := range rot {
			out[k.ID] = struct{}{}
		}
	}
	return out, nil
}

// BuildLogWitnessSets returns the LogWitnessSets map for
// *discover.DefaultAuthoritativeResolver from a per-log
// WitnessSetSpec slice (the same spec type BuildWitnessSets
// already consumes for the cosign-side KeySet construction).
//
// The map key is the spec's LogDID; the value is the flat list
// of PubKeyIDs derived from:
//
//   - spec.WitnessDIDs via witness.KeysFromDIDs (ECDSA), AND
//   - spec.BLSWitnesses[*].ID (raw [32]byte BLS key IDs)
//
// Duplicate LogDID across specs is rejected. Empty spec slice
// yields an empty (non-nil) map.
func BuildLogWitnessSets(specs []WitnessSetSpec) (map[string][][32]byte, error) {
	out := make(map[string][][32]byte, len(specs))
	for i, s := range specs {
		if s.LogDID == "" {
			return nil, fmt.Errorf("crosslog: witness_set_specs[%d]: log_did required", i)
		}
		if _, dup := out[s.LogDID]; dup {
			return nil, fmt.Errorf("crosslog: duplicate witness set for log_did %q", s.LogDID)
		}
		keys, err := assembleKeys(s)
		if err != nil {
			return nil, fmt.Errorf("crosslog: witness_set_specs[%d] (log_did=%q): %w",
				i, s.LogDID, err)
		}
		ids := make([][32]byte, 0, len(keys))
		for _, k := range keys {
			ids = append(ids, k.ID)
		}
		out[s.LogDID] = ids
	}
	return out, nil
}
