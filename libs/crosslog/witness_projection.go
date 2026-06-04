/*
FILE PATH: libs/crosslog/witness_projection.go

The on-log BLS-witness projector — the consumer side of baseproof SDK
v1.54.0's WitnessEndpointDeclaration scheme/key/PoP fields.

# WHY THIS EXISTS

WitnessSetSpec.BLSWitnesses could only ever be HAND-BUILT: the sole
on-log→key projector the SDK shipped (witness.KeysFromDIDs) is
secp256k1-only, and did:key cannot encode a BLS-G2 key or its
proof-of-possession. So a BLS witness had no zero-trust source — it
had to be transcribed into operator config.

SDK v1.54.0 closed that: network.WitnessEndpointDeclaration now carries
(SchemeTag, PublicKey, ProofOfPossession), and network.ResolveWitnessKeyAt
walks the declarations to the key material in effect at a position.
BLSWitnessesFromDeclarations projects THAT into the []BLSWitness shape
BuildWitnessSets already consumes — so a BLS witness set is derived from
the replayed log (verify-on-read), not trusted from a config row.

# SET MEMBERSHIP IS NOT SELF-ASSERTED

authorizedPubKeyIDs is REQUIRED and is the set-membership authority: the
witnesses the network has actually admitted to the K-of-N quorum (the
bootstrap genesis set + the on-log witness-rotation chain). It is NOT
derived from the declarations. A declaration is self-asserted, so
treating "every BLS declaration on the log" as the witness set would let
a rogue key inject itself into the quorum. We resolve key material ONLY
for IDs the caller already knows are authorized.
*/
package crosslog

import (
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// BLSWitnessesFromDeclarations projects the on-log
// WitnessEndpointDeclaration records into the []BLSWitness shape
// WitnessSetSpec consumes, for the AUTHORIZED witness PubKeyIDs given.
//
// For each authorized pubKeyID it resolves the key material in effect at
// asOf via network.ResolveWitnessKeyAt:
//
//   - SchemeBLS  → emit a BLSWitness{ID, PublicKey, ProofOfPossession}.
//   - SchemeECDSA → SKIP: the secp256k1 key is recovered from the
//     witness's did:key (WitnessSetSpec.WitnessDIDs + witness.KeysFromDIDs),
//     not carried on-log.
//
// A pubKeyID with no declaration at asOf (ErrWitnessEndpointsNotDeclared)
// or one that is retired (ErrWitnessEndpointsRetired) is SKIPPED — a BLS
// witness that hasn't published its key yet, or has retired it, simply
// isn't projected; the K-of-N math is governed by the authorized set, not
// by this projection. Any OTHER resolver error (unsorted records, etc.)
// is returned — those are materialization/operator bugs, surfaced
// loudly rather than silently dropping a witness.
//
// An empty declaration set yields (nil, nil): a network that has
// published no endpoint declarations simply has no on-log BLS witnesses.
// The returned slice's PublicKey/ProofOfPossession are the resolver's
// defensive copies.
func BLSWitnessesFromDeclarations(
	records network.WitnessEndpointDeclarationByPosition,
	authorizedPubKeyIDs [][32]byte,
	asOf types.LogPosition,
) ([]BLSWitness, error) {
	if len(records) == 0 || len(authorizedPubKeyIDs) == 0 {
		return nil, nil
	}
	var out []BLSWitness
	for _, id := range authorizedPubKeyIDs {
		km, err := network.ResolveWitnessKeyAt(records, id, asOf)
		if err != nil {
			if errors.Is(err, network.ErrWitnessEndpointsNotDeclared) ||
				errors.Is(err, network.ErrWitnessEndpointsRetired) {
				continue // not (yet) declared, or retired — not projected
			}
			return nil, fmt.Errorf("crosslog: resolve witness key %x: %w", id, err)
		}
		if km.SchemeTag != signatures.SchemeBLS {
			continue // ECDSA witnesses come from WitnessDIDs/did:key
		}
		out = append(out, BLSWitness{
			ID:                km.PubKeyID,
			PublicKey:         km.PublicKey,
			ProofOfPossession: km.ProofOfPossession,
		})
	}
	return out, nil
}

// BLSWitnessesFromDeclarationsLatest is BLSWitnessesFromDeclarations with the
// asOf resolved automatically to the latest position present in records — the
// "current witness set" projection (the common case). Pass an explicit asOf to
// BLSWitnessesFromDeclarations for point-in-time replay.
//
// asOf is the maximum EffectivePos among records, so it is correct for records
// built by BuildWitnessEndpointsFromConfig (sequence-only positions) AND by
// MaterializeFromEntries (full LogDID@Sequence positions): asOf shares the
// records' LogDID either way, so the SDK resolver's position comparison
// (network.LogPosition.Less — LogDID then Sequence) resolves on Sequence. An
// empty record set or empty authorized set yields (nil, nil).
func BLSWitnessesFromDeclarationsLatest(
	records network.WitnessEndpointDeclarationByPosition,
	authorizedPubKeyIDs [][32]byte,
) ([]BLSWitness, error) {
	if len(records) == 0 || len(authorizedPubKeyIDs) == 0 {
		return nil, nil
	}
	var asOf types.LogPosition
	for _, r := range records {
		if asOf.Less(r.EffectivePos) {
			asOf = r.EffectivePos
		}
	}
	return BLSWitnessesFromDeclarations(records, authorizedPubKeyIDs, asOf)
}
