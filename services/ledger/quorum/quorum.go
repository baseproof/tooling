/*
Package quorum is the single source of truth for the ledger's active
witness key set — the K-of-N topology every cosignature check resolves
against (admission embedded-tree-head verification, the equivocation
monitor, and witness-set rotation).

# Why this package exists

Before consolidation the witness key set was constructed three times —
once each in the admission wiring, the rotation handler, and the
equivocation monitor — every site independently calling KeysFromDIDs +
NewWitnessKeySet + NewProductionBLSVerifier. That fragmentation had two
costs:

  - Post-rotation staleness. The rotation handler swapped its own copy
    on a rotation; the admission gate and the equivocation monitor kept
    their boot-time copies and silently verified against stale keys.
  - A false BLS impression. Every site passed a real gnark-backed BLS
    verifier (NewProductionBLSVerifier) even though the only key loader
    (witness.KeysFromDIDs) resolves secp256k1 DIDs ONLY — so no BLS key
    could ever enter the set. The verifier had nothing to chew on.

Manager replaces all three with one atomic.Pointer the readers share.

# Concurrency

cosign.WitnessKeySet is immutable after construction (NewWitnessKeySet
makes a defensive key copy and freezes its lookup tables). That
immutability is what makes a whole-pointer swap correct: Current()
readers on the admission hot path are wait-free and always observe a
complete set — either the pre-rotation one or the post-rotation one,
never a torn state. Update() (the rotation handler, off the hot path)
is a single atomic store; the previous set is GC'd once in-flight
readers release it. No mutex, no cache-line contention under the
1k+ TPS admission load.

# BLS: policy-driven, verified at the keyset seam

NewKeySet selects the cosignature verifier from the network's signature
policy: AllowedCosignSchemeTags admitting SchemeBLS (0x02) wires a
gnark-backed cosign.NewProductionBLSVerifier; an ECDSA-only policy stays
verifier-free (NewECDSAWitnessKeySet, byte-identical to before).
cosign.Verify dispatches per-signature on SchemeTag — an ECDSA-only set
never touches the BLS path; under a BLS-admitting policy a BLS cosignature
is fully verified instead of failing cosign.ErrBLSVerifierRequired.

The ledger stays "dumb but verifies integrity": it does NOT resolve or
decide witness membership for BLS. Membership stays where it always was —
the genesis did:key set and on-log witness rotations, both cryptographically
verified. A BLS witness joins via a rotation whose NewSet carries the 96-byte
G2 key + 48-byte proof-of-possession; VerifyRotation proves the OLD K-of-N
authorized it and NewWitnessKeySet PoP-verifies the new BLS keys against the
wired verifier. Wiring that verifier (policy-driven) is the whole change;
the consumers (admission gate, equivocation monitor, rotation handler that
inherits the verifier via cur.BLSVerifier()) observe BLS with no ripple.

LoadWitnessKeys still resolves the GENESIS set as secp256k1 did:keys — a BLS
key cannot be a did:key, so BLS witnesses never enter at genesis; they join
on-log via the verified rotation above.
*/
package quorum

import (
	"sync/atomic"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// Manager holds the active *cosign.WitnessKeySet behind an
// atomic.Pointer. Constructed once at boot and shared by the admission
// verifier and the equivocation monitor (readers, via Current) and the
// rotation handler (writer, via Update).
type Manager struct {
	set atomic.Pointer[cosign.WitnessKeySet]
}

// NewManager returns a Manager seeded with initial, which may be nil
// for a deployment with no genesis witness set — Current then reports
// nil and consumers treat the quorum gate as unavailable.
func NewManager(initial *cosign.WitnessKeySet) *Manager {
	m := &Manager{}
	if initial != nil {
		m.set.Store(initial)
	}
	return m
}

// Current returns the active witness key set, or nil if none is
// installed. Wait-free and safe for concurrent use — this is the
// admission hot-path read.
func (m *Manager) Current() *cosign.WitnessKeySet {
	if m == nil {
		return nil
	}
	return m.set.Load()
}

// Update atomically installs newSet as the active key set. Called by
// the rotation handler after a rotation has verified and persisted.
func (m *Manager) Update(newSet *cosign.WitnessKeySet) {
	if m == nil {
		return
	}
	m.set.Store(newSet)
}

// LoadWitnessKeys resolves the GENESIS witness DIDs into public keys.
// secp256k1 (ECDSA) ONLY — witness.KeysFromDIDs rejects non-secp256k1
// did:key forms, and a BLS key cannot be a did:key (the multicodec carries
// no proof-of-possession slot). BLS witnesses therefore never enter at
// genesis; they join on-log via a verified witness rotation whose NewSet
// carries the BLS key + PoP directly (see NewKeySet + the package doc).
func LoadWitnessKeys(dids []string) ([]types.WitnessPublicKey, error) {
	return witness.KeysFromDIDs(dids)
}

// NewKeySet builds the witness key set, selecting the cosignature verifier
// from the network's signature policy. When allowedCosignSchemeTags admits
// SchemeBLS (0x02) it wires cosign.NewProductionBLSVerifier so a BLS witness's
// cosignature — and the proof-of-possession on its key — are fully verified;
// otherwise it builds an ECDSA-only set (NewECDSAWitnessKeySet, no gnark
// verifier constructed), byte-identical to the prior behavior.
//
// The ledger makes no membership decision here — it only gains the machinery
// to VERIFY whichever cosign schemes the policy admits. cosign.Verify still
// dispatches per-signature on SchemeTag; ValidateCosignSchemePolicy still gates
// which schemes a witness may contribute; a BLS key's PoP is verified at set
// construction. The selection mirrors crosslog.BuildWitnessSetsForPolicy,
// applied to the ledger's already-resolved key list (genesis did:keys + on-log
// rotation sets).
func NewKeySet(keys []types.WitnessPublicKey, networkID cosign.NetworkID, quorumK int, allowedCosignSchemeTags []uint8) (*cosign.WitnessKeySet, error) {
	if cosignSchemeAdmitsBLS(allowedCosignSchemeTags) {
		return cosign.NewWitnessKeySet(keys, networkID, quorumK, cosign.NewProductionBLSVerifier())
	}
	return cosign.NewECDSAWitnessKeySet(keys, networkID, quorumK)
}

// cosignSchemeAdmitsBLS reports whether the network's AllowedCosignSchemeTags
// admits BLS (signatures.SchemeBLS) — the signal to wire a BLS aggregate
// verifier so BLS witness cosignatures verify rather than fail
// ErrBLSVerifierRequired.
func cosignSchemeAdmitsBLS(allowed []uint8) bool {
	for _, tag := range allowed {
		if tag == signatures.SchemeBLS {
			return true
		}
	}
	return false
}
