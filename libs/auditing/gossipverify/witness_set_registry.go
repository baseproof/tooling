// FILE PATH: libs/auditing/gossipverify/witness_set_registry.go
//
// DESCRIPTION:
//
//	WitnessSetRegistry is the live, concurrency-safe holder for the per-
//	source-log *cosign.WitnessKeySet map that cross-log verification reads.
//	It is the single most trust-sensitive object in the inbound-gossip
//	pipeline: the witness sets ARE the root of trust against which every
//	pulled CosignedTreeHead / equivocation / escrow-override finding is
//	checked. Reads (Snapshot/Get) feed VerificationContext; the single write
//	path (ApplyRotation) swaps a set ONLY after the rotation cryptographically
//	verifies against the CURRENTLY-trusted set.
//
//	ZERO-TRUST INVARIANTS:
//	  - Verify-before-swap: ApplyRotation runs witness.VerifyRotation against
//	    the current set; an unverifiable rotation never mutates trust.
//	  - Monotonic: witness.VerifyRotation pins the rotation to the current
//	    set's hash, so a stale or replayed rotation (or one targeting a
//	    superseded set) is rejected — trust cannot be reverted to an older or
//	    compromised set.
//	  - No peer input to the threshold: the new set's quorum K is a caller-
//	    supplied governance decision (cryptography proves WHO signed, never
//	    HOW MANY must).
//
//	Seeded at boot from crosslog.BuildWitnessSets; mutated only by the gossip
//	reconciler acting on a verified WitnessRotationFinding.
package gossipverify

import (
	"errors"
	"fmt"
	"sync"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// ErrWitnessRegistry wraps every WitnessSetRegistry failure. Underlying SDK
// sentinels (witness.* rotation errors, cosign keyset errors) are reachable
// via errors.Is.
var ErrWitnessRegistry = errors.New("verification/witness_set_registry")

// WitnessSetRegistry holds source-log DID → *cosign.WitnessKeySet behind a
// RWMutex. Construct via NewWitnessSetRegistry; safe for concurrent use.
type WitnessSetRegistry struct {
	mu        sync.RWMutex
	sets      map[string]*cosign.WitnessKeySet
	networkID cosign.NetworkID
}

// NewWitnessSetRegistry seeds the registry from the boot-time witness-set map
// (typically crosslog.BuildWitnessSets). networkID is the registry's home
// network identity, retained for diagnostics; rotation rebuilds inherit each
// set's OWN NetworkID (see applyRotationLocked), so a registry holding sets
// from more than one network rotates each under the identity it was seeded
// with — never a cross-network rebind. The seed map is copied; later mutation
// of the caller's map does not affect the registry.
func NewWitnessSetRegistry(seed map[string]*cosign.WitnessKeySet, networkID cosign.NetworkID) *WitnessSetRegistry {
	cp := make(map[string]*cosign.WitnessKeySet, len(seed))
	for k, v := range seed {
		cp[k] = v
	}
	return &WitnessSetRegistry{sets: cp, networkID: networkID}
}

// Get returns the current witness set for logDID.
func (r *WitnessSetRegistry) Get(logDID string) (*cosign.WitnessKeySet, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sets[logDID]
	return s, ok
}

// Snapshot returns a shallow copy of the current map for use as a
// VerificationContext.WitnessSets — a stable view for one verification pass,
// unaffected by a concurrent ApplyRotation. The *cosign.WitnessKeySet values
// are immutable after construction, so sharing the pointers is safe.
func (r *WitnessSetRegistry) Snapshot() map[string]*cosign.WitnessKeySet {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make(map[string]*cosign.WitnessKeySet, len(r.sets))
	for k, v := range r.sets {
		cp[k] = v
	}
	return cp
}

// ApplyRotation verifies a witness-set rotation against the CURRENTLY-trusted
// set for logDID and, only on success, atomically installs the new set bound to
// newQuorum. This is the sole trust-root mutation. Returns an error (and leaves
// trust unchanged) if there is no current set, the rotation does not verify
// against it, or the rotated keys + newQuorum do not form a valid keyset.
func (r *WitnessSetRegistry) ApplyRotation(logDID string, rotation types.WitnessRotation, newQuorum int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyRotationLocked(logDID, rotation, &newQuorum)
}

// ApplyVerifiedRotation installs a rotation using the rotating log's STANDING
// quorum (the current set's K), the SDK's own rotation model: witness.
// VerifyRotation rebuilds the new set under the old set's NetworkID + Quorum +
// BLSVerifier, so only the keys change. This is the path the inbound-gossip
// reconciler takes for a peer-pulled, Tier-2-verified WitnessRotationFinding:
// the new K is NOT sourced from the peer (a witness quorum cannot vote itself a
// weaker threshold) — it is the governance K already trusted for that log.
// Verify-before-swap + monotonic, identical to ApplyRotation otherwise.
func (r *WitnessSetRegistry) ApplyVerifiedRotation(logDID string, rotation types.WitnessRotation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyRotationLocked(logDID, rotation, nil)
}

// applyRotationLocked is the shared verify-before-swap body; the caller holds
// r.mu so the quorum read and the swap are one atomic step (no rotation can
// interleave between deriving K and installing the set). newQuorum == nil ⇒
// inherit the current set's quorum.
func (r *WitnessSetRegistry) applyRotationLocked(logDID string, rotation types.WitnessRotation, newQuorum *int) error {
	current, ok := r.sets[logDID]
	if !ok || current == nil {
		return fmt.Errorf("%w: no current witness set for %q", ErrWitnessRegistry, logDID)
	}
	quorum := current.Quorum()
	if newQuorum != nil {
		quorum = *newQuorum
	}
	// Verify-before-swap + monotonic: VerifyRotation checks the rotation's
	// CurrentSetHash + K-of-N signatures against the current set, so a stale or
	// replayed rotation cannot install (or revert to) an unauthorised set.
	newKeys, err := witness.VerifyRotation(rotation, current)
	if err != nil {
		return fmt.Errorf("%w: rotation verify for %q: %w", ErrWitnessRegistry, logDID, err)
	}
	// Rebuild under the SDK rotation model: NetworkID + Quorum + BLSVerifier are
	// inherited from the CURRENT SET (witness.VerifyRotation does exactly this,
	// rotation.go), so only the keys change. Two inheritances are load-bearing:
	//   - current.NetworkID(), not the registry-global ID: a registry tracking a
	//     FEDERATED peer's log must rotate that set under the peer network's own
	//     identity — rebinding to the local network's ID would silently re-home
	//     the trust root and every subsequent cosign check would dispatch against
	//     the wrong domain separator (cross-network federation correctness).
	//   - current.BLSVerifier(): on a BLS-quorum network, rebuilding with a nil
	//     BLS verifier (the NewECDSAWitnessKeySet shortcut) makes the set
	//     BLS-incapable after the first rotation, and every subsequent
	//     BLS-cosigned head fails to verify.
	next, err := cosign.NewWitnessKeySet(newKeys, current.NetworkID(), quorum, current.BLSVerifier())
	if err != nil {
		return fmt.Errorf("%w: rebuild rotated set for %q: %w", ErrWitnessRegistry, logDID, err)
	}
	r.sets[logDID] = next
	return nil
}

// Len reports how many source logs have a witness set.
func (r *WitnessSetRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sets)
}
