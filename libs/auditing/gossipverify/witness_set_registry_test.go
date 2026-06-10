package gossipverify

import (
	"errors"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

func TestWitnessSetRegistry_GetSnapshotLen(t *testing.T) {
	w := newVGWitnesses(t, 3, 2)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": w.set}, w.nid)

	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}
	got, ok := r.Get("did:log")
	if !ok || got != w.set {
		t.Fatal("Get(did:log) mismatch")
	}
	if _, ok := r.Get("did:nope"); ok {
		t.Fatal("unknown log should miss")
	}
	// Mutating a snapshot must not affect the registry.
	snap := r.Snapshot()
	if snap["did:log"] != w.set {
		t.Fatal("snapshot missing seeded set")
	}
	snap["injected"] = nil
	if r.Len() != 1 {
		t.Fatal("snapshot mutation leaked into registry")
	}
}

func TestWitnessSetRegistry_ApplyRotation_HappyPath(t *testing.T) {
	cur := newVGWitnesses(t, 3, 2)
	next := newVGWitnesses(t, 3, 2) // fresh keys
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)

	if err := r.ApplyRotation("did:log", cur.buildRotation(t, next.keys), 2); err != nil {
		t.Fatalf("ApplyRotation: %v", err)
	}
	got, _ := r.Get("did:log")
	if got == cur.set {
		t.Fatal("witness set not swapped after valid rotation")
	}
	if got.Size() != 3 || got.Quorum() != 2 {
		t.Fatalf("rotated set size=%d quorum=%d, want 3/2", got.Size(), got.Quorum())
	}
}

// The zero-trust invariant: a rotation that does NOT verify against the current
// set must leave trust completely unchanged.
func TestWitnessSetRegistry_ApplyRotation_BogusLeavesTrustUnchanged(t *testing.T) {
	cur := newVGWitnesses(t, 3, 2)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)

	bogus := types.WitnessRotation{
		CurrentSetHash:    [32]byte{0xDE, 0xAD}, // wrong hash → fails verify-before-swap
		NewSet:            cur.keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0xAA}}},
		SchemeTagNew:      signatures.SchemeECDSA,
	}
	if err := r.ApplyRotation("did:log", bogus, 2); !errors.Is(err, ErrWitnessRegistry) {
		t.Fatalf("err = %v, want ErrWitnessRegistry", err)
	}
	if got, _ := r.Get("did:log"); got != cur.set {
		t.Fatal("trust mutated despite a failed rotation")
	}
}

// A stale rotation that was valid against an OLDER set must not re-apply once
// the set has moved on (monotonicity — no revert to a superseded set).
func TestWitnessSetRegistry_ApplyRotation_StaleRotationRejected(t *testing.T) {
	gen := newVGWitnesses(t, 3, 2)
	next := newVGWitnesses(t, 3, 2)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": gen.set}, gen.nid)

	staleRot := gen.buildRotation(t, next.keys) // valid against gen
	if err := r.ApplyRotation("did:log", staleRot, 2); err != nil {
		t.Fatalf("first ApplyRotation: %v", err)
	}
	// Set is now `next`. Replaying the gen→next rotation must fail: its
	// CurrentSetHash pins `gen`, which is no longer current.
	if err := r.ApplyRotation("did:log", staleRot, 2); !errors.Is(err, ErrWitnessRegistry) {
		t.Fatalf("stale replay err = %v, want ErrWitnessRegistry", err)
	}
}

func TestWitnessSetRegistry_ApplyRotation_UnknownLog(t *testing.T) {
	cur := newVGWitnesses(t, 1, 1)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)
	if err := r.ApplyRotation("did:other", cur.buildRotation(t, cur.keys), 1); !errors.Is(err, ErrWitnessRegistry) {
		t.Fatalf("err = %v, want ErrWitnessRegistry", err)
	}
}

// ApplyVerifiedRotation installs the new set under the rotating log's STANDING
// quorum — never a peer-chosen or default K. Seeded at K=3-of-3 so a default of
// 1 or 2 would be detectable; the rotated set must still read 3-of-3.
func TestWitnessSetRegistry_ApplyVerifiedRotation_InheritsQuorum(t *testing.T) {
	cur := newVGWitnesses(t, 3, 3)
	next := newVGWitnesses(t, 3, 3) // fresh keys
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)

	if err := r.ApplyVerifiedRotation("did:log", cur.buildRotation(t, next.keys)); err != nil {
		t.Fatalf("ApplyVerifiedRotation: %v", err)
	}
	got, _ := r.Get("did:log")
	if got == cur.set {
		t.Fatal("witness set not swapped after valid rotation")
	}
	if got.Size() != 3 || got.Quorum() != 3 {
		t.Fatalf("rotated set size=%d quorum=%d, want 3/3 (inherited K)", got.Size(), got.Quorum())
	}
}

// ApplyVerifiedRotation must PRESERVE the BLS verifier across the rebuild.
// Regression for the NewECDSAWitnessKeySet(...) shortcut that rebuilt the set
// with a nil BLS verifier: on a BLS-quorum network that silently made the live
// set BLS-incapable after the first rotation, so every later BLS-cosigned head
// failed to verify. The SDK rotation model (witness.VerifyRotation) inherits
// the current set's BLSVerifier; the registry must do the same.
func TestWitnessSetRegistry_ApplyVerifiedRotation_PreservesBLSVerifier(t *testing.T) {
	cur := newVGWitnesses(t, 3, 2)
	next := newVGWitnesses(t, 3, 2) // fresh keys

	// Re-seed the registry with a BLS-CAPABLE set: same keys/quorum, but a
	// non-nil production BLS verifier (the topology a BLS-quorum log carries).
	blsCapable, err := cosign.NewWitnessKeySet(cur.keys, cur.nid, 2, cosign.NewProductionBLSVerifier())
	if err != nil {
		t.Fatalf("NewWitnessKeySet (BLS-capable seed): %v", err)
	}
	if blsCapable.BLSVerifier() == nil {
		t.Fatal("seed set should carry a non-nil BLS verifier")
	}
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": blsCapable}, cur.nid)

	if err := r.ApplyVerifiedRotation("did:log", cur.buildRotation(t, next.keys)); err != nil {
		t.Fatalf("ApplyVerifiedRotation: %v", err)
	}
	got, _ := r.Get("did:log")
	if got.BLSVerifier() == nil {
		t.Fatal("BLS verifier DROPPED across rotation — rotated set is BLS-incapable " +
			"(NewECDSAWitnessKeySet regression); subsequent BLS-cosigned heads would fail")
	}
}

// ApplyVerifiedRotation is verify-before-swap as well: a rotation that does not
// verify against the current set leaves trust completely unchanged.
func TestWitnessSetRegistry_ApplyVerifiedRotation_BogusLeavesTrustUnchanged(t *testing.T) {
	cur := newVGWitnesses(t, 3, 2)
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:log": cur.set}, cur.nid)
	bogus := types.WitnessRotation{
		CurrentSetHash:    [32]byte{0xDE, 0xAD}, // wrong hash → fails verify-before-swap
		NewSet:            cur.keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0xAA}}},
		SchemeTagNew:      signatures.SchemeECDSA,
	}
	if err := r.ApplyVerifiedRotation("did:log", bogus); !errors.Is(err, ErrWitnessRegistry) {
		t.Fatalf("err = %v, want ErrWitnessRegistry", err)
	}
	if got, _ := r.Get("did:log"); got != cur.set {
		t.Fatal("trust mutated despite a failed rotation")
	}
}

// FEDERATION CORRECTNESS: a rotated set must be rebuilt under the SET'S OWN
// NetworkID, not the registry-global one. A registry tracking a federated
// peer's log (seeded under the peer network's identity) would otherwise
// silently re-home that trust root on first rotation, and every subsequent
// cosign check would dispatch against the wrong domain separator.
func TestWitnessSetRegistry_RotationPreservesPerSetNetworkID(t *testing.T) {
	cur := newVGWitnesses(t, 3, 2)
	next := newVGWitnesses(t, 3, 2)

	// Construct the registry under a DIFFERENT (local) network ID than the
	// tracked set's own — the federated-peer shape.
	var localNID cosign.NetworkID
	for i := range localNID {
		localNID[i] = 0xEE
	}
	if localNID == cur.set.NetworkID() {
		t.Fatal("test setup: IDs must differ")
	}
	r := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{"did:peerlog": cur.set}, localNID)

	if err := r.ApplyVerifiedRotation("did:peerlog", cur.buildRotation(t, next.keys)); err != nil {
		t.Fatalf("ApplyVerifiedRotation: %v", err)
	}
	got, _ := r.Get("did:peerlog")
	if got.NetworkID() != cur.set.NetworkID() {
		t.Fatalf("rotated set NetworkID = %x, want the set's own %x (not the registry-global %x)",
			got.NetworkID(), cur.set.NetworkID(), localNID)
	}
}
