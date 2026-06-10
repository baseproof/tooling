package loadgen

import (
	"strings"
	"testing"
)

// TestDeriveIdentity_Deterministic pins the reproducibility guarantee that
// replaces the legacy O(roots) keypair retention: the identity for a given
// (seed, index) is a pure function — same inputs, same DID and same private
// scalar, every time. This is what lets an amendment re-derive a root's signer on
// demand instead of holding it in memory for the whole run.
func TestDeriveIdentity_Deterministic(t *testing.T) {
	seed := seedBytes(1)
	for _, idx := range []uint64{0, 1, 7, 1024, 1 << 20} {
		a, err := deriveIdentity(seed, idx)
		if err != nil {
			t.Fatalf("derive idx=%d: %v", idx, err)
		}
		b, err := deriveIdentity(seed, idx)
		if err != nil {
			t.Fatalf("re-derive idx=%d: %v", idx, err)
		}
		if a.DID != b.DID {
			t.Errorf("idx=%d: DID not stable: %q vs %q", idx, a.DID, b.DID)
		}
		if a.Priv.D.Cmp(b.Priv.D) != 0 {
			t.Errorf("idx=%d: private scalar not stable", idx)
		}
		// did:key must be the W3C spec-compliant base58btc form (creation.go drops
		// the legacy did:key:f<hex>); the ledger's resolver expects exactly this.
		if !strings.HasPrefix(a.DID, "did:key:z") {
			t.Errorf("idx=%d: DID %q is not a spec-compliant did:key:z…", idx, a.DID)
		}
	}
}

// TestDeriveDelegate_DistinctFromOwner proves the delegate keyspace is disjoint
// from the owner keyspace: at the same index the delegate is a DIFFERENT key
// (a delegated amendment must be signed by a genuinely different signer than the
// entity it acts on), yet still deterministic.
func TestDeriveDelegate_DistinctFromOwner(t *testing.T) {
	seed := seedBytes(1)
	for _, idx := range []uint64{0, 1, 99, 4096} {
		owner, err := deriveIdentity(seed, idx)
		if err != nil {
			t.Fatalf("owner idx=%d: %v", idx, err)
		}
		del, err := deriveDelegateIdentity(seed, idx)
		if err != nil {
			t.Fatalf("delegate idx=%d: %v", idx, err)
		}
		if owner.DID == del.DID {
			t.Errorf("idx=%d: delegate DID equals owner DID — must be a different key", idx)
		}
		if del2, _ := deriveDelegateIdentity(seed, idx); del.DID != del2.DID {
			t.Errorf("idx=%d: delegate identity not deterministic", idx)
		}
	}
}

// TestDeriveIdentity_DistinctPerIndex proves distinct roots get distinct
// identities (no key reuse across leaves) and that the keyspace is seed-scoped
// (a different seed reproduces a different run, not the same one).
func TestDeriveIdentity_DistinctPerIndex(t *testing.T) {
	seed := seedBytes(1)
	seen := map[string]uint64{}
	for idx := uint64(0); idx < 2048; idx++ {
		id, err := deriveIdentity(seed, idx)
		if err != nil {
			t.Fatalf("derive idx=%d: %v", idx, err)
		}
		if prev, dup := seen[id.DID]; dup {
			t.Fatalf("DID collision: idx %d and %d derived the same DID %q", prev, idx, id.DID)
		}
		seen[id.DID] = idx
	}

	// Same index, different seed ⇒ different identity (seed actually scopes the run).
	x, _ := deriveIdentity(seedBytes(1), 42)
	y, _ := deriveIdentity(seedBytes(2), 42)
	if x.DID == y.DID {
		t.Errorf("seed is not scoping the keyspace: seed=1 and seed=2 derived the same DID for idx=42")
	}
}
