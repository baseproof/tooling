package quorum_test

import (
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/quorum"
)

func netID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// keySet builds a one-key ECDSA witness set via the production seam.
// The key is a real secp256k1 point derived deterministically from id
// so distinct ids yield distinct, valid keys: baseproof v1.14.0's
// NewWitnessKeySet rejects a key whose bytes don't parse on the curve,
// whose ID isn't sha256(pubkey), or whose SchemeTag is unset.
func keySet(t *testing.T, id byte) *cosign.WitnessKeySet {
	t.Helper()
	scalar := make([]byte, 32)
	scalar[31] = id
	priv, err := signatures.PrivKeyFromBytes(scalar)
	if err != nil {
		t.Fatalf("PrivKeyFromBytes(id=%d): %v", id, err)
	}
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	k := types.WitnessPublicKey{
		ID:        sha256.Sum256(pub),
		PublicKey: pub,
		SchemeTag: signatures.SchemeECDSA,
	}
	set, err := quorum.NewKeySet([]types.WitnessPublicKey{k}, netID(), 1, []uint8{signatures.SchemeECDSA})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return set
}

// blsWitnessKey builds a real BLS-G2 witness key — 96-byte compressed key +
// a valid 48-byte proof-of-possession — so NewWitnessKeySet's PoP check
// accepts it ONLY when a BLS verifier is wired.
func blsWitnessKey(t *testing.T) types.WitnessPublicKey {
	t.Helper()
	priv, pub, err := signatures.GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	pubBytes := signatures.BLSPubKeyBytes(pub)
	pop, err := signatures.SignBLSPoP(pub, priv)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}
	return types.WitnessPublicKey{
		ID:                sha256.Sum256(pubBytes),
		PublicKey:         pubBytes,
		SchemeTag:         signatures.SchemeBLS,
		ProofOfPossession: pop,
	}
}

// TestNewKeySet_PolicyDrivenBLSVerifier pins the ledger-side BLS integrity
// gate: the cosignature verifier is selected from the network's signature
// policy. A BLS-admitting policy wires a BLS aggregate verifier (so a BLS
// witness's cosignature can be cryptographically verified + counted); an
// ECDSA-only policy wires none (a stray BLS cosignature fails
// cosign.ErrBLSVerifierRequired and never counts toward quorum). The
// AllowedCosignSchemeTags allow-list (ValidateCosignSchemePolicy) gates a BLS
// key out of an ECDSA-only set upstream, so this is the verifier half of the
// "the ledger only verifies what the policy admits" contract.
func TestNewKeySet_PolicyDrivenBLSVerifier(t *testing.T) {
	t.Parallel()
	bls := blsWitnessKey(t)

	withBLS, err := quorum.NewKeySet([]types.WitnessPublicKey{bls}, netID(), 1,
		[]uint8{signatures.SchemeECDSA, signatures.SchemeBLS})
	if err != nil {
		t.Fatalf("BLS-admitting policy must build a BLS witness set: %v", err)
	}
	if withBLS.BLSVerifier() == nil {
		t.Fatal("BLS-admitting policy must wire a BLS aggregate verifier")
	}

	ecdsaOnly, err := quorum.NewKeySet([]types.WitnessPublicKey{bls}, netID(), 1,
		[]uint8{signatures.SchemeECDSA})
	if err != nil {
		t.Fatalf("ecdsa-only NewKeySet build: %v", err)
	}
	if ecdsaOnly.BLSVerifier() != nil {
		t.Fatal("ECDSA-only policy must NOT wire a BLS verifier")
	}
}

func TestManager_NilSafe(t *testing.T) {
	t.Parallel()
	if quorum.NewManager(nil).Current() != nil {
		t.Error("NewManager(nil).Current() should be nil")
	}
	var m *quorum.Manager // nil receiver
	if m.Current() != nil {
		t.Error("nil-receiver Current() should be nil")
	}
	m.Update(nil) // must not panic
}

func TestManager_UpdateSwaps(t *testing.T) {
	t.Parallel()
	a, b := keySet(t, 1), keySet(t, 2)
	m := quorum.NewManager(a)
	if m.Current() != a {
		t.Fatal("Current() != seeded set")
	}
	m.Update(b)
	if m.Current() != b {
		t.Fatal("Current() != updated set after swap")
	}
}

// TestManager_ConcurrentReadDuringSwap exercises the wait-free read
// path against concurrent atomic swaps. Run with -race: a reader must
// only ever observe a complete set (the pre- or post-swap pointer),
// never a torn value.
func TestManager_ConcurrentReadDuringSwap(t *testing.T) {
	t.Parallel()
	a, b := keySet(t, 1), keySet(t, 2)
	m := quorum.NewManager(a)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				if s := m.Current(); s != a && s != b {
					t.Error("Current() returned an unknown/torn set")
					return
				}
			}
		}()
	}
	for i := 0; i < 500; i++ {
		m.Update(b)
		m.Update(a)
	}
	wg.Wait()
}
