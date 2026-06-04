package crosslog

import (
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
)

// witnessDIDs returns n fresh did:key secp256k1 DIDs (the form
// witness.KeysFromDIDs resolves).
func witnessDIDs(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := 0; i < n; i++ {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
		}
		out[i] = kp.DID
	}
	return out
}

func TestBuildWitnessSets_HappyPath(t *testing.T) {
	nid := testNetworkID()
	setA := WitnessSetSpec{LogDID: "did:web:log.a", WitnessDIDs: witnessDIDs(t, 3), QuorumK: 2}
	setB := WitnessSetSpec{LogDID: "did:web:log.b", WitnessDIDs: witnessDIDs(t, 4), QuorumK: 3}

	out, err := BuildWitnessSetsECDSAOnly([]WitnessSetSpec{setA, setB}, nid)
	if err != nil {
		t.Fatalf("BuildWitnessSetsECDSAOnly: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	ks := out["did:web:log.a"]
	if ks == nil {
		t.Fatal("missing keyset for did:web:log.a")
	}
	if ks.Size() != 3 {
		t.Errorf("log.a Size = %d, want 3", ks.Size())
	}
	if ks.Quorum() != 2 {
		t.Errorf("log.a Quorum = %d, want 2", ks.Quorum())
	}
	if ks.NetworkID() != nid {
		t.Errorf("log.a NetworkID mismatch")
	}
	if out["did:web:log.b"].Quorum() != 3 {
		t.Errorf("log.b Quorum = %d, want 3", out["did:web:log.b"].Quorum())
	}
}

func TestBuildWitnessSets_EmptyYieldsNonNilMap(t *testing.T) {
	out, err := BuildWitnessSetsECDSAOnly(nil, testNetworkID())
	if err != nil {
		t.Fatalf("BuildWitnessSetsECDSAOnly(nil): %v", err)
	}
	if out == nil {
		t.Fatal("map must be non-nil")
	}
	if len(out) != 0 {
		t.Fatalf("len = %d, want 0", len(out))
	}
}

func TestBuildWitnessSets_RejectsEmptyLogDID(t *testing.T) {
	_, err := BuildWitnessSetsECDSAOnly([]WitnessSetSpec{
		{LogDID: "", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 1},
	}, testNetworkID())
	if err == nil {
		t.Fatal("empty LogDID must error")
	}
}

func TestBuildWitnessSets_RejectsDuplicateLogDID(t *testing.T) {
	dup := WitnessSetSpec{LogDID: "did:web:dup", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 1}
	_, err := BuildWitnessSetsECDSAOnly([]WitnessSetSpec{dup, dup}, testNetworkID())
	if err == nil {
		t.Fatal("duplicate LogDID must error")
	}
}

func TestBuildWitnessSets_RejectsBadWitnessDID(t *testing.T) {
	_, err := BuildWitnessSetsECDSAOnly([]WitnessSetSpec{
		{LogDID: "did:web:log", WitnessDIDs: []string{"did:web:not-a-key"}, QuorumK: 1},
	}, testNetworkID())
	if err == nil {
		t.Fatal("non-did:key witness must error")
	}
}

func TestBuildWitnessSets_RejectsQuorumAboveN(t *testing.T) {
	_, err := BuildWitnessSetsECDSAOnly([]WitnessSetSpec{
		{LogDID: "did:web:log", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 3},
	}, testNetworkID())
	if err == nil {
		t.Fatal("quorum > N must error")
	}
}

func TestBuildWitnessSets_RejectsZeroNetworkID(t *testing.T) {
	_, err := BuildWitnessSetsECDSAOnly([]WitnessSetSpec{
		{LogDID: "did:web:log", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 1},
	}, cosign.NetworkID{})
	if err == nil {
		t.Fatal("zero NetworkID must error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// BLS witness support
// ─────────────────────────────────────────────────────────────────────

// TestBuildWitnessSets_BLSWitnessesRequireVerifier pins the
// nil-verifier contract: a spec declaring BLS witnesses with
// blsVerifier == nil is rejected at the call site with a precise
// diagnostic (rather than falling through to the SDK's generic
// rejection later).
func TestBuildWitnessSets_BLSWitnessesRequireVerifier(t *testing.T) {
	spec := WitnessSetSpec{
		LogDID: "did:web:bls-log",
		BLSWitnesses: []BLSWitness{
			{
				ID:                [32]byte{0x01},
				PublicKey:         make([]byte, 96),
				ProofOfPossession: make([]byte, 48),
			},
		},
		QuorumK: 1,
	}
	_, err := BuildWitnessSets([]WitnessSetSpec{spec}, testNetworkID(), nil)
	if err == nil {
		t.Fatal("BLS witnesses with nil verifier must error")
	}
	if !contains(err.Error(), "blsVerifier is nil") {
		t.Errorf("error %q should reference blsVerifier", err)
	}
}

// TestBuildWitnessSets_BLSWitnessMissingPublicKey pins per-key
// validation: a BLS spec entry with empty PublicKey is rejected.
func TestBuildWitnessSets_BLSWitnessMissingPublicKey(t *testing.T) {
	spec := WitnessSetSpec{
		LogDID: "did:web:bls-log",
		BLSWitnesses: []BLSWitness{
			{
				ID:                [32]byte{0x01},
				PublicKey:         nil, // empty
				ProofOfPossession: make([]byte, 48),
			},
		},
		QuorumK: 1,
	}
	// Use the SDK's production BLS verifier so the call-site nil
	// check passes; assembly rejects on its own per-key validation.
	_, err := BuildWitnessSets([]WitnessSetSpec{spec}, testNetworkID(), cosign.NewProductionBLSVerifier())
	if err == nil {
		t.Fatal("empty PublicKey must error")
	}
	if !contains(err.Error(), "public_key required") {
		t.Errorf("error %q should reference public_key required", err)
	}
}

// TestBuildWitnessSets_BLSWitnessMissingPoP pins that BLS keys
// without proof-of-possession bytes are rejected — the SDK's
// rogue-key invariant requires PoP for every BLS key, and we
// surface the requirement at the call-site for legibility.
func TestBuildWitnessSets_BLSWitnessMissingPoP(t *testing.T) {
	spec := WitnessSetSpec{
		LogDID: "did:web:bls-log",
		BLSWitnesses: []BLSWitness{
			{
				ID:                [32]byte{0x01},
				PublicKey:         make([]byte, 96),
				ProofOfPossession: nil, // empty
			},
		},
		QuorumK: 1,
	}
	_, err := BuildWitnessSets([]WitnessSetSpec{spec}, testNetworkID(), cosign.NewProductionBLSVerifier())
	if err == nil {
		t.Fatal("empty PoP must error")
	}
	if !contains(err.Error(), "proof_of_possession required") {
		t.Errorf("error %q should reference proof_of_possession required", err)
	}
}

// TestBuildWitnessSets_BLSWitnessZeroID pins that BLS keys
// without a stable 32-byte ID are rejected. The bundle's
// CosignedTreeHead.Signatures[i].PubKeyID references this ID;
// a zero ID would collide across distinct keys.
func TestBuildWitnessSets_BLSWitnessZeroID(t *testing.T) {
	spec := WitnessSetSpec{
		LogDID: "did:web:bls-log",
		BLSWitnesses: []BLSWitness{
			{
				ID:                [32]byte{}, // zero
				PublicKey:         make([]byte, 96),
				ProofOfPossession: make([]byte, 48),
			},
		},
		QuorumK: 1,
	}
	_, err := BuildWitnessSets([]WitnessSetSpec{spec}, testNetworkID(), cosign.NewProductionBLSVerifier())
	if err == nil {
		t.Fatal("zero ID must error")
	}
	if !contains(err.Error(), "id must be non-zero") {
		t.Errorf("error %q should reference id non-zero", err)
	}
}

// TestBuildWitnessSets_BLSWitnessInvalidPoPRejectedBySDK pins
// the integration: even past our call-site checks, the SDK's
// NewWitnessKeySet runs PoP verification on every BLS key. A
// 48-byte slice of zeros is structurally well-formed but
// cryptographically invalid (it's not a valid G1 signature
// over the public key); the SDK rejects it.
func TestBuildWitnessSets_BLSWitnessInvalidPoPRejectedBySDK(t *testing.T) {
	spec := WitnessSetSpec{
		LogDID: "did:web:bls-log",
		BLSWitnesses: []BLSWitness{
			{
				ID:                [32]byte{0xAB, 0xCD},
				PublicKey:         make([]byte, 96), // bytes are zero but length OK
				ProofOfPossession: make([]byte, 48), // bytes are zero but length OK
			},
		},
		QuorumK: 1,
	}
	_, err := BuildWitnessSets([]WitnessSetSpec{spec}, testNetworkID(), cosign.NewProductionBLSVerifier())
	if err == nil {
		t.Fatal("structurally-zero BLS bytes must be rejected by SDK PoP verify")
	}
	// The SDK's NewWitnessKeySet wraps the rejection; we just
	// confirm SOME error surfaces — the SDK owns the precise
	// sentinel.
}

// TestBuildWitnessSets_MixedSchemeFromECDSAOnlyHelper pins the
// safety contract on the ECDSA-only helper: if a spec slips
// through with BLS witnesses populated, the ECDSA-only helper
// MUST reject (because it threads nil for blsVerifier).
func TestBuildWitnessSets_ECDSAOnlyHelperRejectsBLSSpec(t *testing.T) {
	spec := WitnessSetSpec{
		LogDID: "did:web:mixed-but-using-helper",
		BLSWitnesses: []BLSWitness{
			{
				ID:                [32]byte{0x01},
				PublicKey:         make([]byte, 96),
				ProofOfPossession: make([]byte, 48),
			},
		},
		QuorumK: 1,
	}
	_, err := BuildWitnessSetsECDSAOnly([]WitnessSetSpec{spec}, testNetworkID())
	if err == nil {
		t.Fatal("ECDSA-only helper must reject BLS-bearing spec")
	}
}

// contains is strings.Contains shim — kept local to avoid an
// import sprawl for a single test-only helper.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
