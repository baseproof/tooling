package crosslog

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// ───────────────────────────────────────────────────────────────────
// Fixtures
// ───────────────────────────────────────────────────────────────────

// blsWitnessDecl generates a REAL BLS-G2 witness and returns its valid
// on-log endpoint declaration record (PubKeyID == SHA-256(pub), real PoP)
// plus its PubKeyID. Because the key is real, the projected BLSWitness is
// keyset-valid — cosign.NewWitnessKeySet's PoP check will accept it.
func blsWitnessDecl(t *testing.T, seq uint64) (network.WitnessEndpointDeclarationRecord, [32]byte) {
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
	id := sha256.Sum256(pubBytes)
	decl := network.WitnessEndpointDeclaration{
		PubKeyID:          id,
		Endpoints:         map[string]string{"BaseproofWitness": "https://bls.example.org/v1/witness"},
		SchemeTag:         signatures.SchemeBLS,
		PublicKey:         pubBytes,
		ProofOfPossession: pop,
	}
	if err := decl.Validate(); err != nil {
		t.Fatalf("fixture BLS declaration must Validate: %v", err)
	}
	return network.WitnessEndpointDeclarationRecord{
		EffectivePos: types.LogPosition{Sequence: seq},
		Payload:      decl,
	}, id
}

// ecdsaWitnessDecl returns an ECDSA (absent scheme tag) endpoint
// declaration record — no on-log key material (recovered via did:key).
func ecdsaWitnessDecl(seq uint64, id [32]byte) network.WitnessEndpointDeclarationRecord {
	return network.WitnessEndpointDeclarationRecord{
		EffectivePos: types.LogPosition{Sequence: seq},
		Payload: network.WitnessEndpointDeclaration{
			PubKeyID:  id,
			Endpoints: map[string]string{"BaseproofWitness": "https://ecdsa.example.org/v1/witness"},
		},
	}
}

// ───────────────────────────────────────────────────────────────────
// BLSWitnessesFromDeclarations
// ───────────────────────────────────────────────────────────────────

func TestBLSWitnessesFromDeclarations_Empty(t *testing.T) {
	out, err := BLSWitnessesFromDeclarations(nil, [][32]byte{{0x01}}, types.LogPosition{Sequence: 10})
	if err != nil || out != nil {
		t.Fatalf("empty records: got (%v, %v), want (nil, nil)", out, err)
	}
	rec, id := blsWitnessDecl(t, 5)
	out, err = BLSWitnessesFromDeclarations(
		network.WitnessEndpointDeclarationByPosition{rec}, nil, types.LogPosition{Sequence: 10})
	if err != nil || out != nil {
		t.Fatalf("empty authorized set: got (%v, %v), want (nil, nil)", out, err)
	}
	_ = id
}

func TestBLSWitnessesFromDeclarations_ProjectsBLS(t *testing.T) {
	rec, id := blsWitnessDecl(t, 5)
	records := network.WitnessEndpointDeclarationByPosition{rec}

	out, err := BLSWitnessesFromDeclarations(records, [][32]byte{id}, types.LogPosition{Sequence: 10})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("projected %d BLS witnesses, want 1", len(out))
	}
	if out[0].ID != id {
		t.Errorf("ID: got %x want %x", out[0].ID, id)
	}
	if len(out[0].PublicKey) != signatures.BLSG2CompressedLen {
		t.Errorf("PublicKey len = %d, want %d", len(out[0].PublicKey), signatures.BLSG2CompressedLen)
	}
	if len(out[0].ProofOfPossession) != signatures.BLSG1CompressedLen {
		t.Errorf("PoP len = %d, want %d", len(out[0].ProofOfPossession), signatures.BLSG1CompressedLen)
	}
}

func TestBLSWitnessesFromDeclarations_SkipsECDSA(t *testing.T) {
	var ecdsaID [32]byte
	for i := range ecdsaID {
		ecdsaID[i] = 0xEC
	}
	records := network.WitnessEndpointDeclarationByPosition{ecdsaWitnessDecl(5, ecdsaID)}
	out, err := BLSWitnessesFromDeclarations(records, [][32]byte{ecdsaID}, types.LogPosition{Sequence: 10})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if out != nil {
		t.Fatalf("ECDSA witness must NOT be projected as BLS, got %d", len(out))
	}
}

func TestBLSWitnessesFromDeclarations_MixedSet(t *testing.T) {
	blsRec, blsID := blsWitnessDecl(t, 5)
	var ecdsaID [32]byte
	for i := range ecdsaID {
		ecdsaID[i] = 0xEC
	}
	records := network.WitnessEndpointDeclarationByPosition{
		ecdsaWitnessDecl(4, ecdsaID),
		blsRec,
	}
	out, err := BLSWitnessesFromDeclarations(records, [][32]byte{ecdsaID, blsID}, types.LogPosition{Sequence: 10})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if len(out) != 1 || out[0].ID != blsID {
		t.Fatalf("mixed set: want exactly the BLS witness, got %d", len(out))
	}
}

func TestBLSWitnessesFromDeclarations_SkipsUndeclared(t *testing.T) {
	rec, id := blsWitnessDecl(t, 5)
	records := network.WitnessEndpointDeclarationByPosition{rec}
	var unknown [32]byte
	unknown[0] = 0xAA // authorized but never declared

	out, err := BLSWitnessesFromDeclarations(records, [][32]byte{id, unknown}, types.LogPosition{Sequence: 10})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if len(out) != 1 || out[0].ID != id {
		t.Fatalf("undeclared id must be skipped, got %d witnesses", len(out))
	}
}

func TestBLSWitnessesFromDeclarations_SkipsRetired(t *testing.T) {
	rec, id := blsWitnessDecl(t, 5)
	retired := uint64(50)
	rec.Payload.RetiredAt = &retired
	records := network.WitnessEndpointDeclarationByPosition{rec}

	// asOf at/after retirement → skipped.
	out, err := BLSWitnessesFromDeclarations(records, [][32]byte{id}, types.LogPosition{Sequence: 60})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if out != nil {
		t.Fatalf("retired BLS witness must be skipped, got %d", len(out))
	}
	// asOf before retirement → projected.
	out, err = BLSWitnessesFromDeclarations(records, [][32]byte{id}, types.LogPosition{Sequence: 10})
	if err != nil || len(out) != 1 {
		t.Fatalf("pre-retirement: want 1 witness, got %d (%v)", len(out), err)
	}
}

func TestBLSWitnessesFromDeclarations_UnsortedRecordsError(t *testing.T) {
	a, idA := blsWitnessDecl(t, 20)
	b, idB := blsWitnessDecl(t, 10) // earlier seq after later → unsorted
	records := network.WitnessEndpointDeclarationByPosition{a, b}
	_, err := BLSWitnessesFromDeclarations(records, [][32]byte{idA, idB}, types.LogPosition{Sequence: 100})
	if err == nil || !strings.Contains(err.Error(), "resolve witness key") {
		t.Fatalf("unsorted records: want a wrapped resolve error, got %v", err)
	}
}

// TestBLSWitnessesFromDeclarations_EndToEnd proves the projected bytes are
// keyset-valid: project a real BLS witness from the log + combine with
// ECDSA did:key witnesses, then construct the verifying keyset through the
// production BLS verifier (which PoP-checks every BLS key at admission).
func TestBLSWitnessesFromDeclarations_EndToEnd(t *testing.T) {
	blsRec, blsID := blsWitnessDecl(t, 5)
	records := network.WitnessEndpointDeclarationByPosition{blsRec}

	blsWits, err := BLSWitnessesFromDeclarations(records, [][32]byte{blsID}, types.LogPosition{Sequence: 10})
	if err != nil {
		t.Fatalf("project: %v", err)
	}

	spec := WitnessSetSpec{
		LogDID:       "did:web:mixed-log",
		WitnessDIDs:  witnessDIDs(t, 2), // ECDSA, did:key
		BLSWitnesses: blsWits,           // BLS, projected from the log
		QuorumK:      2,
	}
	sets, err := BuildWitnessSets([]WitnessSetSpec{spec}, testNetworkID(), cosign.NewProductionBLSVerifier())
	if err != nil {
		t.Fatalf("BuildWitnessSets with projected BLS witness: %v", err)
	}
	ks := sets["did:web:mixed-log"]
	if ks == nil {
		t.Fatal("missing keyset")
	}
}

// ───────────────────────────────────────────────────────────────────
// BuildWitnessSetsForPolicy
// ───────────────────────────────────────────────────────────────────

func TestBuildWitnessSetsForPolicy_ECDSAOnly(t *testing.T) {
	spec := WitnessSetSpec{LogDID: "did:web:log.a", WitnessDIDs: witnessDIDs(t, 3), QuorumK: 2}
	sets, err := BuildWitnessSetsForPolicy([]WitnessSetSpec{spec}, testNetworkID(), []uint8{signatures.SchemeECDSA})
	if err != nil {
		t.Fatalf("ECDSA-only policy: %v", err)
	}
	if sets["did:web:log.a"] == nil {
		t.Fatal("missing ECDSA keyset")
	}
}

func TestBuildWitnessSetsForPolicy_ECDSAOnly_RejectsBLSSpec(t *testing.T) {
	blsRec, blsID := blsWitnessDecl(t, 5)
	blsWits, _ := BLSWitnessesFromDeclarations(
		network.WitnessEndpointDeclarationByPosition{blsRec}, [][32]byte{blsID}, types.LogPosition{Sequence: 10})
	spec := WitnessSetSpec{LogDID: "did:web:log.a", BLSWitnesses: blsWits, QuorumK: 1}

	// Policy forbids BLS, but the spec carries a BLS witness → fail-closed
	// (the nil-verifier path rejects it loudly).
	_, err := BuildWitnessSetsForPolicy([]WitnessSetSpec{spec}, testNetworkID(), []uint8{signatures.SchemeECDSA})
	if err == nil || !strings.Contains(err.Error(), "blsVerifier is nil") {
		t.Fatalf("BLS spec under ECDSA-only policy: want blsVerifier-nil rejection, got %v", err)
	}
}

func TestBuildWitnessSetsForPolicy_BLSAdmitted(t *testing.T) {
	blsRec, blsID := blsWitnessDecl(t, 5)
	blsWits, _ := BLSWitnessesFromDeclarations(
		network.WitnessEndpointDeclarationByPosition{blsRec}, [][32]byte{blsID}, types.LogPosition{Sequence: 10})
	spec := WitnessSetSpec{
		LogDID:       "did:web:bls-log",
		WitnessDIDs:  witnessDIDs(t, 2),
		BLSWitnesses: blsWits,
		QuorumK:      2,
	}
	for _, tags := range [][]uint8{
		{signatures.SchemeECDSA, signatures.SchemeBLS},
		{signatures.SchemeBLS}, // BLS-only policy
	} {
		sets, err := BuildWitnessSetsForPolicy([]WitnessSetSpec{spec}, testNetworkID(), tags)
		if err != nil {
			t.Fatalf("policy %v: %v", tags, err)
		}
		if sets["did:web:bls-log"] == nil {
			t.Fatalf("policy %v: missing keyset", tags)
		}
	}
}

func TestBuildWitnessSetsForPolicy_UnknownScheme_FailsLoud(t *testing.T) {
	spec := WitnessSetSpec{LogDID: "did:web:log.a", WitnessDIDs: witnessDIDs(t, 3), QuorumK: 2}
	// 0x07 = ML-DSA-65: an entry-sig scheme, NOT a buildable cosign scheme.
	_, err := BuildWitnessSetsForPolicy([]WitnessSetSpec{spec}, testNetworkID(),
		[]uint8{signatures.SchemeECDSA, 0x07})
	if err == nil || !strings.Contains(err.Error(), "0x07") {
		t.Fatalf("unknown admitted scheme: want loud 0x07 rejection, got %v", err)
	}
	if !strings.Contains(err.Error(), "under-count") {
		t.Errorf("error should explain the under-count risk: %v", err)
	}
}

func TestBuildWitnessSetsForPolicy_EmptyTags_ECDSAPath(t *testing.T) {
	// Defensive: empty/absent cosign tags admit no BLS → ECDSA path.
	spec := WitnessSetSpec{LogDID: "did:web:log.a", WitnessDIDs: witnessDIDs(t, 3), QuorumK: 2}
	sets, err := BuildWitnessSetsForPolicy([]WitnessSetSpec{spec}, testNetworkID(), nil)
	if err != nil {
		t.Fatalf("empty tags: %v", err)
	}
	if sets["did:web:log.a"] == nil {
		t.Fatal("missing keyset")
	}
}
