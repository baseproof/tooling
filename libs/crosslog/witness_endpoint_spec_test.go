package crosslog

import (
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"
)

// blsSpec lifts a real BLS witness declaration (from blsWitnessDecl) into a
// WitnessEndpointSpec config row.
func blsSpec(t *testing.T, seq uint64) (WitnessEndpointSpec, [32]byte) {
	t.Helper()
	rec, id := blsWitnessDecl(t, seq)
	p := rec.Payload
	return WitnessEndpointSpec{
		EffectiveSeq:      seq,
		PubKeyID:          p.PubKeyID,
		Endpoints:         p.Endpoints,
		SchemeTag:         p.SchemeTag,
		PublicKey:         p.PublicKey,
		ProofOfPossession: p.ProofOfPossession,
	}, id
}

// TestBuildWitnessEndpointsFromConfig_BuildsValidatesProjects pins the
// config-row → SDK-record → projection path (the witness twin of the
// AuditorSpec flow): a real BLS spec builds a validated record that
// BLSWitnessesFromDeclarationsLatest projects back to the same witness.
func TestBuildWitnessEndpointsFromConfig_BuildsValidatesProjects(t *testing.T) {
	spec, id := blsSpec(t, 5)
	records, err := BuildWitnessEndpointsFromConfig([]WitnessEndpointSpec{spec})
	if err != nil {
		t.Fatalf("BuildWitnessEndpointsFromConfig: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("built %d records, want 1", len(records))
	}
	out, err := BLSWitnessesFromDeclarationsLatest(records, [][32]byte{id})
	if err != nil {
		t.Fatalf("BLSWitnessesFromDeclarationsLatest: %v", err)
	}
	if len(out) != 1 || out[0].ID != id {
		t.Fatalf("projected %d witnesses, want the one BLS witness %x", len(out), id)
	}
}

// TestBuildWitnessEndpointsFromConfig_RejectsBadKeyMaterial confirms each row is
// run through the SDK's Validate (incl. SHA-256(PublicKey)==PubKeyID for BLS), so
// a malformed manifest line fails at boot, not at first projection.
func TestBuildWitnessEndpointsFromConfig_RejectsBadKeyMaterial(t *testing.T) {
	spec, _ := blsSpec(t, 5)
	spec.PubKeyID[0] ^= 0xFF // break the SDK's PublicKey↔PubKeyID binding
	if _, err := BuildWitnessEndpointsFromConfig([]WitnessEndpointSpec{spec}); err == nil {
		t.Fatal("expected Validate rejection for PubKeyID/key mismatch")
	}
}

func TestBLSWitnessesFromDeclarationsLatest_Empty(t *testing.T) {
	if out, err := BLSWitnessesFromDeclarationsLatest(nil, [][32]byte{{0x01}}); err != nil || out != nil {
		t.Fatalf("nil records: got (%v,%v), want (nil,nil)", out, err)
	}
	rec, _ := blsWitnessDecl(t, 5)
	recs := network.WitnessEndpointDeclarationByPosition{rec}
	if out, err := BLSWitnessesFromDeclarationsLatest(recs, nil); err != nil || out != nil {
		t.Fatalf("nil authorized: got (%v,%v), want (nil,nil)", out, err)
	}
}

// TestWitnessEndpointSpec_EndToEnd mirrors the flow JN / every network consumes:
// config rows → SDK records → project latest → BuildWitnessSetsForPolicy builds
// the verifying keyset (the BLS PoP is checked at construction). No JN-local
// walker code — the whole pipeline is domain-agnostic crosslog.
func TestWitnessEndpointSpec_EndToEnd(t *testing.T) {
	spec, id := blsSpec(t, 5)
	records, err := BuildWitnessEndpointsFromConfig([]WitnessEndpointSpec{spec})
	if err != nil {
		t.Fatalf("build records: %v", err)
	}
	blsWits, err := BLSWitnessesFromDeclarationsLatest(records, [][32]byte{id})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	setSpec := WitnessSetSpec{LogDID: "did:web:bls-log", BLSWitnesses: blsWits, QuorumK: 1}
	sets, err := BuildWitnessSetsForPolicy([]WitnessSetSpec{setSpec}, testNetworkID(),
		[]uint8{signatures.SchemeECDSA, signatures.SchemeBLS})
	if err != nil {
		t.Fatalf("BuildWitnessSetsForPolicy: %v", err)
	}
	if sets["did:web:bls-log"] == nil {
		t.Fatal("missing keyset")
	}
}
