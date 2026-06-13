package main

import (
	"context"
	"testing"

	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// TestBuildSignedWitnessDeclaration_AdmittedByKeystone closes the producer→
// verifier loop: the entry this producer mints (through the real signing path)
// is admitted by the keystone authorizer with the witness's PubKeyID in the
// authorized set. Make-Invalid-Unconstructible — the producer builds through
// exactly what the verifier checks.
func TestBuildSignedWitnessDeclaration_AdmittedByKeystone(t *testing.T) {
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	keys, err := witness.KeysFromDIDs([]string{kp.DID})
	if err != nil || len(keys) != 1 {
		t.Fatalf("KeysFromDIDs: keys=%d err=%v", len(keys), err)
	}
	pubKeyID := keys[0].ID

	entry, wire, err := buildSignedWitnessDeclaration(
		kp.PrivateKey, kp.DID, pubKeyID, "did:web:net.log",
		defaultWitnessServiceType, "https://w1.example.com", nil, nil)
	if err != nil {
		t.Fatalf("buildSignedWitnessDeclaration: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("empty serialized wire")
	}

	reg, err := sdkdid.DefaultVerifierRegistry(
		"did:web:net.log", sdkdid.NewKeyResolver(), sdkdid.PKHVerifierOptions{})
	if err != nil {
		t.Fatalf("DefaultVerifierRegistry: %v", err)
	}
	authorized := map[[32]byte]struct{}{pubKeyID: {}}
	if err := admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, reg, authorized); err != nil {
		t.Fatalf("the producer's signed declaration must be admitted by the keystone authorizer, got: %v", err)
	}

	// Negative control: the SAME entry is refused when the witness is NOT in
	// the authorized set — the producer cannot mint trust it doesn't have.
	if err := admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, reg, map[[32]byte]struct{}{}); err == nil {
		t.Fatal("a declaration from a non-authorized witness must be refused")
	}
}
