package wire

import (
	"encoding/json"
	"testing"

	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// TestWitnessSetPubKeyIDs_ExtractsIDs locks the witness_sets row → authorized
// PubKeyID extraction (item 2 rotation union): every WitnessPublicKey.ID in the
// active set's keys_json appears in the authorized set, and malformed JSON
// errors (the provider then falls back to the constitutional genesis baseline,
// never opens).
func TestWitnessSetPubKeyIDs_ExtractsIDs(t *testing.T) {
	a := [32]byte{1, 2, 3}
	b := [32]byte{4, 5, 6}
	keysJSON, err := json.Marshal([]types.WitnessPublicKey{{ID: a}, {ID: b}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := witnessSetPubKeyIDs(keysJSON)
	if err != nil {
		t.Fatalf("witnessSetPubKeyIDs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d ids, want 2", len(got))
	}
	if _, ok := got[a]; !ok {
		t.Error("id a missing")
	}
	if _, ok := got[b]; !ok {
		t.Error("id b missing")
	}

	if _, err := witnessSetPubKeyIDs([]byte("not json")); err == nil {
		t.Fatal("malformed keys_json must error so enrollment falls back to the genesis baseline")
	}
}

// TestWitnessSetPubKeyIDs_MatchesKeysFromDIDs proves the row extraction yields
// the SAME PubKeyID the admission authorizer derives from a declaration's
// signer (witness.KeysFromDIDs). A rotated-in witness in the active witness_sets
// row is therefore authorized for enrollment byte-for-byte — no derivation skew.
func TestWitnessSetPubKeyIDs_MatchesKeysFromDIDs(t *testing.T) {
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	authKeys, err := witness.KeysFromDIDs([]string{kp.DID})
	if err != nil || len(authKeys) != 1 {
		t.Fatalf("KeysFromDIDs: keys=%d err=%v", len(authKeys), err)
	}
	// The witness_sets keys_json is the canonical []types.WitnessPublicKey wire
	// form (rotation_handler.go); marshal the authorizer's own keys into it.
	keysJSON, err := json.Marshal(authKeys)
	if err != nil {
		t.Fatalf("marshal authKeys: %v", err)
	}
	got, err := witnessSetPubKeyIDs(keysJSON)
	if err != nil {
		t.Fatalf("witnessSetPubKeyIDs: %v", err)
	}
	if _, ok := got[authKeys[0].ID]; !ok {
		t.Fatalf("KeysFromDIDs PubKeyID %x not extracted from the witness_sets row form", authKeys[0].ID)
	}
}
