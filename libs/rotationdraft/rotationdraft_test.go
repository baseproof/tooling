/*
FILE PATH: libs/rotationdraft/rotationdraft_test.go

DESCRIPTION:

	The ceremony's cryptographic round-trip, judged by the SDK's OWN full
	recipe: a draft is built against a live-derived current set, ONE
	offline consent is signed with the current witness's key (the exact
	bytes the online purpose=rotation flow signs), Finalize assembles the
	on-log rotation — and witness.VerifyRotation(rotation, currentSet)
	(set-hash rebind, scheme enforcement, OLD K-of-N quorum) must accept
	it. If offline consents were not interchangeable with online ones,
	this test could not pass.

	Refusals pinned: a consent bound to a DIFFERENT proposal (new-set
	hash) or a different network never rides; zero consents fail the SDK's
	structural door at Finalize.
*/
package rotationdraft

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/witness"
)

func TestCeremony_OfflineConsentsVerifyUnderTheSDKRecipe(t *testing.T) {
	// CURRENT set: one witness whose private key we hold (K=1).
	curKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	curKeys, err := witness.KeysFromDIDs([]string{curKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\xab", 32)))
	curSet, err := cosign.NewECDSAWitnessKeySet(curKeys, cosign.NetworkID(nid), 1)
	if err != nil {
		t.Fatal(err)
	}

	// NEW set: a fresh witness.
	newKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := witness.KeysFromDIDs([]string{newKP.DID})
	if err != nil {
		t.Fatal(err)
	}

	curHash := witness.ComputeSetHash(curKeys)
	d := &Draft{
		SchemaVersion:  DraftFormat,
		NetworkIDHex:   hex.EncodeToString(nid[:]),
		CurrentSetHash: hex.EncodeToString(curHash[:]),
		NewSet: []Key{{
			IDHex:     hex.EncodeToString(newKeys[0].ID[:]),
			PublicKey: hex.EncodeToString(newKeys[0].PublicKey),
			SchemeTag: newKeys[0].SchemeTag,
		}},
	}

	// The CURRENT witness consents offline (the OLD K-of-N authority), and
	// the NEW witness dual-signs the same proposal (the structural door's
	// new_signatures requirement) — both via the SAME consent artifact.
	consent, err := d.SignConsent(curKeys[0].ID, curKeys[0].SchemeTag, curKP.PrivateKey)
	if err != nil {
		t.Fatalf("current consent: %v", err)
	}
	newConsent, err := d.SignConsent(newKeys[0].ID, newKeys[0].SchemeTag, newKP.PrivateKey)
	if err != nil {
		t.Fatalf("new consent: %v", err)
	}

	// Finalize + the SDK's FULL recipe as the oracle.
	rotation, err := d.Finalize([]*Consent{consent}, []*Consent{newConsent})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, err := witness.VerifyRotation(rotation, curSet); err != nil {
		t.Fatalf("the SDK recipe must accept an offline-assembled ceremony: %v", err)
	}

	// Refusal: a consent for a DIFFERENT proposal never rides.
	other := *consent
	other.NewSetHashHex = strings.Repeat("ee", 32)
	if _, err := d.Finalize([]*Consent{&other}, []*Consent{newConsent}); err == nil || !strings.Contains(err.Error(), "DIFFERENT proposal") {
		t.Fatalf("cross-proposal consent must refuse: %v", err)
	}

	// Refusal: a consent bound to another network never rides.
	otherNet := *consent
	otherNet.NetworkIDHex = strings.Repeat("11", 32)
	if _, err := d.Finalize([]*Consent{&otherNet}, []*Consent{newConsent}); err == nil || !strings.Contains(err.Error(), "binds network") {
		t.Fatalf("cross-network consent must refuse: %v", err)
	}

	// Refusal: zero consents fail the SDK structural door at Finalize.
	if _, err := d.Finalize(nil, nil); err == nil {
		t.Fatal("zero consents must fail ValidateWitnessRotation at finalize")
	}

	// And a TAMPERED signature is refused by the SDK recipe (not by us).
	forged := *consent
	sig := []byte(forged.SignatureB64)
	forgedRot, _ := d.Finalize([]*Consent{consent}, []*Consent{newConsent})
	forgedRot.CurrentSignatures[0].SigBytes[5] ^= 1
	if _, err := witness.VerifyRotation(forgedRot, curSet); err == nil {
		t.Fatal("a forged consent must fail the SDK quorum verification")
	}
	_ = sig
}
