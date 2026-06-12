/*
FILE PATH: cmd/genesis-endorse/rotation_consent_test.go

DESCRIPTION:

	The consent leg, functionally (PRE-6 B2 — the dedicated test, not the
	incidental kind-switch reference): a host key in the relevant set
	produces a consent that attaches through the draft's AttachEndorsement
	path and survives the SDK's full VerifyRotation recipe; a host key
	outside the set is the membership refusal (the same guard this tool
	applies to genesis constitutions); and a consent minted for draft X
	refuses to ride under draft Y (the relay binding).
*/
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/rotationdraft"
	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

// mkRotationWitness generates a witness key in-process (the consent leg needs
// the private key value, not just a PEM path).
func mkRotationWitness(t *testing.T) (*ecdsa.PrivateKey, types.WitnessPublicKey) {
	t.Helper()
	priv, err := witkey.Generate()
	if err != nil {
		t.Fatalf("witkey.Generate: %v", err)
	}
	did, err := witkey.DID(priv)
	if err != nil {
		t.Fatalf("witkey.DID: %v", err)
	}
	keys, err := witness.KeysFromDIDs([]string{did})
	if err != nil {
		t.Fatalf("KeysFromDIDs: %v", err)
	}
	return priv, keys[0]
}

func draftKey(k types.WitnessPublicKey) rotationdraft.Key {
	return rotationdraft.Key{
		IDHex:     hex.EncodeToString(k.ID[:]),
		PublicKey: hex.EncodeToString(k.PublicKey),
		SchemeTag: k.SchemeTag,
	}
}

func writeRotationDraft(t *testing.T, dir, name string, nid [32]byte, current, next []types.WitnessPublicKey) string {
	t.Helper()
	d := &rotationdraft.Draft{
		SchemaVersion: rotationdraft.DraftFormat,
		NetworkIDHex:  hex.EncodeToString(nid[:]),
		QuorumK:       1,
	}
	for _, k := range current {
		d.CurrentSet = append(d.CurrentSet, draftKey(k))
	}
	for _, k := range next {
		d.NewSet = append(d.NewSet, draftKey(k))
	}
	path := filepath.Join(dir, name)
	if err := rotationdraft.Save(path, d); err != nil {
		t.Fatalf("save draft: %v", err)
	}
	return path
}

func TestRotationConsent_MemberConsentsAttachAndVerify(t *testing.T) {
	dir := t.TempDir()
	curPriv, curKey := mkRotationWitness(t)
	newPriv, newKey := mkRotationWitness(t)
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\x5a", 32)))

	draftPath := writeRotationDraft(t, dir, "draft.json", nid,
		[]types.WitnessPublicKey{curKey}, []types.WitnessPublicKey{newKey})

	// Both ceremony legs run the TOOL's function — the consent each host
	// would carry back.
	curConsent, curDID, err := signRotationConsent(curPriv, draftPath)
	if err != nil {
		t.Fatalf("current-member consent: %v", err)
	}
	if curConsent.Endorsement.SignerDID != curDID || curDID == "" {
		t.Fatalf("the consent's signer identity must be derived from the key (got %q)", curDID)
	}
	newConsent, _, err := signRotationConsent(newPriv, draftPath)
	if err != nil {
		t.Fatalf("new-member consent: %v", err)
	}

	// The consents attach through the draft's AttachEndorsement path and the
	// minted rotation survives the SDK's FULL recipe.
	d, err := rotationdraft.LoadDraft(draftPath)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := d.Finalize([]*rotationdraft.Consent{curConsent, newConsent})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	curSet, err := cosign.NewECDSAWitnessKeySet([]types.WitnessPublicKey{curKey}, cosign.NetworkID(nid), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := witness.VerifyRotation(rotation, curSet); err != nil {
		t.Fatalf("a tool-produced consent must be interchangeable with an online one: %v", err)
	}
}

func TestRotationConsent_OutsiderKeyRefused(t *testing.T) {
	dir := t.TempDir()
	_, curKey := mkRotationWitness(t)
	_, newKey := mkRotationWitness(t)
	outsiderPriv, _ := mkRotationWitness(t)
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\x5a", 32)))

	draftPath := writeRotationDraft(t, dir, "draft.json", nid,
		[]types.WitnessPublicKey{curKey}, []types.WitnessPublicKey{newKey})

	if _, _, err := signRotationConsent(outsiderPriv, draftPath); err == nil ||
		!strings.Contains(err.Error(), "refusing to consent") {
		t.Fatalf("a key in neither set must refuse to consent: %v", err)
	}
}

func TestRotationConsent_BindsItsOwnDraft(t *testing.T) {
	dir := t.TempDir()
	curPriv, curKey := mkRotationWitness(t)
	_, newKeyX := mkRotationWitness(t)
	_, newKeyY := mkRotationWitness(t)
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\x5a", 32)))

	draftX := writeRotationDraft(t, dir, "draft-x.json", nid,
		[]types.WitnessPublicKey{curKey}, []types.WitnessPublicKey{newKeyX})
	draftY := writeRotationDraft(t, dir, "draft-y.json", nid,
		[]types.WitnessPublicKey{curKey}, []types.WitnessPublicKey{newKeyY})

	consentX, _, err := signRotationConsent(curPriv, draftX)
	if err != nil {
		t.Fatal(err)
	}
	dY, err := rotationdraft.LoadDraft(draftY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dY.Finalize([]*rotationdraft.Consent{consentX}); err == nil ||
		!strings.Contains(err.Error(), "DIFFERENT proposal") {
		t.Fatalf("a consent minted for draft X must refuse to ride under draft Y: %v", err)
	}
}
