/*
FILE PATH: libs/rotationdraft/rotationdraft_test.go

DESCRIPTION:

	The ceremony's cryptographic round-trip, judged by the SDK's OWN full
	recipe — through the SDK's RotationDraft coordinator, never around it:
	a draft carries the constructor inputs (current set, new set, quorum K),
	consents are signed offline with the EXACT bytes the online
	purpose=rotation flow signs, and ONE unsorted consent list is bucketed
	by the SDK's membership routing. Finalize self-verifies through
	VerifyRotation, so a rotation that verification would reject is
	unconstructible from this path.

	Refusals pinned at the layer that owns them:
	  - relay bindings (ours): consent for a DIFFERENT proposal / different
	    network / wrong schema never reaches assembly;
	  - membership (ours at SignConsent, SDK's at Attach): an outsider key
	    refuses to consent; a doctored scheme tag matches neither side;
	  - scheme derivation (ours): mixed or zero tags are a named refusal —
	    a wrong on-log tag is unconstructible, not merely unlikely;
	  - assembly (SDK's, surfaced verbatim): conflicting signatures for one
	    key; zero consents; a forged bit fails the self-verify AT Finalize.
*/
package rotationdraft

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

func wireKey(k types.WitnessPublicKey) Key {
	return Key{
		IDHex:     hex.EncodeToString(k.ID[:]),
		PublicKey: hex.EncodeToString(k.PublicKey),
		SchemeTag: k.SchemeTag,
	}
}

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

	d := &Draft{
		SchemaVersion: DraftFormat,
		NetworkIDHex:  hex.EncodeToString(nid[:]),
		QuorumK:       1,
		CurrentSet:    []Key{wireKey(curKeys[0])},
		NewSet:        []Key{wireKey(newKeys[0])},
	}

	// The CURRENT witness consents offline (the OLD K-of-N authority), and
	// the NEW witness signs the same proposal (the new-side section) — both
	// via the SAME consent artifact, relayed in ONE unsorted list.
	consent, err := d.SignConsent(curKP.PrivateKey)
	if err != nil {
		t.Fatalf("current consent: %v", err)
	}
	newConsent, err := d.SignConsent(newKP.PrivateKey)
	if err != nil {
		t.Fatalf("new consent: %v", err)
	}

	// Shuffled order + an idempotent byte-identical re-delivery: the SDK's
	// membership routing buckets them — the operator never sorts.
	rotation, err := d.Finalize([]*Consent{newConsent, consent, newConsent})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// CurrentSetHash is DERIVED from the draft's current set, never asserted.
	if want := witness.ComputeSetHash(curKeys); rotation.CurrentSetHash != want {
		t.Fatal("CurrentSetHash must be derived from the draft's current set")
	}
	if len(rotation.CurrentSignatures) != 1 || len(rotation.NewSignatures) != 1 {
		t.Fatalf("dedup/bucketing: current=%d new=%d, want 1/1",
			len(rotation.CurrentSignatures), len(rotation.NewSignatures))
	}

	// Independent oracle: the SDK's FULL recipe re-judges the minted bytes.
	if _, err := witness.VerifyRotation(rotation, curSet); err != nil {
		t.Fatalf("the SDK recipe must accept an offline-assembled ceremony: %v", err)
	}
}

func TestCeremony_HoldoverConsentRoutesToBothBuckets(t *testing.T) {
	// current = {A, B}, next = {B} (A retires): B's ONE consent counts as
	// predecessor authorization AND the new-side acknowledgment — the SDK's
	// routing, not operator sorting, decides.
	aKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	bKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := witness.KeysFromDIDs([]string{aKP.DID, bKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\xcd", 32)))

	// KeysFromDIDs may canonicalize order; find B by recomputing its wire key.
	bKeys, err := witness.KeysFromDIDs([]string{bKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	b := bKeys[0]

	d := &Draft{
		SchemaVersion: DraftFormat,
		NetworkIDHex:  hex.EncodeToString(nid[:]),
		QuorumK:       1,
		CurrentSet:    []Key{wireKey(keys[0]), wireKey(keys[1])},
		NewSet:        []Key{wireKey(b)},
	}
	bConsent, err := d.SignConsent(bKP.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	rotation, err := d.Finalize([]*Consent{bConsent})
	if err != nil {
		t.Fatalf("a holdover's single consent satisfies K=1 and the new side: %v", err)
	}
	if len(rotation.CurrentSignatures) != 1 || len(rotation.NewSignatures) != 1 {
		t.Fatalf("holdover must dual-route: current=%d new=%d",
			len(rotation.CurrentSignatures), len(rotation.NewSignatures))
	}
}

func TestSignConsent_OutsiderKeyRefused(t *testing.T) {
	curKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	curKeys, err := witness.KeysFromDIDs([]string{curKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	strangerKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\xab", 32)))
	d := &Draft{
		SchemaVersion: DraftFormat,
		NetworkIDHex:  hex.EncodeToString(nid[:]),
		QuorumK:       1,
		CurrentSet:    []Key{wireKey(curKeys[0])},
		NewSet:        []Key{wireKey(curKeys[0])},
	}
	_, err = d.SignConsent(strangerKP.PrivateKey)
	if err == nil || !strings.Contains(err.Error(), "refusing to consent") {
		t.Fatalf("an outsider key must be refused at the signing host: %v", err)
	}
}

func TestFinalize_RelayBindingAndSDKRefusals(t *testing.T) {
	curKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	curKeys, err := witness.KeysFromDIDs([]string{curKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	newKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := witness.KeysFromDIDs([]string{newKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\xab", 32)))
	d := &Draft{
		SchemaVersion: DraftFormat,
		NetworkIDHex:  hex.EncodeToString(nid[:]),
		QuorumK:       1,
		CurrentSet:    []Key{wireKey(curKeys[0])},
		NewSet:        []Key{wireKey(newKeys[0])},
	}
	consent, err := d.SignConsent(curKP.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	newConsent, err := d.SignConsent(newKP.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	// Relay binding: a consent for a DIFFERENT proposal never rides.
	other := *consent
	other.NewSetHashHex = strings.Repeat("ee", 32)
	if _, err := d.Finalize([]*Consent{&other, newConsent}); err == nil || !strings.Contains(err.Error(), "DIFFERENT proposal") {
		t.Fatalf("cross-proposal consent must refuse: %v", err)
	}

	// Relay binding: a consent bound to another network never rides.
	otherNet := *consent
	otherNet.NetworkIDHex = strings.Repeat("11", 32)
	if _, err := d.Finalize([]*Consent{&otherNet, newConsent}); err == nil || !strings.Contains(err.Error(), "binds network") {
		t.Fatalf("cross-network consent must refuse: %v", err)
	}

	// Relay binding: a foreign artifact schema never rides.
	otherSchema := *consent
	otherSchema.SchemaVersion = "baseproof.something-else/v1"
	if _, err := d.Finalize([]*Consent{&otherSchema, newConsent}); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("foreign schema must refuse: %v", err)
	}

	// SDK refusal, surfaced verbatim: zero consents fail the structural door.
	if _, err := d.Finalize(nil); err == nil {
		t.Fatal("zero consents must fail the SDK's structural door at Finalize")
	}

	// SDK refusal: a CONFLICTING signature for the same key (the bit-flipped
	// variant is a different byte string — conflict, detected before crypto).
	conflicting := *consent
	raw, err := hex.DecodeString(conflicting.Endorsement.Signature)
	if err != nil {
		t.Fatal(err)
	}
	raw[5] ^= 1
	conflicting.Endorsement.Signature = hex.EncodeToString(raw)
	if _, err := d.Finalize([]*Consent{consent, &conflicting, newConsent}); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting signatures for one key must refuse: %v", err)
	}

	// SDK refusal: a doctored scheme tag matches neither side at Attach.
	wrongTag := *consent
	wrongTag.Endorsement.SchemeTag = 0x7F
	if _, err := d.Finalize([]*Consent{&wrongTag, newConsent}); err == nil || !strings.Contains(err.Error(), "matches neither side") {
		t.Fatalf("a lying scheme tag must be rejected by the SDK's routing: %v", err)
	}

	// SDK self-verify AT Finalize: a forged bit alone (no honest duplicate to
	// conflict with) assembles structurally but CANNOT be minted.
	if _, err := d.Finalize([]*Consent{&conflicting, newConsent}); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a forged consent must fail the SDK's self-verify at Finalize: %v", err)
	}
}

func TestDeriveScheme_MixedOrZeroTagsAreUnconstructible(t *testing.T) {
	curKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	curKeys, err := witness.KeysFromDIDs([]string{curKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	newKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	newKeys, err := witness.KeysFromDIDs([]string{newKP.DID})
	if err != nil {
		t.Fatal(err)
	}
	var nid [32]byte
	copy(nid[:], []byte(strings.Repeat("\xab", 32)))

	// Mixed tags within one side: a named refusal — the on-log rotation
	// carries ONE tag per side, so a wrong tag is unconstructible here.
	mixedNew := wireKey(newKeys[0])
	mixedNew.SchemeTag = 2
	d := &Draft{
		SchemaVersion: DraftFormat,
		NetworkIDHex:  hex.EncodeToString(nid[:]),
		QuorumK:       1,
		CurrentSet:    []Key{wireKey(curKeys[0])},
		NewSet:        []Key{wireKey(curKeys[0]), mixedNew},
	}
	if _, err := d.SDKDraft(); err == nil || !strings.Contains(err.Error(), "mixed signature schemes") {
		t.Fatalf("mixed tags must refuse derivation: %v", err)
	}

	// A zero tag is never guessed into a default.
	zeroTag := wireKey(newKeys[0])
	zeroTag.SchemeTag = 0
	d.NewSet = []Key{zeroTag}
	if _, err := d.SDKDraft(); err == nil || !strings.Contains(err.Error(), "zero") {
		t.Fatalf("a zero tag must refuse derivation: %v", err)
	}

	// QuorumK is the SDK constructor's to validate — out-of-range surfaces.
	d.NewSet = []Key{wireKey(newKeys[0])}
	d.QuorumK = 0
	if _, err := d.SDKDraft(); err == nil || !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("K=0 must be refused by the SDK constructor: %v", err)
	}
}

func TestFileRoundTrip_StrictDecode(t *testing.T) {
	dir := t.TempDir()
	d := &Draft{
		SchemaVersion: DraftFormat,
		NetworkIDHex:  strings.Repeat("ab", 32),
		QuorumK:       1,
		CurrentSet:    []Key{{IDHex: strings.Repeat("01", 32), PublicKey: "04aa", SchemeTag: 1}},
		NewSet:        []Key{{IDHex: strings.Repeat("02", 32), PublicKey: "04bb", SchemeTag: 1}},
	}
	path := filepath.Join(dir, "draft.json")
	if err := Save(path, d); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDraft(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.QuorumK != 1 || len(got.CurrentSet) != 1 || got.CurrentSet[0].IDHex != d.CurrentSet[0].IDHex {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Unknown fields are refused (DisallowUnknownFields) — a future schema
	// is a NAMED refusal, never silently dropped data.
	bad := filepath.Join(dir, "unknown.json")
	if err := Save(bad, map[string]any{"schema_version": DraftFormat, "surprise": 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDraft(bad); err == nil {
		t.Fatal("unknown fields must refuse")
	}

	// A wrong schema tag refuses by name.
	wrong := filepath.Join(dir, "wrong.json")
	if err := Save(wrong, map[string]any{"schema_version": "x/v9"}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDraft(wrong); err == nil || !strings.Contains(err.Error(), DraftFormat) {
		t.Fatalf("wrong schema must refuse by name: %v", err)
	}
}
