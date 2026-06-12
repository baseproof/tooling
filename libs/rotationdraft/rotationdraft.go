/*
FILE PATH: libs/rotationdraft/rotationdraft.go

DESCRIPTION:

	The witness-rotation ceremony's FILE-RELAY layer (PRE-6b/6c) — and ONLY
	that. Assembly belongs to the SDK: witness.NewRotationDraft routes,
	deduplicates, conflict-rejects, and Finalize() SELF-VERIFIES the
	assembled rotation through the full VerifyRotation recipe before it can
	be minted ("assembly shares the verifier"). This package carries the
	ceremony across air gaps:

	  Draft   — the NewRotationDraft constructor inputs as a relayable file:
	            network binding, the constitutional quorum K, the CURRENT
	            set's keys (fetched from the live witness history, never
	            asserted), and the proposed NEW set's keys. Scheme tags are
	            NOT stored — they are DERIVED from the key material per side
	            (uniform-or-refuse), so a wrong tag is unconstructible.
	  Consent — ONE witness's ceremony.Endorsement over the draft's rotation
	            payload (ceremony.Endorse — the SAME primitive that signs a
	            genesis endorsement, producing the IDENTICAL bytes the online
	            purpose=rotation flow signs), wrapped in the relay bindings
	            the air gap needs: network id + new-set hash, so a consent
	            for a DIFFERENT proposal is a named refusal, never a generic
	            crypto failure. The signing host REFUSES to consent with a
	            key outside the current∪next sets — the same membership
	            discipline the SDK's Attach enforces, applied where the
	            mistake would enter (the guard genesis-endorse models for
	            constitutions).

	Finalize takes ONE consent list: each endorsement enters the SDK through
	AttachEndorsement, whose membership routing buckets it to its side(s) —
	the operator never sorts consents — and the SDK's Finalize is the only
	minter. Binding cross-checks here are relay integrity (a consent for a
	different proposal never even reaches the SDK); trust is the SDK's, end
	to end.
*/
package rotationdraft

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/baseproof/baseproof/ceremony"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// Format tags for the two relay artifacts.
const (
	DraftFormat   = "baseproof.rotation-draft/v1"
	ConsentFormat = "baseproof.rotation-consent/v1"
)

// Key is one witness public key on the wire (hex forms).
type Key struct {
	IDHex     string `json:"id"`         // 32-byte key id, 64-hex
	PublicKey string `json:"public_key"` // hex
	SchemeTag uint8  `json:"scheme_tag"`
}

// Draft is the proposed rotation, relayed for consent collection — the SDK
// RotationDraft's constructor inputs, as a file.
type Draft struct {
	SchemaVersion string `json:"schema_version"`
	NetworkIDHex  string `json:"network_id"` // 64-hex; consents bind to it
	QuorumK       int    `json:"quorum_k"`   // the constitutional K (predecessor threshold)
	CurrentSet    []Key  `json:"current_set"`
	NewSet        []Key  `json:"new_set"`
}

// Consent is one witness's ceremony.Endorsement over the draft's rotation
// payload — the SAME artifact shape a genesis endorsement is (the SDK's one
// signature-relay shape) — wrapped in the bindings the air-gapped relay
// needs to refuse by NAME instead of by crypto failure.
type Consent struct {
	SchemaVersion string               `json:"schema_version"`
	NetworkIDHex  string               `json:"network_id"`
	NewSetHashHex string               `json:"new_set_hash"` // binds the consent to ONE proposal
	Endorsement   ceremony.Endorsement `json:"endorsement"`
}

// ─── key decoding + scheme derivation ───────────────────────────────

func decodeKeys(side string, in []Key) ([]types.WitnessPublicKey, error) {
	out := make([]types.WitnessPublicKey, 0, len(in))
	for i, k := range in {
		id, err := hex32(k.IDHex)
		if err != nil {
			return nil, fmt.Errorf("rotationdraft: %s[%d].id: %w", side, i, err)
		}
		pub, err := hex.DecodeString(strings.TrimSpace(k.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("rotationdraft: %s[%d].public_key: %w", side, i, err)
		}
		out = append(out, types.WitnessPublicKey{ID: id, PublicKey: pub, SchemeTag: k.SchemeTag})
	}
	return out, nil
}

// deriveScheme returns the side's ONE scheme tag, derived from the key
// material — a mixed or zero tag is a NAMED refusal, never a guess. The
// on-log rotation carries one tag per side; a wrong tag must be
// unconstructible from this path.
func deriveScheme(side string, keys []types.WitnessPublicKey) (byte, error) {
	if len(keys) == 0 {
		return 0, fmt.Errorf("rotationdraft: empty %s set", side)
	}
	tag := keys[0].SchemeTag
	if tag == 0 {
		return 0, fmt.Errorf("rotationdraft: %s set carries an unknown (zero) scheme tag — refusing to derive", side)
	}
	for i, k := range keys {
		if k.SchemeTag != tag {
			return 0, fmt.Errorf("rotationdraft: mixed signature schemes in the %s set (0x%02x at [0], 0x%02x at [%d]) — the on-log rotation carries ONE tag per side; refusing to derive",
				side, tag, k.SchemeTag, i)
		}
	}
	return tag, nil
}

// CurrentKeys / NewKeys decode the draft's sets into SDK keys.
func (d *Draft) CurrentKeys() ([]types.WitnessPublicKey, error) {
	return decodeKeys("current_set", d.CurrentSet)
}
func (d *Draft) NewKeys() ([]types.WitnessPublicKey, error) {
	return decodeKeys("new_set", d.NewSet)
}

// NewSetHash computes the canonical new-set hash via the SDK's ONE recipe.
func (d *Draft) NewSetHash() ([32]byte, error) {
	keys, err := d.NewKeys()
	if err != nil {
		return [32]byte{}, err
	}
	return witness.ComputeSetHash(keys), nil
}

// SDKDraft constructs the SDK coordinator from the file — the ONE path to
// assembly. Schemes are derived per side; the SDK constructor re-validates
// everything (quorum range, 2K>N, duplicates). blsVerifier is nil: the
// offline ceremony's v1 transport signs ECDSA consents; a BLS-schemed set
// derives its CORRECT tag here and the SDK's self-verify then refuses
// loudly without a verifier — correct tags or a named refusal, never
// silently-wrong tags.
func (d *Draft) SDKDraft() (*witness.RotationDraft, error) {
	nid, err := hex32(d.NetworkIDHex)
	if err != nil {
		return nil, fmt.Errorf("rotationdraft: network_id: %w", err)
	}
	current, err := d.CurrentKeys()
	if err != nil {
		return nil, err
	}
	next, err := d.NewKeys()
	if err != nil {
		return nil, err
	}
	schemeOld, err := deriveScheme("current_set", current)
	if err != nil {
		return nil, err
	}
	schemeNew, err := deriveScheme("new_set", next)
	if err != nil {
		return nil, err
	}
	sdk, err := witness.NewRotationDraft(cosign.NetworkID(nid), current, next, schemeOld, schemeNew, d.QuorumK, nil)
	if err != nil {
		return nil, fmt.Errorf("rotationdraft: %w", err)
	}
	return sdk, nil
}

// ─── consent signing (the witness host's leg) ────────────────────────

// SignConsent produces this witness's consent: ceremony.Endorse over the SDK
// draft's Payload() — the identity, the scheme tag, and the signed bytes are
// all DERIVED from the key material and the draft, never stated by the
// caller. Constructing the SDK draft first means a malformed proposal is
// refused BEFORE any signature exists (the same order genesis-endorse keeps:
// validate, then sign). A key outside the current∪next sets is REFUSED here,
// where the mistake would enter (the SDK's Attach enforces the same rule at
// assembly; this host-side door saves a wasted relay round).
func (d *Draft) SignConsent(key *ecdsa.PrivateKey) (*Consent, error) {
	nid, err := hex32(d.NetworkIDHex)
	if err != nil {
		return nil, fmt.Errorf("rotationdraft: network_id: %w", err)
	}
	sdk, err := d.SDKDraft()
	if err != nil {
		return nil, err
	}
	e, err := ceremony.Endorse(sdk.Payload(), cosign.NetworkID(nid), cosign.HashAlgoSHA256, key)
	if err != nil {
		return nil, fmt.Errorf("rotationdraft: sign consent: %w", err)
	}

	// Membership, derived through the SDK's ONE endorsement→signature recipe
	// (the same conversion AttachEndorsement applies at assembly).
	sig, err := witness.SignatureFromEndorsement(e)
	if err != nil {
		return nil, fmt.Errorf("rotationdraft: %w", err)
	}
	current, err := d.CurrentKeys()
	if err != nil {
		return nil, err
	}
	next, err := d.NewKeys()
	if err != nil {
		return nil, err
	}
	member := false
	for _, k := range append(current, next...) {
		if k.ID == sig.PubKeyID {
			member = true
			break
		}
	}
	if !member {
		return nil, fmt.Errorf("rotationdraft: this key (%s) is in neither the current nor the next witness set — refusing to consent to a rotation it has no part in",
			e.SignerDID)
	}

	nsh, err := d.NewSetHash()
	if err != nil {
		return nil, err
	}
	return &Consent{
		SchemaVersion: ConsentFormat,
		NetworkIDHex:  d.NetworkIDHex,
		NewSetHashHex: hex.EncodeToString(nsh[:]),
		Endorsement:   e,
	}, nil
}

// ─── finalize: SDK assembly, one consent list ────────────────────────

// Finalize cross-checks each consent's relay binding (a consent for a
// different proposal or network never reaches assembly), then delegates to
// the SDK coordinator through AttachEndorsement: membership routing buckets
// each endorsement to its side(s) (the operator never sorts), idempotent
// re-deliveries dedupe, conflicting signatures reject — and the SDK's
// Finalize MINTS only a rotation the full VerifyRotation recipe accepts.
func (d *Draft) Finalize(consents []*Consent) (types.WitnessRotation, error) {
	sdk, err := d.SDKDraft()
	if err != nil {
		return types.WitnessRotation{}, err
	}
	nsh, err := d.NewSetHash()
	if err != nil {
		return types.WitnessRotation{}, err
	}
	wantNSH := hex.EncodeToString(nsh[:])

	for i, c := range consents {
		if c.SchemaVersion != ConsentFormat {
			return types.WitnessRotation{}, fmt.Errorf("rotationdraft: consents[%d]: schema %q, want %q", i, c.SchemaVersion, ConsentFormat)
		}
		if !strings.EqualFold(c.NetworkIDHex, d.NetworkIDHex) {
			return types.WitnessRotation{}, fmt.Errorf("rotationdraft: consents[%d] binds network %s, draft is %s", i, short(c.NetworkIDHex), short(d.NetworkIDHex))
		}
		if !strings.EqualFold(c.NewSetHashHex, wantNSH) {
			return types.WitnessRotation{}, fmt.Errorf("rotationdraft: consents[%d] binds new_set_hash %s, draft computes %s — a consent for a DIFFERENT proposal", i, short(c.NewSetHashHex), short(wantNSH))
		}
		if err := sdk.AttachEndorsement(c.Endorsement); err != nil {
			return types.WitnessRotation{}, fmt.Errorf("rotationdraft: consents[%d] (%s): %w", i, c.Endorsement.SignerDID, err)
		}
	}
	rot, err := sdk.Finalize()
	if err != nil {
		return types.WitnessRotation{}, fmt.Errorf("rotationdraft: %w", err)
	}
	return rot, nil
}

// ─── file IO (atomic) ────────────────────────────────────────────────

func LoadDraft(path string) (*Draft, error) {
	var d Draft
	if err := loadStrict(path, &d); err != nil {
		return nil, err
	}
	if d.SchemaVersion != DraftFormat {
		return nil, fmt.Errorf("rotationdraft: %q schema %q, want %q", path, d.SchemaVersion, DraftFormat)
	}
	return &d, nil
}

func LoadConsent(path string) (*Consent, error) {
	var c Consent
	if err := loadStrict(path, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func Save(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadStrict(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("rotationdraft: read %q: %w", path, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("rotationdraft: decode %q: %w", path, err)
	}
	return nil
}

func hex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("got %d bytes, want 32", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
