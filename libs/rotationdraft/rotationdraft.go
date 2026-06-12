/*
FILE PATH: libs/rotationdraft/rotationdraft.go

DESCRIPTION:

	The witness-rotation ceremony's file-relay artifacts (PRE-6b/6c) — the
	SEAM both consumers import (the witness host's one-shot consent signer
	and the operator's rotation driver), so the ceremony has exactly one
	wire shape and one digest recipe.

	  Draft   — the proposed rotation: network binding, the CURRENT set
	            hash (fetched from the live witness history, never
	            asserted), and the NEW set's keys. Carried host to host.
	  Consent — ONE witness's cosignature over the SDK's canonical
	            rotation message: cosign.SignECDSA(
	              NewRotationPayloadSHA256(ComputeSetHash(newSet)),
	              networkID, …) — the IDENTICAL bytes the online
	            /v1/cosign purpose=rotation flow signs, so offline and
	            online consents are interchangeable under
	            witness.VerifyRotation.

	The artifacts are convenience, never authority: the finalized
	types.WitnessRotation is verified by the SDK's full recipe (set-hash
	rebind, scheme enforcement, OLD K-of-N quorum) at ProcessRotation —
	and nowhere else mints trust.
*/
package rotationdraft

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

// Draft is the proposed rotation, relayed for consent collection.
type Draft struct {
	SchemaVersion  string `json:"schema_version"`
	NetworkIDHex   string `json:"network_id"`       // 64-hex; consents bind to it
	CurrentSetHash string `json:"current_set_hash"` // 64-hex; from the LIVE history
	NewSet         []Key  `json:"new_set"`
}

// Consent is one witness's signature over the canonical rotation message.
type Consent struct {
	SchemaVersion string `json:"schema_version"`
	NetworkIDHex  string `json:"network_id"`
	NewSetHashHex string `json:"new_set_hash"` // binds the consent to ONE proposal
	PubKeyIDHex   string `json:"pub_key_id"`
	SchemeTag     uint8  `json:"scheme_tag"`
	SignatureB64  string `json:"signature"`
}

// ─── draft mechanics ─────────────────────────────────────────────────

// NewSetKeys decodes the draft's new set into SDK keys.
func (d *Draft) NewSetKeys() ([]types.WitnessPublicKey, error) {
	out := make([]types.WitnessPublicKey, 0, len(d.NewSet))
	for i, k := range d.NewSet {
		id, err := hex32(k.IDHex)
		if err != nil {
			return nil, fmt.Errorf("rotationdraft: new_set[%d].id: %w", i, err)
		}
		pub, err := hex.DecodeString(strings.TrimSpace(k.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("rotationdraft: new_set[%d].public_key: %w", i, err)
		}
		out = append(out, types.WitnessPublicKey{ID: id, PublicKey: pub, SchemeTag: k.SchemeTag})
	}
	return out, nil
}

// NewSetHash computes the canonical new-set hash via the SDK's ONE recipe.
func (d *Draft) NewSetHash() ([32]byte, error) {
	keys, err := d.NewSetKeys()
	if err != nil {
		return [32]byte{}, err
	}
	return witness.ComputeSetHash(keys), nil
}

// SignConsent produces this witness's consent: the SDK cosign signature over
// the canonical rotation message — byte-identical to the online
// purpose=rotation flow.
func (d *Draft) SignConsent(pubKeyID [32]byte, schemeTag uint8, key *ecdsa.PrivateKey) (*Consent, error) {
	nid, err := hex32(d.NetworkIDHex)
	if err != nil {
		return nil, fmt.Errorf("rotationdraft: network_id: %w", err)
	}
	nsh, err := d.NewSetHash()
	if err != nil {
		return nil, err
	}
	payload := cosign.NewRotationPayloadSHA256(nsh)
	sig, err := cosign.SignECDSA(payload, cosign.NetworkID(nid), cosign.HashAlgoSHA256, key)
	if err != nil {
		return nil, fmt.Errorf("rotationdraft: sign consent: %w", err)
	}
	return &Consent{
		SchemaVersion: ConsentFormat,
		NetworkIDHex:  d.NetworkIDHex,
		NewSetHashHex: hex.EncodeToString(nsh[:]),
		PubKeyIDHex:   hex.EncodeToString(pubKeyID[:]),
		SchemeTag:     schemeTag,
		SignatureB64:  base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Finalize assembles the on-log types.WitnessRotation from the draft + the
// collected consents: the CURRENT set's (the OLD K-of-N authority) and the
// NEW set's (the dual-sign attestation the on-log structural door requires).
// Every consent's binding (network id + new-set hash) is cross-checked
// FATALLY — a consent for a different proposal never rides. Trust stays with
// witness.VerifyRotation; this is assembly, not authority.
func (d *Draft) Finalize(currentConsents, newConsents []*Consent) (types.WitnessRotation, error) {
	cur, err := hex32(d.CurrentSetHash)
	if err != nil {
		return types.WitnessRotation{}, fmt.Errorf("rotationdraft: current_set_hash: %w", err)
	}
	newSet, err := d.NewSetKeys()
	if err != nil {
		return types.WitnessRotation{}, err
	}
	nsh, err := d.NewSetHash()
	if err != nil {
		return types.WitnessRotation{}, err
	}
	wantNSH := hex.EncodeToString(nsh[:])

	r := types.WitnessRotation{
		CurrentSetHash: cur,
		NewSet:         newSet,
		SchemeTagOld:   1, // ECDSA consents (v1 ceremony scheme)
		SchemeTagNew:   1,
	}
	appendSide := func(consents []*Consent, side string, dst *[]types.WitnessSignature) error {
		for i, c := range consents {
			if c.SchemaVersion != ConsentFormat {
				return fmt.Errorf("rotationdraft: %s consents[%d]: schema %q, want %q", side, i, c.SchemaVersion, ConsentFormat)
			}
			if !strings.EqualFold(c.NetworkIDHex, d.NetworkIDHex) {
				return fmt.Errorf("rotationdraft: %s consents[%d] binds network %s, draft is %s", side, i, short(c.NetworkIDHex), short(d.NetworkIDHex))
			}
			if !strings.EqualFold(c.NewSetHashHex, wantNSH) {
				return fmt.Errorf("rotationdraft: %s consents[%d] binds new_set_hash %s, draft computes %s — a consent for a DIFFERENT proposal", side, i, short(c.NewSetHashHex), short(wantNSH))
			}
			kid, err := hex32(c.PubKeyIDHex)
			if err != nil {
				return fmt.Errorf("rotationdraft: %s consents[%d].pub_key_id: %w", side, i, err)
			}
			sig, err := base64.StdEncoding.DecodeString(c.SignatureB64)
			if err != nil {
				return fmt.Errorf("rotationdraft: %s consents[%d].signature: %w", side, i, err)
			}
			*dst = append(*dst, types.WitnessSignature{
				PubKeyID: kid, SchemeTag: c.SchemeTag, SigBytes: sig,
			})
		}
		return nil
	}
	if err := appendSide(currentConsents, "current", &r.CurrentSignatures); err != nil {
		return types.WitnessRotation{}, err
	}
	if err := appendSide(newConsents, "new", &r.NewSignatures); err != nil {
		return types.WitnessRotation{}, err
	}
	if err := witness.ValidateWitnessRotation(r); err != nil {
		return types.WitnessRotation{}, fmt.Errorf("rotationdraft: finalized rotation: %w", err)
	}
	return r, nil
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
