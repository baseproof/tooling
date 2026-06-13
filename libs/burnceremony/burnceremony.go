/*
Package burnceremony — the network-burn ceremony's FILE-RELAY layer
(tooling#110), and ONLY that: the SDK owns every trust-shaped operation
(network.BurnContentDigest, cosign.PurposeBurn signing, network.VerifyBurn).

Mirrors libs/rotationdraft: a Draft relays the proposed burn for consent
collection; a Consent is one witness's cosignature over the burn content
digest under the SDK's burn purpose (cross-proposal refusals are NAMED —
a consent for burn X refuses under burn Y by binding, not by crypto
failure); Finalize assembles, dedupes, and SELF-VERIFIES through the same
network.VerifyBurn every verifier runs before minting bytes (assembly
shares the verifier — an under-quorum or tampered burn is unconstructible
here).

FINAL-ANCHOR CHOREOGRAPHY: seal the final cosigned head into the parent
network FIRST, then draft the burn citing that position (FinalAnchor).
The draft carries it; the SDK validates its shape; the parent verifies it
out-of-band. A root network burns without one.
*/
package burnceremony

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

const (
	DraftSchemaV1   = "baseproof.burn-draft/v1"
	ConsentSchemaV1 = "baseproof.burn-consent/v1"
)

var (
	ErrSchemaVersion    = errors.New("burnceremony: unknown schema_version")
	ErrDigestMismatch   = errors.New("burnceremony: consent binds a DIFFERENT burn (content digest mismatch) — refused by name, not by crypto failure")
	ErrNetworkMismatch  = errors.New("burnceremony: consent binds a different network")
	ErrNoConsents       = errors.New("burnceremony: no consents supplied")
	ErrConsentMalformed = errors.New("burnceremony: consent signature material malformed")
)

// FinalAnchor is the parent-log position the network sealed its final
// cosigned head into, BEFORE burning (the choreography order).
type FinalAnchor struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

// Draft is the proposed burn, relayed for consent collection.
type Draft struct {
	SchemaVersion string       `json:"schema_version"`
	NetworkIDHex  string       `json:"network_id"` // 64-hex; consents bind to it
	ReasonClass   string       `json:"reason_class"`
	EvidenceRefs  []string     `json:"evidence_refs,omitempty"`
	FinalAnchor   *FinalAnchor `json:"final_anchor,omitempty"`
}

// Consent is ONE witness's cosignature over the draft's burn content
// digest under cosign.PurposeBurn, wrapped in the relay bindings.
type Consent struct {
	SchemaVersion    string `json:"schema_version"`
	NetworkIDHex     string `json:"network_id"`
	ContentDigestHex string `json:"content_digest"` // binds the consent to ONE burn
	PubKeyIDHex      string `json:"pub_key_id"`
	SchemeTag        byte   `json:"scheme_tag"`
	SigHex           string `json:"sig"`
}

// burnFromDraft assembles the UNSIGNED SDK record (the digest input).
func burnFromDraft(d Draft) (network.NetworkBurn, error) {
	if d.SchemaVersion != DraftSchemaV1 {
		return network.NetworkBurn{}, fmt.Errorf("%w: draft %q", ErrSchemaVersion, d.SchemaVersion)
	}
	nid, err := hex.DecodeString(d.NetworkIDHex)
	if err != nil || len(nid) != 32 {
		return network.NetworkBurn{}, fmt.Errorf("burnceremony: network_id must be 64 hex chars")
	}
	b := network.NetworkBurn{ReasonClass: d.ReasonClass, EvidenceRefs: d.EvidenceRefs}
	copy(b.NetworkID[:], nid)
	if d.FinalAnchor != nil {
		b.FinalAnchorRef = &types.LogPosition{LogDID: d.FinalAnchor.LogDID, Sequence: d.FinalAnchor.Sequence}
	}
	return b, nil
}

// ContentDigest returns the draft's burn content digest — what every
// witness signs, and what every consent binds to.
func ContentDigest(d Draft) ([32]byte, error) {
	b, err := burnFromDraft(d)
	if err != nil {
		return [32]byte{}, err
	}
	return network.BurnContentDigest(b), nil
}

// Sign produces one witness's Consent over the draft — the PRODUCTION
// signing recipe (cosign.SignECDSA under PurposeBurn), so a hand-rolled
// signer cannot drift from what VerifyBurn demands.
func Sign(d Draft, priv *ecdsa.PrivateKey, pubKeyID [32]byte, schemeTag byte) (Consent, error) {
	digest, err := ContentDigest(d)
	if err != nil {
		return Consent{}, err
	}
	nid, _ := hex.DecodeString(d.NetworkIDHex)
	var netID cosign.NetworkID
	copy(netID[:], nid)
	sig, err := cosign.SignECDSA(cosign.NewBurnPayloadSHA256(digest), netID, cosign.HashAlgoSHA256, priv)
	if err != nil {
		return Consent{}, fmt.Errorf("burnceremony: sign: %w", err)
	}
	return Consent{
		SchemaVersion:    ConsentSchemaV1,
		NetworkIDHex:     d.NetworkIDHex,
		ContentDigestHex: hex.EncodeToString(digest[:]),
		PubKeyIDHex:      hex.EncodeToString(pubKeyID[:]),
		SchemeTag:        schemeTag,
		SigHex:           hex.EncodeToString(sig),
	}, nil
}

// Finalize assembles the quorum-signed burn from an UNORDERED consent
// list, refusing cross-proposal and malformed consents BY NAME, deduping
// per key, and SELF-VERIFYING through network.VerifyBurn against the
// supplied current witness set before minting canonical bytes. An
// under-quorum, rogue-signed, or tampered burn is unconstructible here.
func Finalize(d Draft, consents []Consent, set *cosign.WitnessKeySet) ([]byte, error) {
	if len(consents) == 0 {
		return nil, ErrNoConsents
	}
	b, err := burnFromDraft(d)
	if err != nil {
		return nil, err
	}
	digest := network.BurnContentDigest(b)
	digestHex := hex.EncodeToString(digest[:])

	seen := map[string]bool{}
	for i, c := range consents {
		if c.SchemaVersion != ConsentSchemaV1 {
			return nil, fmt.Errorf("%w: consents[%d] %q", ErrSchemaVersion, i, c.SchemaVersion)
		}
		if c.NetworkIDHex != d.NetworkIDHex {
			return nil, fmt.Errorf("%w: consents[%d]", ErrNetworkMismatch, i)
		}
		if c.ContentDigestHex != digestHex {
			return nil, fmt.Errorf("%w: consents[%d]", ErrDigestMismatch, i)
		}
		if seen[c.PubKeyIDHex] {
			continue // dedupe: same witness consenting twice is one consent
		}
		seen[c.PubKeyIDHex] = true
		kid, err := hex.DecodeString(c.PubKeyIDHex)
		if err != nil || len(kid) != 32 {
			return nil, fmt.Errorf("%w: consents[%d] pub_key_id", ErrConsentMalformed, i)
		}
		sig, err := hex.DecodeString(c.SigHex)
		if err != nil || len(sig) == 0 {
			return nil, fmt.Errorf("%w: consents[%d] sig", ErrConsentMalformed, i)
		}
		var ws types.WitnessSignature
		copy(ws.PubKeyID[:], kid)
		ws.SchemeTag = c.SchemeTag
		ws.SigBytes = sig
		b.Signatures = append(b.Signatures, ws)
	}

	// Assembly shares the verifier: the SAME quorum check every walker runs.
	if err := network.VerifyBurn(b, set); err != nil {
		return nil, fmt.Errorf("burnceremony: self-verify refused the assembled burn: %w", err)
	}
	return network.EncodeNetworkBurnPayload(b)
}
