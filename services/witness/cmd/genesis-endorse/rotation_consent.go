/*
FILE PATH: cmd/genesis-endorse/rotation_consent.go

DESCRIPTION:

	The `-kind rotation-consent` leg (PRE-6b wiring): a host holding a
	CURRENT or NEW witness key signs ONE rotation-consent over a relayed
	rotation-draft, entirely offline. This is the file-in/file-out witness
	side of the ceremony — the air-gapped flow the kind seam was built for:
	build the draft centrally, walk it to each witness host, run one verb
	there, carry the consent back, finalize.

	The signing recipe is NOT reimplemented here: rotationdraft.Draft.
	SignConsent produces cosign.SignECDSA over the canonical rotation
	message — the IDENTICAL bytes the witness daemon's online /v1/cosign
	purpose=rotation flow signs — so this offline consent is
	interchangeable with an online one under witness.VerifyRotation. The
	host's pub_key_id + scheme are derived from its OWN key (witkey.DID →
	witness.KeysFromDIDs), never asserted.
*/
package main

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/rotationdraft"
	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

// signRotationConsent loads the relayed draft, derives this host's witness
// identity from its key, and returns the signed consent.
func signRotationConsent(priv *ecdsa.PrivateKey, draftPath string) (*rotationdraft.Consent, string, error) {
	draft, err := rotationdraft.LoadDraft(draftPath)
	if err != nil {
		return nil, "", err
	}

	// This host's witness identity comes from its OWN key — the same
	// derivation the ledger uses to resolve the on-log set, so the consent's
	// pub_key_id matches a key in the current OR new set by construction.
	did, err := witkey.DID(priv)
	if err != nil {
		return nil, "", fmt.Errorf("derive did:key: %w", err)
	}
	keys, err := witness.KeysFromDIDs([]string{did})
	if err != nil {
		return nil, "", fmt.Errorf("derive witness key: %w", err)
	}
	self := keys[0]

	consent, err := draft.SignConsent(self.ID, self.SchemeTag, priv)
	if err != nil {
		return nil, "", err
	}
	return consent, did, nil
}
