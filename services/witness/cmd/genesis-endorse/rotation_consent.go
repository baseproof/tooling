/*
FILE PATH: cmd/genesis-endorse/rotation_consent.go

DESCRIPTION:

	The `-kind rotation-consent` leg (PRE-6b wiring): a host holding a
	CURRENT or NEW witness key signs ONE rotation-consent over a relayed
	rotation-draft, entirely offline. This is the file-in/file-out witness
	side of the ceremony — the air-gapped flow the kind seam was built for:
	build the draft centrally, walk it to each witness host, run one verb
	there, carry the consent back, finalize.

	The signing recipe is NOT reimplemented here — or in rotationdraft:
	SignConsent runs ceremony.Endorse over the SDK draft's rotation payload,
	the SAME primitive that signs a genesis endorsement and the IDENTICAL
	bytes the witness daemon's online /v1/cosign purpose=rotation flow
	signs, so this offline consent is interchangeable with an online one
	under witness.VerifyRotation. The host's identity and scheme are derived
	from its OWN key by the endorsement itself, never asserted — and a key
	in neither the current nor the new set is REFUSED before any signature
	exists (the same guard this tool applies to genesis constitutions).
*/
package main

import (
	"crypto/ecdsa"

	"github.com/baseproof/tooling/libs/rotationdraft"
)

// signRotationConsent loads the relayed draft and returns this host's signed
// consent plus the signer DID the endorsement derived from the key.
func signRotationConsent(priv *ecdsa.PrivateKey, draftPath string) (*rotationdraft.Consent, string, error) {
	draft, err := rotationdraft.LoadDraft(draftPath)
	if err != nil {
		return nil, "", err
	}
	consent, err := draft.SignConsent(priv)
	if err != nil {
		return nil, "", err
	}
	return consent, consent.Endorsement.SignerDID, nil
}
