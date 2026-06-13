/*
FILE PATH: admission/witness_endpoint_authorizer_test.go

Prove-Boundaries lock test for AuthorizeWitnessEndpointDeclaration: a real
did:key witness signs an attestation over SigningPayload and is admitted;
every hijack shape — unattested, unauthorized PubKeyID, tampered signature,
impostor (claims the witness DID but signed by another key) — is REFUSED at
the chokepoint. The positive case is minted through the real signing path
(signatures.SignEntry over envelope.SigningPayload); hand-assembly appears
only in the rejection cases, which is where the doctrine licenses it.
*/
package admission_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/admission"
)

const witnessTestDestination = "did:web:bench.log"

// genWitness mints a secp256k1 keypair and returns its did:key, its canonical
// witness PubKeyID (witness.KeysFromDIDs), and the private key for signing.
func genWitness(t *testing.T) (didStr string, id [32]byte, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	priv.X.FillBytes(uncompressed[1:33])
	priv.Y.FillBytes(uncompressed[33:])
	compressed, err := signatures.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		t.Fatalf("CompressSecp256k1Pubkey: %v", err)
	}
	didStr = sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)
	keys, err := witness.KeysFromDIDs([]string{didStr})
	if err != nil || len(keys) != 1 {
		t.Fatalf("KeysFromDIDs(%s): keys=%d err=%v", didStr, len(keys), err)
	}
	return didStr, keys[0].ID, priv
}

func declPayload(t *testing.T, pubKeyID [32]byte, url string) []byte {
	t.Helper()
	raw, err := network.EncodeWitnessEndpointDeclarationPayload(network.WitnessEndpointDeclaration{
		PubKeyID:  pubKeyID,
		Endpoints: map[string]string{"BaseproofWitness": url},
	})
	if err != nil {
		t.Fatalf("EncodeWitnessEndpointDeclarationPayload: %v", err)
	}
	return raw
}

type signer struct {
	did  string
	priv *ecdsa.PrivateKey
}

// declEntrySignedBy assembles an entry carrying payload and signs its
// SigningPayload with each signer (Signatures[0] == Header.SignerDID by the
// envelope invariant). The sigs commit to SigningPayload (which covers the
// DomainPayload), so they are REAL attestations over this exact declaration.
func declEntrySignedBy(t *testing.T, payload []byte, signers ...signer) *envelope.Entry {
	t.Helper()
	if len(signers) == 0 {
		t.Fatal("declEntrySignedBy: need at least one signer")
	}
	entry := &envelope.Entry{
		Header:        envelope.ControlHeader{SignerDID: signers[0].did, Destination: witnessTestDestination},
		DomainPayload: payload,
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	for _, s := range signers {
		sig, err := signatures.SignEntry(hash, s.priv)
		if err != nil {
			t.Fatalf("SignEntry: %v", err)
		}
		entry.Signatures = append(entry.Signatures, envelope.Signature{
			SignerDID: s.did, AlgoID: envelope.SigAlgoECDSA, Bytes: sig,
		})
	}
	return entry
}

func authorizedSet(ids ...[32]byte) map[[32]byte]struct{} {
	m := make(map[[32]byte]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

func verifierRegistry(t *testing.T) attestationVerifier {
	t.Helper()
	reg, err := sdkdid.DefaultVerifierRegistry(
		witnessTestDestination, sdkdid.NewKeyResolver(), sdkdid.PKHVerifierOptions{})
	if err != nil {
		t.Fatalf("DefaultVerifierRegistry: %v", err)
	}
	return reg
}

// attestationVerifier is the narrow shape AuthorizeWitnessEndpointDeclaration
// needs; *did.VerifierRegistry satisfies it.
type attestationVerifier = interface {
	Verify(ctx context.Context, did string, message, sig []byte, algoID uint16) error
}

// ── Positive: a witness self-declares (real signature) → admitted ──────────

func TestAuthorizeWitnessEndpointDeclaration_SelfDeclared_Admitted(t *testing.T) {
	t.Parallel()
	wDID, wID, wPriv := genWitness(t)
	entry := declEntrySignedBy(t, declPayload(t, wID, "https://w1.example.com"), signer{wDID, wPriv})

	if err := admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, verifierRegistry(t), authorizedSet(wID)); err != nil {
		t.Fatalf("self-declared, authorized witness must be admitted, got: %v", err)
	}
}

// A collector relays (Signatures[0]) and the witness's attestation is an
// additional signature — submission is orthogonal to possession.
func TestAuthorizeWitnessEndpointDeclaration_RelayedAttestation_Admitted(t *testing.T) {
	t.Parallel()
	wDID, wID, wPriv := genWitness(t)
	rDID, _, rPriv := genWitness(t) // the relayer (a different key)
	entry := declEntrySignedBy(t, declPayload(t, wID, "https://w1.example.com"),
		signer{rDID, rPriv}, signer{wDID, wPriv})

	if err := admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, verifierRegistry(t), authorizedSet(wID)); err != nil {
		t.Fatalf("relayed-but-witness-attested declaration must be admitted, got: %v", err)
	}
}

// ── Hijack shapes: every one refused at the chokepoint ─────────────────────

// No witness attestation at all (only a relayer signs) → not self-attested.
func TestAuthorizeWitnessEndpointDeclaration_Unattested_Refused(t *testing.T) {
	t.Parallel()
	_, wID, _ := genWitness(t)
	rDID, _, rPriv := genWitness(t)
	entry := declEntrySignedBy(t, declPayload(t, wID, "https://attacker.example.com"), signer{rDID, rPriv})

	err := admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, verifierRegistry(t), authorizedSet(wID))
	if !errors.Is(err, admission.ErrWitnessEnrollmentUnattested) {
		t.Fatalf("unattested declaration must be refused (unattested), got: %v", err)
	}
}

// The witness signs validly, but its PubKeyID is not in the authorized set.
func TestAuthorizeWitnessEndpointDeclaration_Unauthorized_Refused(t *testing.T) {
	t.Parallel()
	wDID, wID, wPriv := genWitness(t)
	_, otherID, _ := genWitness(t)
	entry := declEntrySignedBy(t, declPayload(t, wID, "https://w1.example.com"), signer{wDID, wPriv})

	err := admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, verifierRegistry(t), authorizedSet(otherID)) // wID absent
	if !errors.Is(err, admission.ErrWitnessEnrollmentUnauthorized) {
		t.Fatalf("non-authorized PubKeyID must be refused (unauthorized), got: %v", err)
	}
}

// The witness attestation signature is corrupted → it does not verify.
func TestAuthorizeWitnessEndpointDeclaration_TamperedSignature_Refused(t *testing.T) {
	t.Parallel()
	wDID, wID, wPriv := genWitness(t)
	entry := declEntrySignedBy(t, declPayload(t, wID, "https://w1.example.com"), signer{wDID, wPriv})
	entry.Signatures[0].Bytes[5] ^= 0xFF // flip a byte in the attestation

	err := admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, verifierRegistry(t), authorizedSet(wID))
	if !errors.Is(err, admission.ErrWitnessEnrollmentAttestationInvalid) {
		t.Fatalf("tampered attestation must be refused (invalid), got: %v", err)
	}
}

// Impostor: the entry CLAIMS the witness's DID but is signed by an attacker's
// key. The signature cannot verify under the witness's did:key — the hijack is
// unconstructible because the attacker holds no witness private key.
func TestAuthorizeWitnessEndpointDeclaration_Impostor_Refused(t *testing.T) {
	t.Parallel()
	wDID, wID, _ := genWitness(t) // the victim witness (authorized)
	_, _, aPriv := genWitness(t)  // the attacker's key
	// Hand-assemble (licensed: proving rejection): claim the witness DID,
	// sign with the attacker's key, target the victim's PubKeyID.
	entry := &envelope.Entry{
		Header:        envelope.ControlHeader{SignerDID: wDID, Destination: witnessTestDestination},
		DomainPayload: declPayload(t, wID, "https://attacker.example.com"),
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, aPriv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: wDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}

	err = admission.AuthorizeWitnessEndpointDeclaration(
		context.Background(), entry, verifierRegistry(t), authorizedSet(wID))
	if !errors.Is(err, admission.ErrWitnessEnrollmentAttestationInvalid) {
		t.Fatalf("impostor (witness DID, attacker key) must be refused (invalid), got: %v", err)
	}
}
