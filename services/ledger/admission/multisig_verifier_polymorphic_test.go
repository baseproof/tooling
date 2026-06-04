/*
FILE PATH:

	admission/multisig_verifier_polymorphic_test.go

DESCRIPTION:

	v1.37.0 SDK adoption — Tier 3 end-to-end tests proving that
	the polymorphic admission path (VerifyEntryAllSignaturesWithVerifier)
	admits entries signed with EVERY signature algorithm the SDK's
	*did.VerifierRegistry can dispatch:

	  - did:key + ECDSA secp256k1 (the legacy case, retained for
	    backward-compat parity with the legacy DIDResolver path)
	  - did:key + Ed25519 (the algorithm that the old ECDSA-only
	    guard at multisig_verifier.go:118 used to reject)
	  - did:key + ML-DSA-65 (post-quantum, NIST FIPS 204 Category 3)

	If any of these tests fail, the v1.37.0 "make ledger dumb"
	migration is incomplete — either the wire-up at
	cmd/ledger/boot/wire/wire.go:buildIdentityDeps stopped registering
	a method, OR the api/submission.go call-site stopped preferring
	deps.Identity.Verifier over the legacy DIDResolver path.

	The test does NOT exercise did:web or did:pkh paths — those
	require a resolver stub (did:web) or chain RPC (did:pkh
	EIP-1271). Their dispatch correctness is exercised by the SDK's
	own pq_verifiers_test.go and pkh_verifier_test.go suites. This
	file's coverage is the integration seam between admission/
	and did/.
*/
package admission_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"

	"github.com/baseproof/tooling/services/ledger/admission"
)

var _ = ecdh.P256 // silence unused import; ecdh is reserved for future tests

const testDestination = "did:web:bench.log"

// polymorphicRegistry builds a *did.VerifierRegistry with did:key +
// did:pkh + did:web (the SDK's DefaultVerifierRegistry triplet).
// EOA-only PKHVerifierOptions (no EIP-1271 chain calls). The web
// resolver is a stub-resolver-shaped DIDResolver that satisfies the
// SDK's constructor; this test doesn't exercise did:web entries.
func polymorphicRegistry(t *testing.T) attestation.SignatureVerifier {
	t.Helper()
	// The DefaultVerifierRegistry constructor requires a non-nil
	// DIDResolver. The SDK's KeyResolver satisfies the interface
	// and resolves did:key locally with no network. This test
	// doesn't exercise did:web — it just needs a non-nil
	// resolver for the registry to construct successfully.
	registry, err := sdkdid.DefaultVerifierRegistry(
		testDestination, sdkdid.NewKeyResolver(), sdkdid.PKHVerifierOptions{})
	if err != nil {
		t.Fatalf("DefaultVerifierRegistry: %v", err)
	}
	return registry
}

// ─────────────────────────────────────────────────────────────────────
// Tier 1 / parity: did:key + ECDSA secp256k1 (the only algorithm the
// legacy adapter would have admitted). v1.37.0 must preserve this case
// at byte-identical semantics.
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntryAllSignaturesWithVerifier_DIDKey_ECDSA(t *testing.T) {
	t.Parallel()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Encode the compressed secp256k1 pubkey as did:key. The SDK's
	// CompressSecp256k1Pubkey expects the 65-byte uncompressed form
	// (0x04 || X || Y); we encode the *ecdsa.PublicKey to that form
	// directly — elliptic.Marshal is deprecated and secp256k1 has no
	// crypto/ecdh equivalent — then compress.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	priv.X.FillBytes(uncompressed[1:33])
	priv.Y.FillBytes(uncompressed[33:])
	compressed, err := signatures.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		t.Fatalf("CompressSecp256k1Pubkey: %v", err)
	}
	didStr := sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)

	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   didStr,
			Destination: testDestination,
		},
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: didStr,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}

	verifier := polymorphicRegistry(t)
	report, err := admission.VerifyEntryAllSignaturesWithVerifier(
		context.Background(), entry, verifier)
	if err != nil {
		t.Fatalf("VerifyEntryAllSignaturesWithVerifier: %v", err)
	}
	if report == nil || report.FirstError != nil {
		t.Fatalf("report: %+v", report)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tier 1 unlock: did:key + Ed25519. Pre-v1.37.0 the legacy adapter
// at multisig_verifier.go:118 rejected every algoID != SigAlgoECDSA.
// After v1.37.0 the SDK registry admits this through KeyVerifier's
// VerificationMethodEd25519 dispatch.
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntryAllSignaturesWithVerifier_DIDKey_Ed25519(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	didStr := sdkdid.EncodeDIDKey(sdkdid.MulticodecEd25519, []byte(pub))

	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   didStr,
			Destination: testDestination,
		},
	}
	// Ed25519 signs the FULL message, not a 32-byte hash. The SDK's
	// VerifyEntrySignatures passes sha256(SigningPayload) as the
	// 32-byte message and Ed25519's primitive accepts any length —
	// so we sign the same 32-byte hash the verifier will pass.
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig := ed25519.Sign(priv, hash[:])
	entry.Signatures = []envelope.Signature{{
		SignerDID: didStr,
		AlgoID:    envelope.SigAlgoEd25519,
		Bytes:     sig,
	}}

	verifier := polymorphicRegistry(t)
	report, err := admission.VerifyEntryAllSignaturesWithVerifier(
		context.Background(), entry, verifier)
	if err != nil {
		t.Fatalf("VerifyEntryAllSignaturesWithVerifier(Ed25519): %v", err)
	}
	if report == nil || report.FirstError != nil {
		t.Fatalf("report: %+v", report)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tier 3: did:key + ML-DSA-65. NIST FIPS 204 Category 3 post-quantum
// signature, wired through the SDK's KeyVerifier per baseproof v1.37.0.
// This proves the ledger gets PQ admission "for free" once the SDK
// supports it — zero ledger-side algorithm-specific code.
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntryAllSignaturesWithVerifier_DIDKey_MLDSA65(t *testing.T) {
	t.Parallel()
	pub, priv, err := signatures.GenerateMLDSA65()
	if err != nil {
		t.Fatalf("GenerateMLDSA65: %v", err)
	}
	pubBytes := signatures.MLDSA65PubKeyBytes(pub)
	didStr := sdkdid.EncodeDIDKey(sdkdid.MulticodecMLDSA65, pubBytes)

	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   didStr,
			Destination: testDestination,
		},
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignMLDSA65(priv, hash[:])
	if err != nil {
		t.Fatalf("SignMLDSA65: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: didStr,
		AlgoID:    envelope.SigAlgoMLDSA65,
		Bytes:     sig,
	}}

	verifier := polymorphicRegistry(t)
	report, err := admission.VerifyEntryAllSignaturesWithVerifier(
		context.Background(), entry, verifier)
	if err != nil {
		t.Fatalf("VerifyEntryAllSignaturesWithVerifier(ML-DSA-65): %v", err)
	}
	if report == nil || report.FirstError != nil {
		t.Fatalf("report: %+v", report)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Negative: tampered signature still rejected via the polymorphic
// path. Pins that the SDK registry doesn't silently accept; the
// rejection is wrapped by the SDK's per-method verifier into
// FirstError on the report.
// ─────────────────────────────────────────────────────────────────────

func TestVerifyEntryAllSignaturesWithVerifier_TamperedSignature_Rejected(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	didStr := sdkdid.EncodeDIDKey(sdkdid.MulticodecEd25519, []byte(pub))

	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:   didStr,
			Destination: testDestination,
		},
	}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig := ed25519.Sign(priv, hash[:])
	// Flip one byte in the signature.
	sig[0] ^= 0xff
	entry.Signatures = []envelope.Signature{{
		SignerDID: didStr,
		AlgoID:    envelope.SigAlgoEd25519,
		Bytes:     sig,
	}}

	verifier := polymorphicRegistry(t)
	_, err = admission.VerifyEntryAllSignaturesWithVerifier(
		context.Background(), entry, verifier)
	if err == nil {
		t.Fatal("expected tampered Ed25519 signature to be rejected, got nil error")
	}
}
