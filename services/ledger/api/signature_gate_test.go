package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// These tests pin the SHARED signature gate (verifyEntrySignaturesGated) that
// BOTH submission paths route through. Before the fix, api/batch.go inlined only
// the legacy single-sig verifier, so batch-submitted entries skipped multi-sig,
// non-ECDSA, and signature-policy verification. The gate is the structural fix:
// testing it here proves the semantics for the single-entry AND the batch path
// at once, and TestBatchHandler_MultiSig_RoutesThroughVerifier proves the batch
// HANDLER actually invokes it.

const gateDest = "did:web:gate.test"

// gateRegistry is the SDK DefaultVerifierRegistry (did:key/pkh/web, EOA-only) —
// the production polymorphic verifier the gate uses when Identity.Verifier is set.
func gateRegistry(t *testing.T) attestation.SignatureVerifier {
	t.Helper()
	reg, err := sdkdid.DefaultVerifierRegistry(gateDest, sdkdid.NewKeyResolver(), sdkdid.PKHVerifierOptions{})
	if err != nil {
		t.Fatalf("DefaultVerifierRegistry: %v", err)
	}
	return reg
}

func didKeyECDSA(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	// secp256k1 SEC1 uncompressed encoding (0x04 || X || Y); elliptic.Marshal
	// is deprecated and crypto/ecdh has no secp256k1 curve.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	priv.X.FillBytes(uncompressed[1:33])
	priv.Y.FillBytes(uncompressed[33:])
	compressed, err := signatures.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		t.Fatalf("CompressSecp256k1Pubkey: %v", err)
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)
}

// ecdsaGateEntry builds a valid single-signature ECDSA entry whose signer DID is
// a did:key the SDK registry resolves locally.
func ecdsaGateEntry(t *testing.T) *envelope.Entry {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	did := didKeyECDSA(t, priv)
	entry := &envelope.Entry{Header: envelope.ControlHeader{SignerDID: did, Destination: gateDest}}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: did, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	return entry
}

// twoSigECDSAEntry builds a 2-signature entry: Signatures[0] is always a valid
// ECDSA signature by the primary signer (== Header.SignerDID); Signatures[1] is
// a second ECDSA cosigner that is tampered when tamperSecond is true. Returns
// the primary public key so the legacy single-sig path (which resolves only
// Header.SignerDID) can be exercised.
func twoSigECDSAEntry(t *testing.T, tamperSecond bool) (*envelope.Entry, *ecdsa.PublicKey) {
	t.Helper()
	priv0, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(0): %v", err)
	}
	priv1, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(1): %v", err)
	}
	did0 := didKeyECDSA(t, priv0)
	did1 := didKeyECDSA(t, priv1)
	entry := &envelope.Entry{Header: envelope.ControlHeader{SignerDID: did0, Destination: gateDest}}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig0, err := signatures.SignEntry(hash, priv0)
	if err != nil {
		t.Fatalf("SignEntry(0): %v", err)
	}
	sig1, err := signatures.SignEntry(hash, priv1)
	if err != nil {
		t.Fatalf("SignEntry(1): %v", err)
	}
	if tamperSecond {
		sig1[0] ^= 0xff
	}
	entry.Signatures = []envelope.Signature{
		{SignerDID: did0, AlgoID: envelope.SigAlgoECDSA, Bytes: sig0},
		{SignerDID: did1, AlgoID: envelope.SigAlgoECDSA, Bytes: sig1},
	}
	return entry, &priv0.PublicKey
}

// THE regression: with Gates.MultiSig ON, an entry whose SECOND signature is
// invalid is REJECTED. Pre-fix the batch path never reached this — it verified
// Signatures[0] only — so a forged cosignature rode along unchecked.
func TestVerifyEntrySignaturesGated_MultiSig_RejectsInvalidCosignature(t *testing.T) {
	entry, _ := twoSigECDSAEntry(t, true /* tamper Signatures[1] */)
	deps := &SubmissionDeps{
		Gates:    admission.Gates{MultiSig: true},
		Identity: IdentityDeps{Verifier: gateRegistry(t)},
	}
	_, err := verifyEntrySignaturesGated(context.Background(), entry, entry.Signatures[0].Bytes, deps)
	if err == nil {
		t.Fatal("multi-sig gate ACCEPTED an entry with an invalid Signatures[1] — the cosignature " +
			"is being ignored (the batch under-verification gap is NOT closed)")
	}
}

// Parity: a valid multi-sig entry passes.
func TestVerifyEntrySignaturesGated_MultiSig_AcceptsValidMultiSig(t *testing.T) {
	entry, _ := twoSigECDSAEntry(t, false /* both valid */)
	deps := &SubmissionDeps{
		Gates:    admission.Gates{MultiSig: true},
		Identity: IdentityDeps{Verifier: gateRegistry(t)},
	}
	if _, err := verifyEntrySignaturesGated(context.Background(), entry, entry.Signatures[0].Bytes, deps); err != nil {
		t.Fatalf("multi-sig gate rejected a fully-valid 2-signature entry: %v", err)
	}
}

// The batch path now admits the algorithms the SDK registry can verify — proven
// here with Ed25519, which the old ECDSA-only batch verifier rejected outright.
func TestVerifyEntrySignaturesGated_MultiSig_AdmitsEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	did := sdkdid.EncodeDIDKey(sdkdid.MulticodecEd25519, []byte(pub))
	entry := &envelope.Entry{Header: envelope.ControlHeader{SignerDID: did, Destination: gateDest}}
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	entry.Signatures = []envelope.Signature{{SignerDID: did, AlgoID: envelope.SigAlgoEd25519, Bytes: ed25519.Sign(priv, hash[:])}}

	deps := &SubmissionDeps{
		Gates:    admission.Gates{MultiSig: true},
		Identity: IdentityDeps{Verifier: gateRegistry(t)},
	}
	if _, err := verifyEntrySignaturesGated(context.Background(), entry, entry.Signatures[0].Bytes, deps); err != nil {
		t.Fatalf("multi-sig gate rejected a valid Ed25519 entry (non-ECDSA admission): %v", err)
	}
}

// Documents the EXACT divergence the fix removes: the legacy single-sig path
// (Gates.MultiSig OFF) ACCEPTS the same entry the multi-sig path rejects above,
// because it only ever verifies Signatures[0]. This is the behaviour the batch
// path was stuck on before the shared gate.
func TestVerifyEntrySignaturesGated_LegacyPath_IgnoresCosignature(t *testing.T) {
	entry, primaryPub := twoSigECDSAEntry(t, true /* Signatures[1] tampered, [0] valid */)
	deps := &SubmissionDeps{
		Gates:    admission.Gates{MultiSig: false},
		Identity: IdentityDeps{DIDResolver: &fakeDIDResolver{pub: primaryPub}},
	}
	if _, err := verifyEntrySignaturesGated(context.Background(), entry, entry.Signatures[0].Bytes, deps); err != nil {
		t.Fatalf("legacy single-sig path should verify only Signatures[0] (valid) and ignore the "+
			"tampered Signatures[1], got: %v", err)
	}
}

// The gate composes the network signature-policy layer: an algorithm the policy
// does not admit is rejected even though it verifies cryptographically. The
// batch path now gets this gate too.
func TestVerifyEntrySignaturesGated_EnforcesSignaturePolicy(t *testing.T) {
	doc := network.BootstrapDocument{GenesisSignaturePolicy: network.SignaturePolicy{
		AllowedEntrySigSchemes:  []uint16{envelope.SigAlgoEd25519}, // ECDSA deliberately NOT allowed
		AllowedCosignSchemeTags: []uint8{0x01},
		MinSignaturesPerEntry:   1,
	}}
	resolver, err := admission.NewGenesisSignaturePolicyResolver(doc)
	if err != nil {
		t.Fatalf("NewGenesisSignaturePolicyResolver: %v", err)
	}
	entry := ecdsaGateEntry(t) // a cryptographically VALID ECDSA entry
	deps := &SubmissionDeps{
		Gates:                   admission.Gates{MultiSig: true, SignaturePolicy: true},
		Identity:                IdentityDeps{Verifier: gateRegistry(t)},
		SignaturePolicyResolver: resolver,
	}
	_, err = verifyEntrySignaturesGated(context.Background(), entry, entry.Signatures[0].Bytes, deps)
	if !errors.Is(err, admission.ErrSignatureAlgoNotAllowed) {
		t.Fatalf("expected ErrSignatureAlgoNotAllowed (ECDSA not in policy), got: %v", err)
	}
}

// stubGateVerifier is a controllable attestation.SignatureVerifier used to prove
// the BATCH HANDLER routes signature verification through Identity.Verifier when
// Gates.MultiSig is on.
type stubGateVerifier struct{ fail bool }

func (s stubGateVerifier) Verify(_ context.Context, _ string, _ []byte, _ []byte, _ uint16) error {
	if s.fail {
		return errors.New("stub verifier: reject")
	}
	return nil
}

// Handler-level proof that the batch endpoint now honours Gates.MultiSig +
// Identity.Verifier (the fix). The SAME wire entry is accepted when the wired
// verifier passes and rejected when it fails — so the outcome depends on the
// polymorphic verifier the batch path previously ignored. Pre-fix, batch used
// the legacy DIDResolver path and the verifier had no effect.
func TestBatchHandler_MultiSig_RoutesThroughVerifier(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fail       bool
		wantAccept bool
	}{
		{"verifier_passes_accepted", false, true},
		{"verifier_fails_rejected", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opSignerPriv, _ := signatures.GenerateKey()
			signerPriv, _ := signatures.GenerateKey()
			wire, _ := signedEntryModeBWithKey(t, signerPriv, "did:test:log", []byte("ms-batch"), 1, 3600)

			walFake := &stubSubmissionWAL{}
			deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, walFake)
			// Flip the batch onto the polymorphic multi-sig path with a
			// controllable verifier (PoW stays on for the Mode-B preflight).
			deps.Gates.MultiSig = true
			deps.Identity.Verifier = stubGateVerifier{fail: tc.fail}

			body, _ := json.Marshal(BatchSubmissionRequest{
				Entries: []BatchEntry{{WireBytesHex: hex.EncodeToString(wire)}},
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/entries/batch", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			NewBatchSubmissionHandler(deps).ServeHTTP(rr, req)

			accepted := rr.Code == http.StatusAccepted
			if accepted != tc.wantAccept {
				t.Fatalf("batch accept=%v (code %d), want accept=%v\nbody: %s",
					accepted, rr.Code, tc.wantAccept, rr.Body.String())
			}
			if tc.wantAccept && len(walFake.submitted) != 1 {
				t.Errorf("WAL.Submit calls = %d, want 1 (entry should be durable)", len(walFake.submitted))
			}
			if !tc.wantAccept && len(walFake.submitted) != 0 {
				t.Errorf("WAL.Submit calls = %d, want 0 (rejected entry must not persist)", len(walFake.submitted))
			}
		})
	}
}
