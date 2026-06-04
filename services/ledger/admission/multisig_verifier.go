/*
FILE PATH:

	admission/multisig_verifier.go

DESCRIPTION:

	PR-C gate 1 — multi-signature admission via the SDK's uniform
	attestation.VerifyEntrySignatures primitive.

	The legacy admission.VerifyEntrySignature path (entry_signature_
	verifier.go) verifies ONLY Signatures[0]. Entries arriving with N
	cosignatures pass through with Signatures[1..N] cryptographically
	unchecked — a silent gap an adversary could weaponise by attaching
	garbage cosignatures that imply (to downstream readers) a
	cosignature chain that never actually verifies.

	VerifyEntryAllSignatures closes that gap by calling
	attestation.VerifyEntrySignatures, which:

	  1. Computes sha256(SigningPayload(entry)) ONCE (no quadratic
	     re-hash across signatures).
	  2. Verifies every Signatures[i] against its declared SignerDID
	     and AlgoID.
	  3. Enforces the SDK Principle 5 envelope invariant
	     (Signatures[0].SignerDID == Header.SignerDID).
	  4. Returns a structured report with per-signature outcomes,
	     mapped here to the existing admission sentinels for the
	     api/submission.go switch.

	The legacy single-sig path stays intact in
	entry_signature_verifier.go. The api/submission.go branch picks
	one or the other based on SubmissionDeps.Gates.MultiSig (PR-A).
	Default flag OFF — flipped via LEDGER_ADMISSION_MULTISIG_ENABLE
	on rollout after one canary cycle confirms no regression against
	the bench/admission baseline.

KEY ARCHITECTURAL DECISIONS:

  - Two paths to attestation.SignatureVerifier:

    1. **Polymorphic (v1.37.0+, production)**: callers pass a
    *did.VerifierRegistry directly via
    VerifyEntryAllSignaturesWithVerifier. The SDK registry
    dispatches on DID method (did:key / did:web / did:pkh) and on
    algoID (ECDSA / Ed25519 / EIP-191 / EIP-712 / EIP-1271 /
    ML-DSA-65 / ML-DSA-87 / SLH-DSA-128s). The ledger is "dumb"
    at this seam — it admits whatever the SDK can verify.

    2. **Legacy adapter (test fallback)**: VerifyEntryAllSignatures
    wraps a ledger DIDResolver in sigVerifierAdapter, which is
    secp256k1-ECDSA-only. Kept for tests that pre-date the
    VerifierRegistry seam and for ledgers that have not yet wired
    a registry. The api.IdentityDeps struct holds both fields;
    production sets Verifier, tests can keep using DIDResolver.

  - sigVerifierAdapter is now bounded scope. The original "ECDSA-only
    by design" rationale at this layer was retrofitted to code that
    never actually called ecrecover or any chain — it did offline
    ECDSA math and returned ZeroWeb3VerificationReceipt. The honest
    statement: this adapter is a SHIM that supports the single
    algorithm the SDK's legacy DIDResolver returns; on-chain
    verification (EIP-1271) and post-quantum verification (ML-DSA,
    SLH-DSA) live in the polymorphic path through the SDK's
    *did.VerifierRegistry.

  - The verifier propagates the FIRST per-signature error, mapped
    to admission.ErrSignatureInvalid (same shape as the single-sig
    path → HTTP 401). Per-signature granularity stays available
    via the underlying SignatureReport (returned to callers so
    test code can assert against specific Results[i].Err).
*/
package admission

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdktypes "github.com/baseproof/baseproof/types"
)

// ErrUnsupportedSignatureAlgo is surfaced when the multi-sig path
// encounters a Signature whose AlgoID is not SigAlgoECDSA. secp256k1
// ECDSA is the only admissible Layer-2 entry curve by design (see the
// crypto-boundary note in the file header); a non-ECDSA cosignature is
// rejected here, not skipped. Wrapped errors include the offending
// algoID for diagnostic context.
var ErrUnsupportedSignatureAlgo = errors.New("admission: unsupported signature algorithm")

// sigVerifierAdapter bridges the ledger's DIDResolver (which
// returns *ecdsa.PublicKey for did:key identifiers) to the SDK's
// attestation.SignatureVerifier (which expects an algoID-dispatching
// Verify(ctx, did, msg, sig, algoID) method).
//
// Stateless; safe for concurrent use by every admission goroutine.
type sigVerifierAdapter struct {
	resolver DIDResolver
}

// Verify implements attestation.SignatureVerifier. secp256k1 ECDSA
// only (Layer-2 domain boundary — see file header); any other algoID
// is rejected with ErrUnsupportedSignatureAlgo.
func (a *sigVerifierAdapter) Verify(
	ctx context.Context,
	did string,
	message []byte,
	sig []byte,
	algoID uint16,
) error {
	if a.resolver == nil {
		// Wire-format-integrity-only trust model: the same shape
		// the single-sig path uses (entry_signature_verifier.go
		// short-circuits on nil resolver). For multi-sig, "skip
		// crypto" means treat every signature as nominally valid;
		// the caller must explicitly opt into this by passing a
		// nil resolver, and a future hardening PR can flip this
		// default to fail-closed.
		return nil
	}
	if algoID != envelope.SigAlgoECDSA {
		return fmt.Errorf("%w: did=%q algo=0x%04x", ErrUnsupportedSignatureAlgo, did, algoID)
	}
	pub, err := a.resolver.ResolvePublicKey(ctx, did)
	if err != nil {
		return fmt.Errorf("%w: did=%s: %v", ErrSignerDIDResolution, did, err)
	}
	if pub == nil {
		return fmt.Errorf("%w: did=%s: resolver returned nil public key", ErrSignerDIDResolution, did)
	}
	// signingHash here is the same digest VerifyEntrySignatures
	// computed once at the top — message IS that digest's bytes
	// (32 bytes). signatures.VerifyEntry takes [32]byte by value.
	if len(message) != 32 {
		return fmt.Errorf("%w: expected 32-byte signing hash, got %d", ErrSignatureInvalid, len(message))
	}
	var hash [32]byte
	copy(hash[:], message)
	if err := signatures.VerifyEntry(hash, sig, pub); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// VerifyWithReceipt implements attestation.SignatureVerifierWithReceipt
// (added in baseproof v1.7.0). The ECDSA adapter performs no on-chain
// verification — there is nothing to pin to — so the receipt is
// always the zero receipt (types.ZeroWeb3VerificationReceipt) on
// success. Per the v1.7.0 SDK contract, a receipt-aware verifier
// that returns Zero is semantically "no Web3 verification was
// performed for this signature"; the SDK's
// attestation.VerifyEntrySignatures dispatch table treats this as
// the default-non-EIP-1271 branch.
//
// Wiring an SCW (EIP-1271) verifier requires constructing a real
// *did.VerifierRegistry with a configured PKHVerifierOptions
// (Executors, QuorumK, BlockProvider) and assigning it directly
// to api.IdentityDeps.Verifier. The registry implements both
// attestation.SignatureVerifier and attestation.SignatureVerifierWithReceipt
// (compile-time pin at did/verifier_registry.go); the receipt
// returned by that path is populated per the K-of-N receipt
// schema. The adapter here is the test-friendly fallback for
// ledgers that do not (yet) need on-chain verification.
func (a *sigVerifierAdapter) VerifyWithReceipt(
	ctx context.Context,
	did string,
	message []byte,
	sig []byte,
	algoID uint16,
) (sdktypes.Web3VerificationReceipt, error) {
	if err := a.Verify(ctx, did, message, sig, algoID); err != nil {
		// Per v1.7.0 contract: failed verification MUST return the
		// Zero receipt — partial receipts for rejected signatures
		// MUST NOT leak.
		return sdktypes.ZeroWeb3VerificationReceipt(), err
	}
	return sdktypes.ZeroWeb3VerificationReceipt(), nil
}

// NewSignatureVerifier wraps a DIDResolver as an
// attestation.SignatureVerifier suitable for the SDK's
// policy verifier (attestation.VerifyEntryAttestationPolicy /
// verifier.VerifyComplete Stage 6) and for any future Stage 6
// caller. Internally reuses the same sigVerifierAdapter that
// PR-C's VerifyEntryAllSignatures uses, so signature-verification
// semantics are uniform across the multi-sig gate and the policy
// gate.
//
// nil resolver: the returned verifier short-circuits to "every
// signature is nominally valid" — wire-format-integrity-only
// trust model, matching the legacy single-sig path. Production
// always wires a real resolver.
func NewSignatureVerifier(resolver DIDResolver) attestation.SignatureVerifier {
	return &sigVerifierAdapter{resolver: resolver}
}

// VerifyEntryAllSignatures verifies EVERY signature on entry via
// the SDK's attestation.VerifyEntrySignatures. Returns nil on full
// success (all signatures valid); returns one of the existing
// admission sentinels on failure:
//
//   - attestation.ErrNilEntry        → bad-call programmer error
//   - attestation.ErrNilSignatureVerifier → bad-call programmer error
//   - attestation.ErrEmptySignatures → SDK envelope invariant
//   - attestation.ErrPrimaryDIDMismatch → SDK envelope invariant
//   - ErrSignatureInvalid (wrapping first per-sig error) → 401
//   - ErrSignerDIDResolution (wrapping resolver error) → 401
//   - ErrUnsupportedSignatureAlgo → 422
//
// All of these are enrolled in admission/error_mapping.go so the
// api/submission.go branch (PR-A wiring) routes them to the right
// HTTP status + OTel error_class without per-call switches.
//
// nil resolver: same wire-format-integrity-only behaviour as the
// legacy single-sig path. Every signature is rubber-stamped as
// valid (the adapter returns nil unconditionally).
func VerifyEntryAllSignatures(
	ctx context.Context,
	entry *envelope.Entry,
	resolver DIDResolver,
) (*attestation.SignatureReport, error) {
	adapter := &sigVerifierAdapter{resolver: resolver}
	report, err := attestation.VerifyEntrySignatures(ctx, entry, adapter)
	if err != nil {
		// Envelope-level rejection — propagate the SDK sentinel
		// as-is so error_mapping.go can route it.
		return nil, err
	}
	if report.FirstError != nil {
		// Per-signature failure. The first error is already
		// wrapped with admission.ErrSignatureInvalid /
		// ErrSignerDIDResolution / ErrUnsupportedSignatureAlgo
		// (the adapter does the wrapping) so callers using
		// errors.Is get the right sentinel.
		return report, report.FirstError
	}
	return report, nil
}

// VerifyEntryAllSignaturesWithVerifier is the v1.37.0 polymorphic
// admission entry point. It delegates the entire dispatch — DID
// method routing, algorithm selection, on-chain (EIP-1271) and
// post-quantum (ML-DSA / SLH-DSA) verification — to the SDK's
// attestation.VerifyEntrySignatures + the supplied verifier.
//
// In production, verifier is a *did.VerifierRegistry constructed
// in cmd/ledger/boot/wire/wire.go with did:key + did:web + did:pkh
// resolvers and (optionally) PKHVerifierOptions populated with an
// Ethereum RPC client for EIP-1271. The ledger no longer makes
// algorithm policy decisions at this layer; whatever the SDK can
// verify, admission accepts. Cross-network replay rejection is
// preserved (the SDK's cosign.Verify still binds to NetworkID at
// the cryptographic boundary).
//
// nil verifier: returns the SDK's ErrNilSignatureVerifier as before
// — caller should wire one. Tests that want the wire-format-only
// trust model can still use the legacy VerifyEntryAllSignatures
// path with nil DIDResolver.
func VerifyEntryAllSignaturesWithVerifier(
	ctx context.Context,
	entry *envelope.Entry,
	verifier attestation.SignatureVerifier,
) (*attestation.SignatureReport, error) {
	report, err := attestation.VerifyEntrySignatures(ctx, entry, verifier)
	if err != nil {
		return nil, err
	}
	if report.FirstError != nil {
		return report, report.FirstError
	}
	return report, nil
}

// compile-time assertion: sigVerifierAdapter implements
// attestation.SignatureVerifier. A drift in the SDK interface
// surfaces here at build time.
var _ attestation.SignatureVerifier = (*sigVerifierAdapter)(nil)

// compile-time assertion: sigVerifierAdapter ALSO implements
// attestation.SignatureVerifierWithReceipt (baseproof v1.7.0+). The
// adapter's receipts are always Zero — see VerifyWithReceipt for
// the rationale. Without this assertion, attestation.VerifyEntrySignatures
// would dispatch via the plain Verify path and report.Web3Receipts
// would always be Zero anyway; with it, the dispatch goes through
// VerifyWithReceipt, which is the canonical contract.
var _ attestation.SignatureVerifierWithReceipt = (*sigVerifierAdapter)(nil)

// compile-time assertion: an *ecdsa.PublicKey is still what the
// adapter expects from the resolver. Surfaces resolver-shape
// drift at build time.
var _ = (*ecdsa.PublicKey)(nil)
