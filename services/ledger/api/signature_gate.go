package api

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// verifyEntrySignaturesGated is the SINGLE definition of "is this entry's
// signature bundle admissible?", shared by BOTH submission paths — the
// single-entry POST /v1/entries (prepareSubmission step 4) and the batch
// POST /v1/entries/batch (preflightEntry) — so the two cannot diverge.
//
// Behaviour:
//
//   - Gates.MultiSig ON: verify EVERY signature polymorphically via the SDK —
//     VerifyEntryAllSignaturesWithVerifier when a *did.VerifierRegistry is wired
//     (production: did:key / did:web / did:pkh × ECDSA / Ed25519 / EIP-191 /
//     EIP-712 / EIP-1271 / ML-DSA-65 / ML-DSA-87 / SLH-DSA-128s), or the
//     ECDSA-only DIDResolver adapter otherwise (tests / pre-registry deploys).
//     Then, when Gates.SignaturePolicy is on AND a resolver is wired, enforce the
//     network signature policy (algorithm allow-list + signature-count thresholds).
//   - Gates.MultiSig OFF: the legacy single-signature path (Signatures[0] only).
//
// Returns the per-signature Web3 verification receipts (nil on the legacy path),
// which the caller threads into WAL.Submit, and the first verification error —
// already SDK-sentinel-wrapped so every caller maps it uniformly via
// admission.MapSDKError.
//
// WHY THIS EXISTS: the batch path (api/batch.go) previously inlined ONLY the
// legacy single-sig call (admission.VerifyEntrySignature), so a batch-submitted
// entry had Signatures[1..N] cryptographically UNCHECKED, never ran the
// polymorphic (non-ECDSA / PQ / EIP-1271) verifier, and skipped the network
// signature-policy gate — a correctness gap relative to the single-entry path.
// Routing both callers through this one function closes that divergence
// structurally: the batch path can no longer fall behind the single path.
func verifyEntrySignaturesGated(
	ctx context.Context,
	entry *envelope.Entry,
	sigBytes []byte,
	deps *SubmissionDeps,
) ([]types.Web3VerificationReceipt, error) {
	var receipts []types.Web3VerificationReceipt
	if !deps.Gates.MultiSig {
		// Legacy single-signature path (Signatures[0] only). Preserved for
		// tests and pre-multi-sig deployments; flipped on via
		// LEDGER_ADMISSION_MULTISIG_ENABLE (default ON).
		if err := admission.VerifyEntrySignature(ctx, entry, sigBytes, deps.Identity.DIDResolver); err != nil {
			return nil, err
		}
	} else {
		var (
			report *attestation.SignatureReport
			err    error
		)
		if deps.Identity.Verifier != nil {
			report, err = admission.VerifyEntryAllSignaturesWithVerifier(ctx, entry, deps.Identity.Verifier)
		} else {
			report, err = admission.VerifyEntryAllSignatures(ctx, entry, deps.Identity.DIDResolver)
		}
		if report != nil {
			receipts = report.Web3Receipts
		}
		if err != nil {
			return receipts, err
		}
		// Network signature policy (gate 2): allow-list + count thresholds, on
		// the already-verified report. Off unless explicitly enabled with a
		// wired resolver.
		if report != nil && deps.Gates.SignaturePolicy && deps.SignaturePolicyResolver != nil {
			if policyErr := admission.VerifyEntrySignaturePolicy(
				ctx, deps.SignaturePolicyResolver, entry, report,
			); policyErr != nil {
				return receipts, policyErr
			}
		}
	}

	// Algorithm-policy gate (issue #201 — crypto-agility): independent of the
	// single/multi-sig mode, it checks every declared signature algoID against
	// the network's on-log lifecycle policy (forbidden/absent → reject). Off
	// unless Gates.AlgorithmPolicy is set with a wired resolver.
	if deps.Gates.AlgorithmPolicy && deps.AlgorithmPolicyResolver != nil {
		if err := admission.VerifyEntryAlgorithmPolicy(ctx, deps.AlgorithmPolicyResolver, entry); err != nil {
			return receipts, err
		}
	}
	return receipts, nil
}

// admitProtocolVersion enforces the network protocol-version admission policy on
// a submission's wire-format version — shared by BOTH submission paths so they
// stay consistent. When the gate is wired (Gates.ProtocolVersion + a resolver)
// it delegates to admission.VerifyEntryProtocolVersion (only write-admitted
// versions pass). Otherwise the legacy rule stands: only the binary's current
// wire version is admitted. Both branches return admission.ErrProtocolVersionNotAdmitted
// (mapped to 422), so callers map uniformly via admission.MapSDKError.
func admitProtocolVersion(ctx context.Context, wireVersion uint16, deps *SubmissionDeps) error {
	if deps.Gates.ProtocolVersion && deps.ProtocolVersionResolver != nil {
		return admission.VerifyEntryProtocolVersion(ctx, deps.ProtocolVersionResolver, wireVersion)
	}
	if wireVersion != envelope.CurrentProtocolVersion() {
		return fmt.Errorf("%w: unsupported protocol version %d (expected %d)",
			admission.ErrProtocolVersionNotAdmitted, wireVersion, envelope.CurrentProtocolVersion())
	}
	return nil
}
