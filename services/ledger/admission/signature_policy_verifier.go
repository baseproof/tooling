/*
FILE PATH: admission/signature_policy_verifier.go

Part II.6 — per-network SignaturePolicy admission gate.

# WHAT THIS ENFORCES

After per-signature cryptographic verification (admission.
VerifyEntryAllSignatures, gate 1), this gate enforces the
NETWORK-LEVEL signature policy declared in
network.BootstrapDocument.GenesisSignaturePolicy (SDK plan §I.7):

  - Allow-list: every signature's AlgoID must be in
    GenesisSignaturePolicy.AllowedEntrySigSchemes. A signature
    using an algorithm the network's governance has NOT admitted
    is rejected even if it cryptographically verifies. This is
    the surface that lets a network refuse weak algorithms (e.g.,
    forbid SHA-1 EIP191 after a published collision).

  - Threshold: count of valid signatures must be ≥
    GenesisSignaturePolicy.MinSignaturesPerEntry. The SDK's
    verifier.EntrySignaturePolicy.Evaluate models this.

  - Per-group thresholds (e.g., "≥1 PQ-class signature required
    post-migration"): also via verifier.EntrySignaturePolicy.
    The genesis-only resolver does NOT yet enforce
    RequireHybridAfter (seq-aware policy) — that ships when the
    I.18 amendment walker lands. Until then, networks express
    persistent per-group thresholds via direct policy fields.

# WHY THIS IS A SEPARATE GATE

attestation.VerifyEntrySignatures verifies bytes; it does NOT
know what the network has decided about ALGORITHM admission.
Conflating the two (e.g., refusing to verify signatures of
forbidden algorithms) would tie cryptographic verification to
governance policy — a clean-architecture violation. The two
concerns split cleanly:

	Layer 1 (admission/multisig_verifier.go): "are the bytes
	              cryptographically valid under their declared key?"
	Layer 2 (this file):                       "is the bundle of
	              successfully-verified signatures admissible under
	              the network's policy?"

# POLICY RESOLVER PATTERN

SignaturePolicyResolver is the seam between the gate and the
policy source. v1.3 ships GenesisSignaturePolicyResolver — a
static wrapper around BootstrapDocument.GenesisSignaturePolicy.
A future I.18-walker-backed implementation that surfaces on-log
amendments will be a different SignaturePolicyResolver impl;
the gate code stays unchanged.

# FEATURE FLAG

Gated by Gates.SignaturePolicy (default OFF during rollout). A
new network MAY launch with the gate ON from genesis; existing
networks roll out the gate after a deployment cycle. With the
gate OFF, only the layer-1 cryptographic verify runs — pre-v1.3
admission semantics.

Plan §II.6.
*/
package admission

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/verifier"
)

// ErrSignatureAlgoNotAllowed is returned when an entry signature
// uses an algoID that is NOT in the network's
// GenesisSignaturePolicy.AllowedEntrySigSchemes. Per-signature
// detail is logged at the call site; this sentinel routes to a
// 403 via admission/error_mapping.go.
var ErrSignatureAlgoNotAllowed = errors.New(
	"admission: signature algorithm not allowed by network signature policy")

// ErrSignaturePolicyFailed is returned when the network's
// EntrySignaturePolicy.Evaluate rejects the verified-signature
// bundle. Wraps the SDK's typed sentinels
// (verifier.ErrPolicyMinValidSigs, verifier.ErrPolicyMinSigsFromGroup)
// so callers can errors.Is against them.
var ErrSignaturePolicyFailed = errors.New(
	"admission: entry signature policy failed")

// ErrSignaturePolicyResolverFailed is returned when the resolver
// cannot supply a current policy (e.g., underlying I/O failure
// in an amendment-aware implementation). Distinct from
// ErrSignaturePolicyFailed so the admission pipeline can route
// it as 500 (infrastructure) rather than 403 (policy reject).
var ErrSignaturePolicyResolverFailed = errors.New(
	"admission: signature policy resolver failed")

// SignaturePolicyResolver returns the EntrySignaturePolicy
// currently in force on this network. v1.3 ships a static
// implementation (GenesisSignaturePolicyResolver); future
// amendment-aware implementations will surface the latest
// policy from an on-log walker.
//
// Context is propagated so amendment-aware impls can honor
// caller cancellation while their underlying walker fetches
// new entries. The static resolver ignores ctx.
type SignaturePolicyResolver interface {
	// Current returns the policy in force right now. The returned
	// EntrySignaturePolicy has already passed Validate at
	// construction time (boot-time check); the hot-path Evaluate
	// trusts that invariant.
	//
	// AllowedAlgos returns the set of algoIDs the network admits.
	// The gate uses this for the allow-list reject; the
	// EntrySignaturePolicy itself does NOT model algo allow-listing
	// (it only counts).
	Current(ctx context.Context) (policy verifier.EntrySignaturePolicy, allowedAlgos map[uint16]struct{}, err error)
}

// VerifyEntrySignaturePolicy enforces the network signature policy
// on a pre-verified signature report. Returns nil iff every
// admitted signature is allow-listed and the per-group thresholds
// pass.
//
// CONTRACT:
//
//   - nil resolver → gate disabled, return nil (the caller has
//     opted out, typically via Gates.SignaturePolicy=false).
//
//   - nil entry → programmer error (caller bug); panic-equivalent
//     wrapped as an internal-server error sentinel. The admission
//     pipeline never feeds nil entries to this gate; this guard
//     defends against a future refactor.
//
//   - nil report → same — multi-sig verify must run first and
//     produce a report.
//
//   - resolver.Current() error → ErrSignaturePolicyResolverFailed
//     (routes to 500 — infrastructure failure, NOT a policy reject).
//
//   - signature with algoID ∉ AllowedEntrySigSchemes →
//     ErrSignatureAlgoNotAllowed (routes to 403). Reported on the
//     FIRST offending sig; subsequent rejections are logged in
//     batches by the admission pipeline.
//
//   - policy.Evaluate rejection → ErrSignaturePolicyFailed wrapping
//     the SDK sentinel (routes to 403).
//
// PERFORMANCE: O(N) in len(report.Results) where N ≤ 64 (envelope
// signature-count cap). Map lookups amortized O(1). On a typical
// 1-2 signature entry the gate is sub-microsecond.
func VerifyEntrySignaturePolicy(
	ctx context.Context,
	resolver SignaturePolicyResolver,
	entry *envelope.Entry,
	report *attestation.SignatureReport,
) error {
	if resolver == nil {
		return nil
	}
	if entry == nil {
		return fmt.Errorf("admission: VerifyEntrySignaturePolicy called with nil entry")
	}
	if report == nil {
		return fmt.Errorf("admission: VerifyEntrySignaturePolicy called with nil report")
	}

	policy, allowed, err := resolver.Current(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignaturePolicyResolverFailed, err)
	}

	// Step 1: allow-list reject. Iterate the report's per-signature
	// results. A signature whose AlgoID is NOT in `allowed`
	// causes immediate rejection — even if the signature
	// cryptographically verified. This is the network's "we do
	// NOT admit this algorithm" gate.
	//
	// We check ALL signatures (not just the ones that verified
	// cryptographically) because an entry that smuggles in an
	// unallowed algorithm is malformed by the network's policy
	// regardless of whether that signature's bytes happened to
	// verify under some key the resolver returned.
	for i, sig := range entry.Signatures {
		if _, ok := allowed[sig.AlgoID]; !ok {
			return fmt.Errorf("%w: signatures[%d] uses algoID 0x%04x",
				ErrSignatureAlgoNotAllowed, i, sig.AlgoID)
		}
	}

	// Step 2: build []verifier.VerifiedSig from the report's
	// per-signature outcomes — but only the ones that verified
	// cryptographically. Failed verifications do NOT count toward
	// MinValidSigs.
	verified := make([]verifier.VerifiedSig, 0, report.Total)
	for _, r := range report.Results {
		if r.Err == nil {
			verified = append(verified, verifier.VerifiedSig{
				AlgoID:    r.AlgoID,
				SignerDID: r.SignerDID,
			})
		}
	}

	// Step 3: evaluate the policy. Returns the SDK's typed sentinel
	// (verifier.ErrPolicyMinValidSigs or .ErrPolicyMinSigsFromGroup)
	// joined with ErrSignaturePolicyFailed via errors.Join so callers
	// can errors.Is against EITHER the gate sentinel (for 403 routing)
	// OR the SDK sentinel (for diagnostic dispatch).
	if err := policy.Evaluate(verified); err != nil {
		return errors.Join(ErrSignaturePolicyFailed, err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// GenesisSignaturePolicyResolver — the v1.3 static resolver
// ─────────────────────────────────────────────────────────────────────

// GenesisSignaturePolicyResolver is a SignaturePolicyResolver that
// always returns the network's genesis signature policy — the one
// hashed into NetworkID via BootstrapDocument.GenesisSignaturePolicy
// (SDK plan §I.7).
//
// This is the v1.3 implementation. When the I.18 amendment walker
// ships, networks needing post-genesis policy changes will swap in
// a new SignaturePolicyResolver that surfaces on-log amendments;
// the gate code in VerifyEntrySignaturePolicy stays unchanged.
type GenesisSignaturePolicyResolver struct {
	policy       verifier.EntrySignaturePolicy
	allowedAlgos map[uint16]struct{}
}

// NewGenesisSignaturePolicyResolver builds the static resolver from
// a network.BootstrapDocument's GenesisSignaturePolicy. The
// translation:
//
//   - AllowedEntrySigSchemes      → allow-list set
//   - MinSignaturesPerEntry       → EntrySignaturePolicy.MinValidSigs
//   - AllowedEntrySigSchemes      → EntrySignaturePolicy.SchemeGroups
//     (every allowed algo mapped to its
//     conventional group: "classical"
//     for ECDSA/Ed25519/EIP-191/EIP-712/
//     EIP-1271/JWZ, "pq" for ML-DSA-65/
//     ML-DSA-87/SLH-DSA-128s)
//   - RequireHybridAfter (seq)    → NOT enforced in v1.3 (genesis-only;
//     no seq awareness here). When the
//     amendment walker lands, the
//     amendment-aware resolver will
//     populate MinSigsFromSchemeGroup
//     ["pq"]=1 based on the current
//     tree size relative to the
//     amendment's RequireHybridAfter.
//
// Returns an error if the resulting EntrySignaturePolicy fails its
// own Validate (defense-in-depth: malformed policy from genesis must
// fail boot, not the first admission).
func NewGenesisSignaturePolicyResolver(
	doc network.BootstrapDocument,
) (*GenesisSignaturePolicyResolver, error) {
	gp := doc.GenesisSignaturePolicy

	allowed := make(map[uint16]struct{}, len(gp.AllowedEntrySigSchemes))
	for _, algo := range gp.AllowedEntrySigSchemes {
		allowed[algo] = struct{}{}
	}

	schemeGroups := make(map[uint16]string, len(gp.AllowedEntrySigSchemes))
	for _, algo := range gp.AllowedEntrySigSchemes {
		if group := conventionalGroupForAlgo(algo); group != "" {
			schemeGroups[algo] = group
		}
	}

	policy := verifier.EntrySignaturePolicy{
		MinValidSigs: gp.MinSignaturesPerEntry,
		// MinSigsFromSchemeGroup intentionally empty in v1.3.
		// RequireHybridAfter is seq-aware (amendment-walker
		// concern); the genesis-only resolver does not enforce it.
		MinSigsFromSchemeGroup: nil,
		SchemeGroups:           schemeGroups,
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("admission: GenesisSignaturePolicy invalid: %w", err)
	}

	return &GenesisSignaturePolicyResolver{
		policy:       policy,
		allowedAlgos: allowed,
	}, nil
}

// Current implements SignaturePolicyResolver. Ignores ctx — the
// static resolver does no I/O.
func (r *GenesisSignaturePolicyResolver) Current(
	_ context.Context,
) (verifier.EntrySignaturePolicy, map[uint16]struct{}, error) {
	return r.policy, r.allowedAlgos, nil
}

// conventionalGroupForAlgo returns the group name a given algoID
// belongs to under the SDK plan §I.11 convention. Unknown algoIDs
// return "" — they're still admitted (allow-list-permitting) but
// do NOT count toward any per-group threshold.
//
// Locking these by hardcoded map (rather than a registry) is
// intentional: the convention is protocol-permanent, and a
// registry would invite per-network "I want my own group naming"
// drift. New algorithm IDs that ship in future SDKs require a
// coordinated update here.
func conventionalGroupForAlgo(algo uint16) string {
	switch algo {
	case envelope.SigAlgoECDSA,
		envelope.SigAlgoEd25519,
		envelope.SigAlgoEIP191,
		envelope.SigAlgoEIP712,
		envelope.SigAlgoEIP1271,
		envelope.SigAlgoJWZ:
		return "classical"
	case envelope.SigAlgoMLDSA65,
		envelope.SigAlgoMLDSA87,
		envelope.SigAlgoSLHDSA128s:
		return "pq"
	default:
		return ""
	}
}

// Compile-time guard: GenesisSignaturePolicyResolver satisfies
// SignaturePolicyResolver. Drift surfaces at build time.
var _ SignaturePolicyResolver = (*GenesisSignaturePolicyResolver)(nil)
