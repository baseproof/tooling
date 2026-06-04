/*
FILE PATH: admission/pow_gate.go

Mode-B Proof-of-Work admission gate.

# WHAT THIS ENFORCES

For unauthenticated submissions (no Mode-A credit deduction —
caller hasn't presented a known exchange identity), the entry's
envelope.ControlHeader.AdmissionProof MUST satisfy:

  - Mode == AdmissionModeB
  - TargetLog == this ledger's LogDID
  - Difficulty ≥ ledger's current minimum (from DifficultyResolver)
  - Epoch within acceptanceWindow of CurrentEpoch
  - Hash(stamp_input + nonce) meets the leading-zero-bit target

The SDK's crypto/admission.VerifyStamp does the cryptographic
verification end-to-end; this gate is the seam between the
admission pipeline and the SDK primitive. The seam exists so:

	(1) The difficulty source is injected (DifficultyResolver
	    interface) — a future on-log difficulty walker plugs in
	    without touching submission.go / batch.go.
	(2) The gate is opt-out-able via Gates.ModeBPoW — a network
	    can disable Mode-B entirely if it wants only Mode-A
	    (Credit) admissions.
	(3) Error sentinels route through admission/error_mapping.go
	    so api/submission.go's HTTP-status switch stays
	    table-driven (matches II.6 SignaturePolicy gate pattern).

# WHY NOT EXTRACT MORE

VerifyStamp's signature is wide (8 parameters). The gate funnels
this into a narrower (ctx, resolver, entry, logDID, epoch params)
shape — same as II.6's VerifyEntrySignaturePolicy. Caller
constructs the epoch from its AdmissionConfig and supplies it;
the resolver supplies (difficulty, hashFunc).

# PRODUCT GOAL ALIGNMENT

  - #9 Mode A + Mode B admission — Mode B is shipped. The gate
    refactor here extracts inline code into a reusable function
    so the operational and testing posture matches Mode A's
    CreditDeducter (clean interface, swappable impl).
  - #10 Policy-based gating, ZT-affirmed — opt-out flag +
    typed sentinels for routing.

Issue #152 (post-II) closure for the gate-refactor scope. The
on-log difficulty walker is OUT OF SCOPE per the design review
(no concrete consumer; difficulty changes are governance-rare;
admission-only consumption — no post-admission re-verification).
*/
package admission

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/core/envelope"
	sdkadmission "github.com/baseproof/baseproof/crypto/admission"
)

// ─────────────────────────────────────────────────────────────────────
// Error sentinels — routed via admission/error_mapping.go
// ─────────────────────────────────────────────────────────────────────

// ErrModeBProofRequired is returned when an unauthenticated
// submission carries no envelope.ControlHeader.AdmissionProof
// (the caller bypassed Mode-A credit AND skipped Mode-B PoW).
// Routes to HTTP 403 — the request has no admission credential
// the ledger recognizes.
var ErrModeBProofRequired = errors.New(
	"admission: unauthenticated submission requires a Mode-B compute stamp")

// ErrModeBStampInvalid is returned when VerifyStamp rejects the
// supplied proof for any reason (mode mismatch, target log
// mismatch, difficulty below minimum, epoch out of window,
// hash below target, malformed body). The underlying SDK
// sentinel is joined via errors.Join so callers can errors.Is
// on the specific failure class.
//
// Routes to HTTP 403 — the proof exists but doesn't meet the
// network's current policy.
var ErrModeBStampInvalid = errors.New(
	"admission: Mode-B compute stamp verification failed")

// ErrModeBResolverFailed is returned when the DifficultyResolver
// fails to supply a current difficulty (e.g., I/O failure in a
// future on-log impl). Distinct from ErrModeBStampInvalid so the
// admission pipeline routes it as 500 (infrastructure) rather
// than 403 (policy reject).
var ErrModeBResolverFailed = errors.New(
	"admission: difficulty resolver failed")

// ─────────────────────────────────────────────────────────────────────
// DifficultyResolver — the injection seam
// ─────────────────────────────────────────────────────────────────────

// DifficultyResolver supplies the difficulty + hash function in
// force right now. The seam exists so the gate's only dependency
// on difficulty sourcing is this interface — production wires
// StaticDifficultyResolver (wraps middleware.DifficultyController),
// a hypothetical future deployment can wire an on-log walker.
//
// Context is propagated so on-log resolvers can honor caller
// cancellation while fetching new records. The static resolver
// ignores ctx.
//
// HashFunc is the SDK's sdkadmission.HashFunc value (not the
// string). The translation from "sha256" / "argon2id" → HashFunc
// happens once at construction; the hot path never re-does it.
type DifficultyResolver interface {
	// Current returns (difficulty, hashFunc, nil) on success.
	// Errors join ErrModeBResolverFailed at the call site for
	// proper HTTP routing.
	Current(ctx context.Context) (difficulty uint32, hashFunc sdkadmission.HashFunc, err error)
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAdmissionStamp — the gate function
// ─────────────────────────────────────────────────────────────────────

// VerifyAdmissionStamp enforces Mode-B PoW on an unauthenticated
// submission. The caller decides WHETHER to call this (the
// Gates.ModeBPoW feature flag + the unauthenticated-context probe
// live at the call site); the gate itself runs the cryptographic
// verification given a non-nil resolver + entry.
//
// CONTRACT:
//
//   - nil resolver → gate inert, returns nil. (The caller has
//     opted out, typically via Gates.ModeBPoW=false OR by
//     determining the request is authenticated and Mode-A
//     handles cost.)
//   - nil entry / nil entry.Header.AdmissionProof → returns
//     ErrModeBProofRequired (routes to 403).
//   - resolver.Current() error → ErrModeBResolverFailed wrapping
//     the underlying error (routes to 500).
//   - VerifyStamp rejection → ErrModeBStampInvalid joined with
//     the SDK sentinel (routes to 403). Callers can errors.Is
//     on the SDK sentinel (e.g., ErrStampHashBelowTarget,
//     ErrStampEpochOutOfWindow) for diagnostic dispatch.
//
// PERFORMANCE: one resolver.Current call + one VerifyStamp call.
// The resolver is expected to be sub-microsecond
// (StaticDifficultyResolver reads an atomic.Uint32). VerifyStamp's
// cost is dominated by the hash function — SHA-256 is ~1 µs;
// Argon2id with default params is ~50 ms (intentional — that's
// the work the PoW is asking for).
//
// The acceptanceWindow + currentEpoch parameters are passed
// explicitly (not pulled from a global) so the caller decides
// the freshness window per-request — admission and batch
// pipelines may differ, and tests need to inject deterministic
// epochs.
func VerifyAdmissionStamp(
	ctx context.Context,
	resolver DifficultyResolver,
	entry *envelope.Entry,
	logDID string,
	currentEpoch, acceptanceWindow uint64,
) error {
	if resolver == nil {
		return nil
	}
	if entry == nil {
		// Programmer error — admission pipeline never passes nil.
		// Fail loud rather than silently allow.
		return fmt.Errorf("admission: VerifyAdmissionStamp called with nil entry")
	}
	if entry.Header.AdmissionProof == nil {
		return ErrModeBProofRequired
	}

	difficulty, hashFunc, err := resolver.Current(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrModeBResolverFailed, err)
	}

	canonicalHash, err := envelope.EntryIdentity(entry)
	if err != nil {
		// envelope.EntryIdentity should not fail on a previously-
		// deserialized entry; treat as a programmer-error
		// upstream contract violation.
		return fmt.Errorf("admission: VerifyAdmissionStamp: EntryIdentity: %w", err)
	}

	apiProof := sdkadmission.ProofFromWire(entry.Header.AdmissionProof, logDID)
	if vErr := sdkadmission.VerifyStamp(
		apiProof,
		canonicalHash,
		logDID,
		difficulty,
		hashFunc,
		nil, // Argon2idParams nil → SDK default; HashSHA256 ignores it
		currentEpoch,
		acceptanceWindow,
	); vErr != nil {
		// Join the gate sentinel with the SDK's specific sentinel
		// so callers can errors.Is on EITHER the gate marker (for
		// 403 routing in error_mapping.go) OR the SDK sentinel
		// (for diagnostic dispatch).
		return errors.Join(ErrModeBStampInvalid, vErr)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// StaticDifficultyResolver — wraps middleware.DifficultyController
// ─────────────────────────────────────────────────────────────────────

// difficultySource is the slice of middleware.DifficultyController
// the resolver consumes. Declared as an interface so the admission
// package does not import api/middleware (avoids an api → admission
// → middleware import cycle and keeps admission's dependency
// surface narrow).
//
// *middleware.DifficultyController satisfies this in production;
// tests can supply any value with the same shape.
type difficultySource interface {
	// CurrentDifficulty returns the in-force difficulty as the
	// uint32 the SDK's VerifyStamp consumes.
	CurrentDifficulty() uint32

	// HashFunction returns the hash function NAME — "sha256" or
	// "argon2id" — matching the middleware controller's existing
	// API surface. The resolver translates this once at
	// construction.
	HashFunction() string
}

// StaticDifficultyResolver wraps a difficultySource (today:
// *middleware.DifficultyController) into the DifficultyResolver
// interface. "Static" refers to the SOURCE, not the value —
// the underlying controller's difficulty is atomically mutable
// at runtime via the auto-adjust loop in
// middleware/rate_limit.go:Run. The wrapper is stateless;
// every Current call reads the controller's current value.
type StaticDifficultyResolver struct {
	source difficultySource
}

// NewStaticDifficultyResolver constructs the resolver. nil
// source is rejected — a wiring bug at the composition root
// surfaces immediately rather than at the first admission
// cycle.
func NewStaticDifficultyResolver(source difficultySource) (*StaticDifficultyResolver, error) {
	if source == nil {
		return nil, fmt.Errorf("admission: NewStaticDifficultyResolver: nil source")
	}
	return &StaticDifficultyResolver{source: source}, nil
}

// Current returns the in-force difficulty + hashFunc. Translates
// the controller's string HashFunction() to the SDK's HashFunc
// type:
//
//   - "argon2id" → sdkadmission.HashArgon2id
//   - "sha256" or anything else → sdkadmission.HashSHA256
//
// The fallback to HashSHA256 mirrors the existing inline
// behaviour in api/submission.go step 7 and api/batch.go
// preflight — a misspelled HashFunction config falls back to
// SHA-256 rather than failing the gate (an operator typing
// "shap256" should not bring Mode-B admission down).
func (r *StaticDifficultyResolver) Current(_ context.Context) (uint32, sdkadmission.HashFunc, error) {
	difficulty := r.source.CurrentDifficulty()
	var hashFunc sdkadmission.HashFunc
	switch r.source.HashFunction() {
	case "argon2id":
		hashFunc = sdkadmission.HashArgon2id
	default:
		hashFunc = sdkadmission.HashSHA256
	}
	return difficulty, hashFunc, nil
}

// Compile-time guard: StaticDifficultyResolver satisfies
// DifficultyResolver. Drift surfaces at build time.
var _ DifficultyResolver = (*StaticDifficultyResolver)(nil)
