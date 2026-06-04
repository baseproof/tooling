/*
FILE PATH: libs/bundle/verify.go

VerifyBundle wrapper — delegates cryptographic verification to
SDK log/bundle.VerifyBundle and surfaces an operator-friendly
classification of the outcome.

# WHY THIS WRAPS THE SDK INSTEAD OF SHIPPING NEW CRYPTO

The SDK's log/bundle.VerifyBundle is the single canonical
implementation: it runs preflight (NetworkID binding, leaf-hash
binding, witness-set resolution) then delegates per-stage crypto
verification to verifier.VerifyEntryAtPosition. The auditor and
a future `baseproof inspect` CLI MUST share this code path so a
regression in one cannot diverge from the other.

The wrapper adds:

  - A typed Outcome enum (Verified / Rejected / TransportError)
    so call sites can branch on the failure class without
    string-matching SDK error messages.
  - A Verdict struct that carries (Outcome, Bundle, Report,
    Error) — everything an operator needs for a one-shot
    decision: act, alert, or retry.
  - The required SDK opts plumbing (ExpectedNetworkID,
    WitnessSetResolver) — composed from the caller's
    HTTPWitnessSetResolver and an optional pinned NetworkID.
*/
package bundle

import (
	"context"
	"errors"
	"fmt"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
)

// Outcome classifies the result of VerifyBundleWithResolver.
// Callers branch on this to decide whether to act on the bundle,
// alert an operator, or retry the fetch.
type Outcome int

const (
	// OutcomeUnknown is the zero value. Should never appear in
	// a returned Verdict; surface as a programmer error if it
	// does (the verifier failed to set the outcome explicitly).
	OutcomeUnknown Outcome = iota

	// OutcomeVerified means SDK VerifyBundle returned a Report
	// whose AllChecksGreen() == true. The caller may act on the
	// bundle.
	OutcomeVerified

	// OutcomeRejected means the SDK returned a Report whose
	// AllChecksGreen() == false — every cryptographic check
	// ran but at least one failed (preflight error, leaf-hash
	// mismatch, inclusion-proof failure, SMT proof failure,
	// cosignature quorum failure). The bundle is structurally
	// well-formed but cryptographically invalid; the caller
	// MUST NOT act on it and SHOULD alert (this is a fork /
	// equivocation / forgery signal).
	OutcomeRejected

	// OutcomeTransportError means VerifyBundle itself returned a
	// non-nil error (nil bundle, unknown format, witness-set
	// resolver failure). This is NOT a cryptographic verdict —
	// it's an upstream wiring or availability issue. The caller
	// SHOULD retry or escalate as an availability alert, NOT a
	// fork alert.
	OutcomeTransportError
)

// String returns a stable name for the outcome (lowercase, no
// underscores — suitable for structured-log fields).
func (o Outcome) String() string {
	switch o {
	case OutcomeVerified:
		return "verified"
	case OutcomeRejected:
		return "rejected"
	case OutcomeTransportError:
		return "transport_error"
	default:
		return "unknown"
	}
}

// Verdict is the unified return shape from
// VerifyBundleWithResolver. Carries the outcome, the bundle, the
// SDK's per-stage report (nil on transport error), and the
// transport/preflight error (nil on verified or rejected).
type Verdict struct {
	Outcome Outcome
	Bundle  *sdkbundle.Bundle
	Report  *sdkbundle.Report
	Err     error
}

// VerifyBundleWithResolver runs SDK log/bundle.VerifyBundle and
// classifies the outcome.
//
//   - bundle == nil → OutcomeTransportError with sdkbundle.ErrNilBundle.
//   - resolver == nil → OutcomeTransportError; the caller MUST
//     wire a resolver because every real bundle's witness set is
//     content-addressed and unresolved without one.
//   - expectedNetworkID == zero → no NetworkID pin (SDK skips
//     the check). Production callers MUST supply the pinned
//     NetworkID; tooling that audits multiple networks may pass
//     zero and read the NetworkID from the bundle.
func VerifyBundleWithResolver(
	ctx context.Context,
	b *sdkbundle.Bundle,
	resolver sdkbundle.WitnessSetResolver,
	expectedNetworkID [32]byte,
) Verdict {
	if b == nil {
		return Verdict{Outcome: OutcomeTransportError, Err: sdkbundle.ErrNilBundle}
	}
	if resolver == nil {
		return Verdict{
			Outcome: OutcomeTransportError,
			Bundle:  b,
			Err:     errors.New("bundle/verify: WitnessSetResolver required (nil)"),
		}
	}

	report, err := sdkbundle.VerifyBundle(ctx, b, sdkbundle.VerifyBundleOptions{
		ExpectedNetworkID:  expectedNetworkID,
		WitnessSetResolver: resolver,
	})
	if err != nil {
		// SDK-level transport / preflight error — the verifier
		// didn't even produce a report.
		return Verdict{Outcome: OutcomeTransportError, Bundle: b, Err: err}
	}
	if report == nil {
		// Defensive guard — SDK contract is "non-nil report on
		// non-error". A nil report on nil err is a programmer
		// bug we want surfaced loudly.
		return Verdict{
			Outcome: OutcomeTransportError,
			Bundle:  b,
			Err:     fmt.Errorf("bundle/verify: SDK returned nil report + nil error (SDK contract violation)"),
		}
	}
	if report.AllChecksGreen() {
		return Verdict{Outcome: OutcomeVerified, Bundle: b, Report: report}
	}
	return Verdict{Outcome: OutcomeRejected, Bundle: b, Report: report}
}
