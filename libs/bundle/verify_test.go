/*
FILE PATH: libs/bundle/verify_test.go

Tests for VerifyBundleWithResolver — the outcome-classification
wrapper around SDK log/bundle.VerifyBundle.

Scope: PROGRAMMER-error guards + Outcome routing. The SDK's
crypto verification is exercised by the SDK's own tests; this
file pins the WRAPPER's contract (nil-handling, Outcome
classification, transport-vs-rejection distinction).
*/
package bundle

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
)

// stubResolver implements sdkbundle.WitnessSetResolver with a
// stored result. Used to exercise the verify wrapper without
// hitting HTTP.
type stubResolver struct {
	set *cosign.WitnessKeySet
	err error
}

func (s *stubResolver) ResolveWitnessSet(_ context.Context, _ [32]byte) (*cosign.WitnessKeySet, error) {
	return s.set, s.err
}

// ─────────────────────────────────────────────────────────────────────
// Outcome enum string-form pins
// ─────────────────────────────────────────────────────────────────────

func TestOutcome_String(t *testing.T) {
	cases := map[Outcome]string{
		OutcomeUnknown:        "unknown",
		OutcomeVerified:       "verified",
		OutcomeRejected:       "rejected",
		OutcomeTransportError: "transport_error",
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Errorf("Outcome(%d).String() = %q, want %q", o, got, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Programmer-error guards (early return paths)
// ─────────────────────────────────────────────────────────────────────

func TestVerifyBundleWithResolver_NilBundleIsTransportError(t *testing.T) {
	v := VerifyBundleWithResolver(context.Background(), nil, &stubResolver{}, [32]byte{})
	if v.Outcome != OutcomeTransportError {
		t.Errorf("Outcome = %v, want OutcomeTransportError", v.Outcome)
	}
	if !errors.Is(v.Err, sdkbundle.ErrNilBundle) {
		t.Errorf("Err = %v, want wraps ErrNilBundle", v.Err)
	}
}

func TestVerifyBundleWithResolver_NilResolverIsTransportError(t *testing.T) {
	// Bundle non-nil but resolver nil — wrapper rejects before
	// the SDK runs.
	b := &sdkbundle.Bundle{Format: sdkbundle.FormatV1}
	v := VerifyBundleWithResolver(context.Background(), b, nil, [32]byte{})
	if v.Outcome != OutcomeTransportError {
		t.Errorf("Outcome = %v, want OutcomeTransportError", v.Outcome)
	}
	if v.Err == nil {
		t.Fatal("nil resolver must surface an error")
	}
	if v.Bundle == nil {
		t.Error("Bundle should pass through even on resolver-nil error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// SDK preflight failures → Outcome routing
// ─────────────────────────────────────────────────────────────────────

func TestVerifyBundleWithResolver_UnknownFormatIsTransportError(t *testing.T) {
	// A bundle with the wrong Format field — SDK rejects at the
	// first preflight stage via ErrUnknownFormat. The wrapper
	// classifies this as transport_error (not "rejected") because
	// no cryptographic check actually ran.
	b := &sdkbundle.Bundle{Format: "baseproof-bundle/forged"}
	v := VerifyBundleWithResolver(context.Background(), b, &stubResolver{}, [32]byte{})
	if v.Outcome != OutcomeTransportError {
		t.Errorf("Outcome = %v, want OutcomeTransportError (preflight fail)", v.Outcome)
	}
	if !errors.Is(v.Err, sdkbundle.ErrUnknownFormat) {
		t.Errorf("Err = %v, want wraps ErrUnknownFormat", v.Err)
	}
}

// NetworkID-mismatch IS a preflight check that ran — the SDK
// returns a Report with PreflightErr set (not an error from
// VerifyBundle itself). The wrapper sees a Report whose
// AllChecksGreen() is false and classifies as OutcomeRejected.
// This is the "fork / equivocation" alert class — the caller
// MUST treat it as a cryptographic verdict, not a transport
// problem.
func TestVerifyBundleWithResolver_NetworkIDMismatchIsRejected(t *testing.T) {
	b := &sdkbundle.Bundle{
		Format:    sdkbundle.FormatV1,
		NetworkID: [32]byte{0xAA},
	}
	expected := [32]byte{0xBB}
	v := VerifyBundleWithResolver(context.Background(), b, &stubResolver{}, expected)
	if v.Outcome != OutcomeRejected {
		t.Errorf("Outcome = %v, want OutcomeRejected", v.Outcome)
	}
	if v.Report == nil {
		t.Fatal("Report should be non-nil on rejected (SDK ran the preflight)")
	}
	if v.Report.AllChecksGreen() {
		t.Error("Report.AllChecksGreen() must be false on NetworkID mismatch")
	}
}

// Resolver-error case: SDK calls resolver, resolver returns
// (nil, err) — SDK surfaces this as a Report.PreflightErr, NOT
// as a VerifyBundle return error (per the SDK contract).
// Wrapper classifies as OutcomeRejected (preflight failure
// observed) — though it could be argued this is "transport"
// since the underlying resolver had an I/O problem. Pin the
// behaviour explicitly so a future refactor doesn't silently
// flip the classification.
func TestVerifyBundleWithResolver_ResolverErrorIsRejected(t *testing.T) {
	b := &sdkbundle.Bundle{
		Format:         sdkbundle.FormatV1,
		WitnessSetHint: sdkbundle.WitnessSetHint{SetHash: [32]byte{0xAA}},
	}
	v := VerifyBundleWithResolver(context.Background(), b,
		&stubResolver{err: errors.New("network down")}, [32]byte{})
	if v.Outcome != OutcomeRejected {
		t.Errorf("Outcome = %v, want OutcomeRejected (resolver error → preflight fail)", v.Outcome)
	}
	if v.Report == nil || v.Report.PreflightErr == nil {
		t.Error("expected Report.PreflightErr to carry the resolver error")
	}
}
