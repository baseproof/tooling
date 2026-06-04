// FILE PATH: services/auditor/internal/gossipfeed/metrics_test.go
//
// Tests for the Phase 9 OTel error-dimensionality classifier
// (Trust Alignment 14). The classifier is the only public
// surface that has stable semantics worth testing
// independently of the OTel meter — the counter wiring itself
// is a thin pass-through to the SDK.
//
//  1. ClassifyError returns ErrorClassOther for nil input.
//  2. v1.7.1 typed-sentinel classification via errors.Is:
//     gossip.ErrSignatureInvalid → SignatureInvalid;
//     gossip.ErrChainBreak → ChainBreak;
//     gossip.ErrLamportRegression → LamportRegression;
//     gossip.ErrSinkQueueFull → QueueFull. Each is checked
//     wrapped (fmt.Errorf %w) to prove the classifier unwraps.
//  3. Errors NOT matching any sentinel return ErrorClassOther,
//     INCLUDING free-text that merely mentions "signature" — the
//     v1.7.1 classifier no longer string-matches, so an
//     unrelated error can never mis-page security.
//  4. nil-receiver RecordEmit / RecordError are no-ops (callers
//     can pre-emptively wire Instruments without a meter
//     configured in dev / test).
package gossipfeed

import (
	"errors"
	"fmt"
	"testing"

	"github.com/baseproof/baseproof/gossip"
)

func TestClassifyError_NilReturnsOther(t *testing.T) {
	if got := ClassifyError(nil); got != ErrorClassOther {
		t.Fatalf("ClassifyError(nil) = %q, want %q", got, ErrorClassOther)
	}
}

func TestClassifyError_TypedSentinels_ViaErrorsIs(t *testing.T) {
	cases := []struct {
		name     string
		sentinel error
		want     ErrorClass
	}{
		{"signature_invalid", gossip.ErrSignatureInvalid, ErrorClassSignatureInvalid},
		{"chain_break", gossip.ErrChainBreak, ErrorClassChainBreak},
		{"lamport_regression", gossip.ErrLamportRegression, ErrorClassLamportRegression},
		{"queue_full", gossip.ErrSinkQueueFull, ErrorClassQueueFull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Bare sentinel.
			if got := ClassifyError(tc.sentinel); got != tc.want {
				t.Errorf("bare %v = %q, want %q", tc.sentinel, got, tc.want)
			}
			// Wrapped sentinel — proves the classifier unwraps via errors.Is.
			wrapped := fmt.Errorf("gossipfeed publish at originator did:web:x: %w", tc.sentinel)
			if got := ClassifyError(wrapped); got != tc.want {
				t.Errorf("wrapped %v = %q, want %q", tc.sentinel, got, tc.want)
			}
		})
	}
}

func TestClassifyError_OtherForUnmatched(t *testing.T) {
	// Free-text errors — including ones that mention "signature" —
	// must NOT match any security/SRE bucket. This is the whole
	// point of the v1.7.1 typed-sentinel switch: a stray log line
	// mentioning "signature" can never page the security on-call.
	cases := []error{
		errors.New("some unanticipated infrastructure failure"),
		errors.New("goroutine panic recovered"),
		errors.New("signature verification failed"), // free-text, NOT the sentinel
		errors.New("chain break at event 0xabcd"),   // free-text, NOT the sentinel
	}
	for _, err := range cases {
		if got := ClassifyError(err); got != ErrorClassOther {
			t.Errorf("%q = %q, want %q (untyped → low-priority bucket)", err, got, ErrorClassOther)
		}
	}
}

func TestNilInstruments_NoOps(t *testing.T) {
	var inst *Instruments
	// Both methods must be safe on a nil receiver so production
	// hot paths don't need to nil-check before recording.
	inst.RecordEmit(gossip.KindCosignedTreeHead)
	inst.RecordError(gossip.KindEquivocationFinding, errors.New("anything"))
}

func TestErrorClassValues_AreStable(t *testing.T) {
	// Dashboard panels query on these exact strings. The test
	// fails if they ever change without coordinated dashboard
	// updates.
	want := []ErrorClass{
		"signature_invalid",
		"chain_break",
		"lamport_regression",
		"queue_full",
		"other",
	}
	got := []ErrorClass{
		ErrorClassSignatureInvalid,
		ErrorClassChainBreak,
		ErrorClassLamportRegression,
		ErrorClassQueueFull,
		ErrorClassOther,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ErrorClass constants drifted at idx %d: want %q got %q",
				i, want[i], got[i])
		}
	}
}
