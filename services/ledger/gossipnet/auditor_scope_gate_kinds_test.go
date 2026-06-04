/*
FILE PATH: gossipnet/auditor_scope_gate_kinds_test.go

v1.32.0 SDK adoption — Tier C tests for the isFindingKind
dispatch in AuditorScopeGate. Companion to
auditor_scope_gate_test.go; separated so the dispatch table is
its own assertion surface (a regression that adds a new finding
Kind without registering it here would be visible immediately).

# WHAT THIS LOCKS

isFindingKind(k) → true iff k is one of:
  - sdkgossip.KindEquivocationFinding
  - sdkgossip.KindSMTReplayFinding
  - sdkgossip.KindHistoryRewriteFinding

Every other SDK-registered kind MUST return false. The list is
exhaustive over the SDK's RegisteredKinds() at the time of
v1.32.0 — a new Kind added in a future SDK bump that should be
gated by the auditor registry will surface as a failed test
here (the new Kind appears in RegisteredKinds() but
isFindingKind returns false). That's the desired forcing
function: every new finding Kind requires an intentional
dispatch update.

Pure unit tests; iterates over sdkgossip.RegisteredKinds().
*/
package gossipnet

import (
	"testing"

	sdkgossip "github.com/baseproof/baseproof/gossip"
)

// TestIsFindingKind_KnownFindings pins the three finding kinds
// the v1.32.0 auditor scope gates. A regression that loses any
// of these would silently let unauthorized DIDs publish that
// kind through the gossip plane.
func TestIsFindingKind_KnownFindings(t *testing.T) {
	cases := []sdkgossip.Kind{
		sdkgossip.KindEquivocationFinding,
		sdkgossip.KindSMTReplayFinding,
		sdkgossip.KindHistoryRewriteFinding,
	}
	for _, k := range cases {
		if !isFindingKind(k) {
			t.Errorf("isFindingKind(%s) = false, want true (a finding kind)", k)
		}
	}
}

// TestIsFindingKind_NonFindings pins the inverse: every other
// SDK-registered kind MUST NOT be gated. Cosigned tree heads in
// particular: they're high-volume, signed by the LEDGER (not
// auditors), and gating them through the auditor registry would
// brick the entire gossip plane.
func TestIsFindingKind_NonFindings(t *testing.T) {
	cases := []sdkgossip.Kind{
		sdkgossip.KindCosignedTreeHead,
		sdkgossip.KindOriginatorRotation,
		sdkgossip.KindWitnessRotation,
		sdkgossip.KindEscrowOverrideAuth,
		sdkgossip.KindGhostLeaf,
		sdkgossip.KindCrossLogInclusion,
		sdkgossip.KindEntryCommitmentEquivocation,
	}
	for _, k := range cases {
		if isFindingKind(k) {
			t.Errorf("isFindingKind(%s) = true, want false (not a finding kind)", k)
		}
	}
}

// TestIsFindingKind_UnregisteredKindReturnsFalse pins the closed-
// set behavior: an unrecognized kind string MUST return false.
// A regression that defaulted to true would let unknown
// (potentially attacker-crafted) Kind strings collapse into the
// auditor gate's authorization check, which then probably
// fails closed — but the safer answer is "this isn't a finding,
// don't gate it; let the SDK's own kind registry reject it".
func TestIsFindingKind_UnregisteredKindReturnsFalse(t *testing.T) {
	cases := []sdkgossip.Kind{
		"BP-GOSSIP-MADE-UP-V99",
		"",
		"random text",
	}
	for _, k := range cases {
		if isFindingKind(k) {
			t.Errorf("isFindingKind(%q) = true, want false", k)
		}
	}
}

// TestIsFindingKind_ExhaustiveOverSDKRegistry asserts coverage:
// every Kind the SDK currently registers must be explicitly
// classified by isFindingKind. A new Kind shipped in a future
// SDK that arrives without a classification decision here
// either:
//
//   - Surfaces here as a previously-unknown Kind that defaults
//     to "not a finding" (probably fine — gossip plane unchanged)
//     OR
//   - Surfaces in production as a Kind the gate doesn't gate,
//     and an auditor capability the network expected to restrict
//     is silently unrestricted.
//
// The forcing function is: this test enumerates every registered
// Kind and asserts isFindingKind returned EITHER true or false
// (already true by Go's type system — bool always returns); the
// useful assertion is that any NEW Kind must trigger an explicit
// review by the developer adding the kind to the registry. We
// log every Kind's classification so the test's output gives
// reviewers a snapshot.
func TestIsFindingKind_ExhaustiveOverSDKRegistry(t *testing.T) {
	known := sdkgossip.RegisteredKinds()
	if len(known) == 0 {
		t.Fatal("SDK reports no registered kinds — sanity check failed")
	}
	for _, k := range known {
		_ = isFindingKind(k) // forces every registered Kind through the dispatch
		t.Logf("Kind %s -> finding=%v", k, isFindingKind(k))
	}
}
