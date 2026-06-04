/*
FILE PATH: libs/monitoring/governance_shared.go

Shared primitives for the three network-governance compliance monitors
(signature_policy / algorithm_policy / protocol_version). Each monitor
independently re-derives an on-log governance chain via its SDK Resolve…At
walker and checks the admitted entries/heads against the policy in effect at
their position. These helpers are the small pieces those three checks share.

KEY DEPENDENCIES: baseproof/core/envelope (the signature-algorithm constants).
*/
package monitoring

import "github.com/baseproof/baseproof/core/envelope"

// contains reports whether v appears in set. Used for the allow-list membership
// tests (entry signature schemes, cosignature scheme tags).
func contains[T comparable](set []T, v T) bool {
	for _, e := range set {
		if e == v {
			return true
		}
	}
	return false
}

// isPQScheme reports whether algoID is a post-quantum signature scheme — the
// ML-DSA / SLH-DSA family (0x0007 / 0x0008 / 0x0009).
//
// This mirrors the ledger's conventionalGroupForAlgo "pq" grouping
// (admission/signature_policy_verifier.go). It is a HARDCODED protocol
// convention, not an SDK helper: a new PQ algorithm ID shipping in a future SDK
// requires a coordinated update here AND in the ledger. Keeping the auditor's
// notion of "PQ" identical to the ledger's is what makes the RequireHybridAfter
// consistency check an independent re-derivation rather than drift.
func isPQScheme(algoID uint16) bool {
	switch algoID {
	case envelope.SigAlgoMLDSA65, envelope.SigAlgoMLDSA87, envelope.SigAlgoSLHDSA128s:
		return true
	default:
		return false
	}
}

// policyAdmitsPQScheme reports whether the allow-list admits at least one PQ
// scheme — the precondition for a SATISFIABLE RequireHybridAfter mandate. A
// policy that sets RequireHybridAfter while admitting no PQ scheme is internally
// contradictory (entries cannot satisfy the hybrid requirement); the ledger
// rejects that policy and so the auditor flags it.
func policyAdmitsPQScheme(allowed []uint16) bool {
	for _, a := range allowed {
		if isPQScheme(a) {
			return true
		}
	}
	return false
}
