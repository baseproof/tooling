/*
FILE PATH:

	admission/feature_flags.go

DESCRIPTION:

	Per-gate feature flags for the SDK uniform-verify rollout
	(issue #75). Each admission gate is guarded by exactly one
	boolean here, populated from one environment variable.

	Defaults reflect the ledger's role as the structural-correctness
	trust boundary:

	  - Gates 1 (multi-sig) and 2 (CosignatureOf binding) default
	    ON. They are the ledger's structural/cryptographic trust
	    boundary — every downstream consumer (judicial-network,
	    witnesses, monitors) inherits the protection.

	  - Gate 4 (surgical evidence-chain STRUCTURAL walk: cycles,
	    broken hops, bounded depth) defaults OFF. It depends on
	    production wiring (EntryFetcher) that lands as a follow-up;
	    flipping ON before wiring is harmless (the gate fails-open
	    on missing capability) but the env var stays the explicit
	    opt-in for ops clarity.

	  - Domain-policy enforcement (schema-declared attestation
	    policies, role/authority decisions) is NOT a ledger
	    concern. The judicial-network SubmitGate is the canonical
	    writer-side validator; the ledger is a dumb sequencer that
	    only checks structure + cryptography.

	Operators flip any gate OFF for a canary cycle by setting the
	corresponding env var to "false" (or "0" / "no" / "off"). The
	var is the override knob, not a master-enable switch.

WHY ONE-FLAG-PER-GATE:

	Composite kill-switches force "all on / all off" decisions.
	Independent flags let ops respond to a per-gate regression by
	flipping that gate alone — the other gates stay armed, the
	rollback surface is minimal, and the dashboard signal that
	triggered the rollback stays attributable.

ENVIRONMENT VARIABLES (override the per-gate default; case-
insensitive "true"/"1"/"yes"/"on" enables, "false"/"0"/"no"/"off"
disables; unset means "use the default"):

  - LEDGER_ADMISSION_MULTISIG_ENABLE         — PR-C gate 1 (default ON)
  - LEDGER_ADMISSION_COSIG_BINDING_ENABLE    — PR-D gate 2 (default ON)
  - LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE   — PR-F gate 4 (default OFF)
  - LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE — Part II.6 (default OFF)
  - LEDGER_ADMISSION_MODEB_POW_ENABLE        — Post-II #3 (default ON)

USAGE:

	gates := admission.LoadGatesFromEnv()
	if gates.MultiSig {
	    // PR-C: attestation.VerifyEntrySignatures path
	} else {
	    // legacy single-sig path (signatures.VerifyEntry)
	}

	The Gates struct is also constructible by tests
	(admission.Gates{MultiSig: true}) without env munging.
*/
package admission

import (
	"os"
	"strings"
)

// Gates groups the per-gate booleans that the admission path
// consults at request time. Pass by value; the struct is small and
// immutable after construction.
type Gates struct {
	// MultiSig enables PR-C: replace signatures.VerifyEntry with
	// attestation.VerifyEntrySignatures so every Signatures[i] is
	// verified, not only Signatures[0]. Default ON — closes the
	// silent multi-sig gap at the ledger trust boundary. Override
	// to false via LEDGER_ADMISSION_MULTISIG_ENABLE=false for a
	// canary disable.
	MultiSig bool

	// CosigBinding enables PR-D: when entry.Header.CosignatureOf
	// is non-nil, look up the target locally and call
	// attestation.IsAttestation to confirm the binding before
	// admission. Default ON — closes the silent "CosignatureOf =
	// random position" gap at the ledger trust boundary.
	CosigBinding bool

	// EvidenceChain enables PR-F: surgical
	// verifier.VerifyEvidenceChain walk for Path C / scope-authority
	// entries OR policies declaring DelegationOriginDID. NOT a
	// universal walk on every admission. Default OFF (depends on
	// EvidenceChainFetcher wiring; fail-open until wired).
	EvidenceChain bool

	// SignaturePolicy enables Part II.6: after per-signature
	// cryptographic verification (MultiSig gate), enforce the
	// network's SignaturePolicy — allow-list of admitted algoIDs,
	// minimum valid-signature count, per-group thresholds. The
	// policy source is the SignaturePolicyResolver in
	// SubmissionDeps; v1.3 ships GenesisSignaturePolicyResolver
	// (static, BootstrapDocument-derived). Default OFF during
	// rollout to give operators a canary cycle; flipped ON via
	// LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE=true once the
	// network's GenesisSignaturePolicy has been verified against
	// the live admission traffic shape.
	SignaturePolicy bool

	// ModeBPoW enables Mode-B Proof-of-Work admission for
	// unauthenticated submissions (post-Part-II #3 — issue #152).
	// Default ON — the gate was unconditional before the
	// refactor; flipping ON preserves the existing security
	// posture (unauthenticated submissions MUST satisfy PoW).
	// Operators flip to false via
	// LEDGER_ADMISSION_MODEB_POW_ENABLE=false to disable Mode-B
	// entirely; in that posture the admission handler rejects
	// every unauthenticated submission outright ("this network
	// requires authenticated Mode-A submissions"). The handler
	// does NOT silently admit Mode-B without PoW — that would be
	// a security regression.
	ModeBPoW bool

	// AlgorithmPolicy enables the on-log algorithm-policy gate (issue #201,
	// crypto-agility): after cryptographic verification, reject an entry whose
	// signature algorithm is "forbidden" (or absent) under the network's current
	// algorithm policy (active|deprecated admitted). Source is
	// AlgorithmPolicyResolver in SubmissionDeps (genesis-only or the
	// amendment-aware OnLog resolver). Default OFF — flip via
	// LEDGER_ADMISSION_ALGORITHM_POLICY_ENABLE=true.
	AlgorithmPolicy bool

	// ProtocolVersion enables the on-log protocol-version admission gate
	// (issue #201): reject a submission whose wire-format version is not admitted
	// for writes by the network's current policy (read_only|forbidden|absent
	// rejected). Source is ProtocolVersionResolver in SubmissionDeps. Default
	// OFF — flip via LEDGER_ADMISSION_PROTOCOL_VERSION_ENABLE=true. When off, the
	// legacy "wire version == CurrentProtocolVersion()" rule stands.
	ProtocolVersion bool
}

// envFlagWithDefault returns the truthy/falsy interpretation of
// name's env value, falling back to def when unset. Case-
// insensitive. Recognised truthy: "true"/"1"/"yes"/"on". Recognised
// falsy: "false"/"0"/"no"/"off". Unrecognised non-empty values
// fall back to def (operator clearly meant SOMETHING but didn't
// match the vocabulary — preserve the default rather than guess).
//
// Centralised here so all gates use identical parsing.
func envFlagWithDefault(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

// LoadGatesFromEnv reads the LEDGER_ADMISSION_*_ENABLE
// environment variables and returns the populated Gates struct
// with per-gate defaults applied for unset variables. Called once
// at boot from cmd/ledger/boot/wire and threaded through
// SubmissionDeps; never re-read at request time.
func LoadGatesFromEnv() Gates {
	return Gates{
		MultiSig:        envFlagWithDefault("LEDGER_ADMISSION_MULTISIG_ENABLE", true),
		CosigBinding:    envFlagWithDefault("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", true),
		EvidenceChain:   envFlagWithDefault("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", false),
		SignaturePolicy: envFlagWithDefault("LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE", false),
		ModeBPoW:        envFlagWithDefault("LEDGER_ADMISSION_MODEB_POW_ENABLE", true),
		AlgorithmPolicy: envFlagWithDefault("LEDGER_ADMISSION_ALGORITHM_POLICY_ENABLE", false),
		ProtocolVersion: envFlagWithDefault("LEDGER_ADMISSION_PROTOCOL_VERSION_ENABLE", false),
	}
}
