/*
FILE PATH: libs/monitoring/signature_policy_compliance.go — platform.signature_policy_compliance.

Independent re-derivation of the network SIGNATURE POLICY (the founding
GenesisSignaturePolicy + on-log BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1 amendments)
and verification that the ledger admitted only policy-compliant entries and
cosignatures. This is the auditor half of the gate the ledger enforces at
admission (admission.VerifyEntrySignaturePolicy + quorum.ValidateCosignSchemePolicy):
same on-log inputs, same SDK walker (network.ResolveSignaturePolicyAt), so a
mismatch is a genuine finding — the ledger admitted something the network policy
forbids — not drift.

WHAT IT CHECKS, at the policy in effect at each subject's OWN position:
  - chain integrity: the projected chain resolves at the audited as-of (a
    non-resolving chain — unsorted / none-in-effect — is itself Critical).
  - per entry: every signature's AlgoID ∈ AllowedEntrySigSchemes, and the
    signature count ≥ MinSignaturesPerEntry.
  - per cosigned head: every cosignature SchemeTag ∈ AllowedCosignSchemeTags
    (the cosign-scheme-tags gap — the SDK cosignature verifier is structural and
    has NO notion of the network's AllowedCosignSchemeTags).
  - policy consistency: a RequireHybridAfter mandate with no PQ scheme in the
    allow-list is unsatisfiable (Warning).

A genuine policy violation is Critical: in steady state it is impossible (the
ledger's admission gate already rejected it), so when it fires it has caught a
gate bypass — exactly the defense-in-depth this monitor exists for.

KEY DEPENDENCIES: baseproof/network (the signature-policy walker), baseproof/monitoring,
tooling/libs/crosslog (the EntryAtPosition projection input).
*/
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

const MonitorSignaturePolicyCompliance monitoring.MonitorID = "platform.signature_policy_compliance"

// CosignedHeadObservation is one cosigned tree head as the auditor observed it:
// the head's log position + the scheme tags of the cosignatures it carries. The
// daemon projects these from the heads it has ingested; the monitor checks each
// tag against the AllowedCosignSchemeTags in effect at the head's position.
type CosignedHeadObservation struct {
	Position   types.LogPosition
	SchemeTags []uint8
}

// SignaturePolicyComplianceConfig configures the signature-policy monitor. All
// inputs are already-projected (the daemon scans + materializes; see
// crosslog.MaterializeGovernance), keeping the check pure over its inputs.
type SignaturePolicyComplianceConfig struct {
	// Records is the genesis-seeded, EffectivePos-sorted signature-policy chain
	// (records[0] is the genesis baseline). Empty ⇒ the monitor is unwired and
	// no-ops.
	Records network.SignaturePolicyByPosition

	// Entries are the admitted business entries to check (each at its on-log
	// position). May be empty (no per-entry checks performed).
	Entries []crosslog.EntryAtPosition

	// Heads are the cosigned tree heads to check for cosignature scheme-tag
	// compliance. May be empty.
	Heads []CosignedHeadObservation

	// AsOf is the audited log position (typically the latest tree size) used for
	// the chain-integrity resolution.
	AsOf types.LogPosition
}

// CheckSignaturePolicyCompliance resolves the signature-policy chain and flags
// any admitted entry or cosignature that violates the policy in effect at its
// position. An empty Records slice (the monitor is unwired) returns no alerts.
func CheckSignaturePolicyCompliance(
	_ context.Context,
	cfg SignaturePolicyComplianceConfig,
	now time.Time,
) ([]monitoring.Alert, error) {
	if len(cfg.Records) == 0 {
		return nil, nil
	}

	// Chain integrity: the chain must resolve at the audited as-of. A
	// non-resolving chain (unsorted records, or as-of before genesis) is a
	// projection/ledger fault and Critical on its own — and per-entry
	// resolution below would fail identically, so report it once and stop.
	asOfPolicy, err := network.ResolveSignaturePolicyAt(cfg.Records, cfg.AsOf)
	if err != nil {
		return []monitoring.Alert{sigPolicyAlert(monitoring.Critical,
			"signature-policy chain does not resolve at the audited position",
			map[string]any{"as_of": cfg.AsOf.String(), "records": len(cfg.Records), "error": err.Error()},
			now)}, nil
	}

	var alerts []monitoring.Alert

	// Policy consistency: a hybrid-after mandate is unsatisfiable without a PQ
	// scheme in the allow-list (the ledger rejects such a policy).
	if asOfPolicy.RequireHybridAfter != nil && !policyAdmitsPQScheme(asOfPolicy.AllowedEntrySigSchemes) {
		alerts = append(alerts, sigPolicyAlert(monitoring.Warning,
			"signature policy sets require_hybrid_after but admits no post-quantum scheme (unsatisfiable)",
			map[string]any{
				"as_of":                     cfg.AsOf.String(),
				"require_hybrid_after":      *asOfPolicy.RequireHybridAfter,
				"allowed_entry_sig_schemes": asOfPolicy.AllowedEntrySigSchemes,
			}, now))
	}

	// Per-entry compliance, against the policy in effect at the ENTRY's position.
	for _, e := range cfg.Entries {
		if e.Entry == nil {
			continue
		}
		pol, perr := network.ResolveSignaturePolicyAt(cfg.Records, e.Position)
		if perr != nil {
			alerts = append(alerts, sigPolicyAlert(monitoring.Warning,
				"cannot resolve signature policy at entry position",
				map[string]any{"entry_pos": e.Position.String(), "error": perr.Error()}, now))
			continue
		}
		if uint8Count(len(e.Entry.Signatures)) < pol.MinSignaturesPerEntry {
			alerts = append(alerts, sigPolicyAlert(monitoring.Critical,
				"admitted entry carries fewer signatures than min_signatures_per_entry",
				map[string]any{
					"entry_pos":                e.Position.String(),
					"signer":                   e.Entry.Header.SignerDID,
					"signature_count":          len(e.Entry.Signatures),
					"min_signatures_per_entry": pol.MinSignaturesPerEntry,
				}, now))
		}
		for _, sig := range e.Entry.Signatures {
			if !contains(pol.AllowedEntrySigSchemes, sig.AlgoID) {
				alerts = append(alerts, sigPolicyAlert(monitoring.Critical,
					fmt.Sprintf("admitted entry signed with non-allowed scheme 0x%04X", sig.AlgoID),
					map[string]any{
						"entry_pos":                 e.Position.String(),
						"signer":                    e.Entry.Header.SignerDID,
						"algo_id":                   fmt.Sprintf("0x%04X", sig.AlgoID),
						"allowed_entry_sig_schemes": pol.AllowedEntrySigSchemes,
					}, now))
			}
		}
	}

	// Cosignature scheme-tag compliance, against the policy at the HEAD's position.
	for _, h := range cfg.Heads {
		pol, herr := network.ResolveSignaturePolicyAt(cfg.Records, h.Position)
		if herr != nil {
			alerts = append(alerts, sigPolicyAlert(monitoring.Warning,
				"cannot resolve signature policy at head position",
				map[string]any{"head_pos": h.Position.String(), "error": herr.Error()}, now))
			continue
		}
		for _, tag := range h.SchemeTags {
			if !contains(pol.AllowedCosignSchemeTags, tag) {
				alerts = append(alerts, sigPolicyAlert(monitoring.Critical,
					fmt.Sprintf("cosigned head carries cosignature scheme tag 0x%02X not in allowed_cosign_scheme_tags", tag),
					map[string]any{
						"head_pos":                   h.Position.String(),
						"scheme_tag":                 fmt.Sprintf("0x%02X", tag),
						"allowed_cosign_scheme_tags": pol.AllowedCosignSchemeTags,
					}, now))
			}
		}
	}

	return alerts, nil
}

// uint8Count clamps a signature count into the uint8 domain MinSignaturesPerEntry
// lives in (range 1..64), so a pathologically large bundle (>255 signatures)
// compares correctly rather than wrapping to a small value and tripping a false
// sub-threshold alert. n is a slice length, so it is never negative.
func uint8Count(n int) uint8 {
	if n > 255 {
		return 255
	}
	return uint8(n)
}

func sigPolicyAlert(sev monitoring.Severity, msg string, details map[string]any, now time.Time) monitoring.Alert {
	return monitoring.Alert{
		Monitor:     MonitorSignaturePolicyCompliance,
		Severity:    sev,
		Destination: monitoring.Both,
		Message:     msg,
		Details:     details,
		EmittedAt:   now,
	}
}
