/*
FILE PATH: libs/monitoring/protocol_version_compliance.go — platform.protocol_version_compliance.

Independent re-derivation of the network PROTOCOL-VERSION admission policy (the
synthesized genesis baseline + on-log BP-ENTRY-NETWORK-PROTOCOL-VERSION-V1
amendments) and verification that the ledger admitted no write under a
non-write-admitted version and published no illegal admission-state transition.

# THE LEGAL-TRANSITION RULE (NOT IN THE SDK)

authz.ResolveProtocolVersionAdmissionAt is last-write-wins with NO built-in
monotonicity — so, unlike the algorithm-policy walker, it will not reject an
illegal transition. The lifecycle intent is that a protocol version is RETIRED
over time (its capabilities only NARROW), never un-retired. This monitor encodes
that as a capability-shrink rule, modelling each admission state as a set of
capabilities:

	write_only {W}   read_write {W,R}   read_only {R}   forbidden {}

A transition prev→next for a given version is ILLEGAL iff next grants a
capability prev lacked (caps(next) ⊄ caps(prev)). That single rule catches every
un-retirement: un-forbidding ({}→anything), re-granting write (read_only→
read_write / write_only), re-granting read (write_only→read_write / read_only).
Retiring directions (read_write→read_only, anything→forbidden) shrink
capabilities and are legal.

WHAT IT CHECKS:
  - chain integrity: ResolveProtocolVersionAdmissionAt at the audited as-of
    (unsorted / none-in-effect → Critical).
  - legal transitions: every consecutive amendment pair, per shared version
    (capability-shrink rule above) → Critical on a re-grant.
  - per entry: the entry's Header.ProtocolVersion PermitsWrite under the policy
    in effect at the entry's position.

KEY DEPENDENCIES: baseproof/authz (the protocol-version walker), baseproof/monitoring,
tooling/libs/crosslog.
*/
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

const MonitorProtocolVersionCompliance monitoring.MonitorID = "platform.protocol_version_compliance"

// protocol-version admission-state capability bits.
const (
	capWrite = 1 << 0
	capRead  = 1 << 1
)

// capsOf maps an admission state to its capability set. An unknown state maps to
// no capabilities (defensive — the SDK decoder already rejects unknown states).
func capsOf(s authz.ProtocolVersionAdmissionState) int {
	switch s {
	case authz.ProtocolVersionWriteOnly:
		return capWrite
	case authz.ProtocolVersionReadWrite:
		return capWrite | capRead
	case authz.ProtocolVersionReadOnly:
		return capRead
	case authz.ProtocolVersionForbidden:
		return 0
	default:
		return 0
	}
}

// ProtocolVersionComplianceConfig configures the protocol-version monitor.
type ProtocolVersionComplianceConfig struct {
	// Records is the genesis-seeded, EffectivePos-sorted protocol-version chain.
	// Empty ⇒ unwired, no-op.
	Records authz.ProtocolVersionAdmissionByPosition

	// Entries are the admitted business entries to check. May be empty.
	Entries []crosslog.EntryAtPosition

	// AsOf is the audited log position used for the chain-integrity resolution.
	AsOf types.LogPosition
}

// CheckProtocolVersionCompliance resolves the protocol-version chain, flags any
// illegal admission-state transition (the capability-shrink rule the SDK does
// not enforce), and flags any admitted entry whose wire version is not
// write-admitted at its position.
func CheckProtocolVersionCompliance(
	_ context.Context,
	cfg ProtocolVersionComplianceConfig,
	now time.Time,
) ([]monitoring.Alert, error) {
	if len(cfg.Records) == 0 {
		return nil, nil
	}

	// Chain integrity at the audited as-of (records are genesis-seeded + sorted
	// by the projector; a resolve error here is a projection/ledger fault).
	if _, err := authz.ResolveProtocolVersionAdmissionAt(cfg.Records, cfg.AsOf); err != nil {
		return []monitoring.Alert{protoVersionAlert(monitoring.Critical,
			"protocol-version chain does not resolve at the audited position",
			map[string]any{"as_of": cfg.AsOf.String(), "records": len(cfg.Records), "error": err.Error()},
			now)}, nil
	}

	var alerts []monitoring.Alert

	// Legal-transition check: consecutive amendments, per shared version, must
	// only NARROW capabilities. cfg.Records is sorted by the projector.
	for i := 1; i < len(cfg.Records); i++ {
		prev := cfg.Records[i-1].Policy
		next := cfg.Records[i].Policy
		for _, nv := range next.AdmittedVersions {
			pv, ok := prev.Lookup(nv.Version)
			if !ok {
				continue // version first appears here — any initial state is legal
			}
			prevCaps, nextCaps := capsOf(pv.AdmittedFor), capsOf(nv.AdmittedFor)
			if nextCaps&^prevCaps != 0 { // next grants a capability prev lacked
				alerts = append(alerts, protoVersionAlert(monitoring.Critical,
					fmt.Sprintf("illegal protocol-version transition for version %d: %s → %s re-grants a capability",
						nv.Version, pv.AdmittedFor, nv.AdmittedFor),
					map[string]any{
						"effective_pos": cfg.Records[i].EffectivePos.String(),
						"version":       nv.Version,
						"from":          string(pv.AdmittedFor),
						"to":            string(nv.AdmittedFor),
					}, now))
			}
		}
	}

	// Per-entry: the entry's wire version must be WRITE-admitted at its position.
	for _, e := range cfg.Entries {
		if e.Entry == nil {
			continue
		}
		pol, perr := authz.ResolveProtocolVersionAdmissionAt(cfg.Records, e.Position)
		if perr != nil {
			alerts = append(alerts, protoVersionAlert(monitoring.Warning,
				"cannot resolve protocol-version policy at entry position",
				map[string]any{"entry_pos": e.Position.String(), "error": perr.Error()}, now))
			continue
		}
		v := e.Entry.Header.ProtocolVersion
		if !pol.PermitsWrite(v) {
			rec, known := pol.Lookup(v)
			state := "absent"
			if known {
				state = string(rec.AdmittedFor)
			}
			alerts = append(alerts, protoVersionAlert(monitoring.Critical,
				fmt.Sprintf("admitted entry written under protocol version %d not write-admitted (state: %s)", v, state),
				map[string]any{
					"entry_pos":        e.Position.String(),
					"signer":           e.Entry.Header.SignerDID,
					"protocol_version": v,
					"admitted_for":     state,
				}, now))
		}
	}

	return alerts, nil
}

func protoVersionAlert(sev monitoring.Severity, msg string, details map[string]any, now time.Time) monitoring.Alert {
	return monitoring.Alert{
		Monitor:     MonitorProtocolVersionCompliance,
		Severity:    sev,
		Destination: monitoring.Both,
		Message:     msg,
		Details:     details,
		EmittedAt:   now,
	}
}
