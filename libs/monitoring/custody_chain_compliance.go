/*
FILE PATH: libs/monitoring/custody_chain_compliance.go — platform.custody_chain_compliance.

Independent re-derivation of every artifact's on-log custody chain
(ArtifactGenesis → CustodyTransfer → Destruction). The ledger gates restricted
artifact reads on this chain (artifactstore.CustodyHook → storage.ArtifactCustodyAt);
this monitor walks the SAME chain from the SAME on-log entries to detect one the
ledger should never have admitted.

WHAT IT CHECKS, per artifact (grouped by ContentDigest), at the audited as-of:
  - storage.ArtifactCustodyAt walks the genesis + EffectivePos-sorted transfers
    with per-hop FromOwner == current-owner verification (fail-closed). A walk
    error is the finding:
  - ErrCustodyChainBroken  — a transfer's FromOwner is not the current owner
    (a forged / orphan transfer) → Critical.
  - ErrCustodyCrossContent — a transfer is spliced from another artifact's
    chain → Critical.
  - ErrCustodyGenesisRequired / ErrCustodyTransfersNotSorted /
    ErrCustodyNullEffectivePos → Warning: after this monitor sorts +
    EffectivePos is stamped from the on-log position, these signal a
    scan-window gap (no genesis in range) or a projection anomaly, not a
    proven ledger fraud — surfaced for investigation, not paged.

A clean chain — including a genesis-only artifact or one with an in-effect
destruction (a legitimate erasure) — raises nothing.

The auditor cannot observe restricted READS, so served-while-destroyed
enforcement is out of scope here (it needs serve-time access logs the auditor
does not hold); this monitor verifies the chain INTEGRITY the ledger relies on.

KEY DEPENDENCIES: baseproof/storage (the custody walk + sort), baseproof/monitoring,
tooling/libs/crosslog (the per-ContentDigest projection).
*/
package monitoring

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

const MonitorCustodyChainCompliance monitoring.MonitorID = "platform.custody_chain_compliance"

// CustodyChainComplianceConfig configures the custody-chain monitor. Custody is
// the per-ContentDigest projection (see crosslog.MaterializeCustody); empty ⇒
// the monitor is unwired and no-ops.
type CustodyChainComplianceConfig struct {
	Custody crosslog.MaterializedCustody
	// AsOf is the audited log position. Walk every chain up to here — typically
	// the latest tree size so all transfers are included.
	AsOf types.LogPosition
}

// CheckCustodyChainCompliance walks each artifact's custody chain via
// storage.ArtifactCustodyAt and flags any chain that does not walk cleanly. An
// empty projection returns no alerts.
func CheckCustodyChainCompliance(
	_ context.Context,
	cfg CustodyChainComplianceConfig,
	now time.Time,
) ([]monitoring.Alert, error) {
	if len(cfg.Custody.Chains) == 0 {
		return nil, nil
	}
	if cfg.AsOf.IsNull() {
		return []monitoring.Alert{custodyAlert(monitoring.Warning,
			"custody audit has no as-of position (cannot walk chains)",
			map[string]any{"chains": len(cfg.Custody.Chains)}, now)}, nil
	}

	// Deterministic alert order across runs.
	keys := make([]string, 0, len(cfg.Custody.Chains))
	for k := range cfg.Custody.Chains {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var alerts []monitoring.Alert
	for _, k := range keys {
		ch := cfg.Custody.Chains[k]
		// Defensive copy before the in-place sort so the projection slice is not
		// mutated under a concurrent reader, then feed the walk in EffectivePos order.
		transfers := append([]storage.ArtifactCustodyTransfer(nil), ch.Transfers...)
		storage.SortCustodyTransfers(transfers)

		_, _, err := storage.ArtifactCustodyAt(ch.Genesis, transfers, cfg.AsOf)
		if err == nil {
			continue // chain walks cleanly (incl. genesis-only / destroyed)
		}
		alerts = append(alerts, custodyAlert(custodySeverity(err), custodyMessage(err),
			map[string]any{
				"content_digest": k,
				"genesis_owner":  ch.Genesis.Owner,
				"transfers":      len(transfers),
				"destroyed":      ch.Destruction != nil && !cfg.AsOf.Less(ch.Destruction.EffectivePos),
				"error":          err.Error(),
			}, now))
	}
	return alerts, nil
}

// custodySeverity maps a walk error to a severity. A FromOwner mismatch or a
// cross-content splice is a genuine structural violation the ledger admitted
// (Critical); a missing genesis or an ordering/null anomaly is most likely a
// scan-window gap or projection issue on the auditor side (Warning).
func custodySeverity(err error) monitoring.Severity {
	switch {
	case errors.Is(err, storage.ErrCustodyChainBroken),
		errors.Is(err, storage.ErrCustodyCrossContent):
		return monitoring.Critical
	default:
		return monitoring.Warning
	}
}

func custodyMessage(err error) string {
	switch {
	case errors.Is(err, storage.ErrCustodyChainBroken):
		return "custody chain broken: a transfer's FromOwner is not the current owner (forged/orphan transfer)"
	case errors.Is(err, storage.ErrCustodyCrossContent):
		return "custody chain spliced: a transfer references a different artifact's ContentDigest"
	case errors.Is(err, storage.ErrCustodyGenesisRequired):
		return "custody chain has no genesis in the audited range (scan-window gap or orphan transfers)"
	default:
		return "custody chain does not walk cleanly"
	}
}

func custodyAlert(sev monitoring.Severity, msg string, details map[string]any, now time.Time) monitoring.Alert {
	return monitoring.Alert{
		Monitor:     MonitorCustodyChainCompliance,
		Severity:    sev,
		Destination: monitoring.Both,
		Message:     msg,
		Details:     details,
		EmittedAt:   now,
	}
}

// CustodyChainSource returns the latest custody projection + audited as-of.
// Typically a closure over a freshly-walked (or cached) log scan. A non-nil
// error aborts the cycle; an empty projection is valid (the monitor no-ops).
type CustodyChainSource func(ctx context.Context) (CustodyChainComplianceConfig, error)
