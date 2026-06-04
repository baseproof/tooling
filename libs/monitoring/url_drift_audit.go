/*
FILE PATH: libs/monitoring/url_drift_audit.go

T11 — Periodic background URL-drift auditor.

# WHAT THIS DOES

Runs crosslog.RunAdvisoryCrossChecks on a cadence and emits one
monitoring.Alert per mismatch detected. Mirrors the
anchor_freshness.go shape — same Alert envelope, same Severity
classification, same Destination routing so the alerting
infrastructure handles drift alerts the same way it handles
anchor staleness alerts.

# SCOPE BOUNDARY

This file is the periodic check + alert emission. The
WHAT-COUNTS-AS-DRIFT logic lives in crosslog.RunAdvisoryCrossChecks
(T9) — this file does NOT re-implement it. The alert routing logic
(Ops vs BuildCommentary) lives in the operator's Alert consumer
— this file emits Severity + Destination + Details and the
consumer dispatches.

# WHY ADVISORY

The on-log surface is AUTHORITATIVE. A mismatch detected here
does NOT change resolver behavior; the resolver continues to
return on-log URLs. The alert exists so the operator KNOWS that
a witness's domain origin or an auditor's did:web has drifted
from the network-signed surface — a real compromise indicator
that warrants investigation. The system continues to operate
correctly through the alert.

# WHY Severity = Warning

A single URL drift event is operationally a WARNING — the
on-log surface is unchanged, the system is operating correctly,
but the domain surface has diverged from the signed view. This
is the canonical "see this, investigate" signal. SUSTAINED drift
across multiple auditors / witnesses might warrant a Critical
alert at a higher tier; this monitor leaves that decision to the
operator's alert pipeline.
*/
package monitoring

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/monitoring"

	"github.com/baseproof/tooling/libs/crosslog"
)

// MonitorURLDrift is the MonitorID for the v1.32.0 URL drift
// auditor. Mirrors the MonitorAnchorFreshness ID shape so the
// alerting infrastructure can dispatch on Monitor uniformly.
const MonitorURLDrift monitoring.MonitorID = "judicial.url_drift"

// URLDriftAuditConfig configures a periodic URL drift audit.
type URLDriftAuditConfig struct {
	// LocalLogDID is the network this auditor instance is monitoring.
	// Surfaces in the alert's Details for cross-network triage.
	LocalLogDID string

	// MaterializedSource returns the latest MaterializedNetwork
	// snapshot. Typically a closure over a freshly-walked log scan
	// (see crosslog.MaterializeFromEntries) or a cached snapshot
	// kept in memory between audit cycles.
	//
	// Returning an empty MaterializedNetwork is valid — the audit
	// then does nothing (no records to cross-check). A non-nil
	// error aborts the cycle and surfaces via the returned alert
	// slice as a Critical severity audit-failure alert.
	MaterializedSource func(ctx context.Context) (crosslog.MaterializedNetwork, error)

	// Resolver is the did.DIDResolver consulted during the cross-
	// check. Typically built via clienttls.BuildDIDResolverWithMTLS
	// from the binary's hoisted outbound *http.Client. nil disables
	// the audit (every cycle returns empty alerts).
	Resolver did.DIDResolver
}

// CheckURLDrift runs one URL drift audit cycle and returns the
// alerts to dispatch. Empty slice means no drift detected (or
// the audit is disabled via nil resolver / empty materialized).
//
// Each mismatch from crosslog.RunAdvisoryCrossChecks becomes one
// monitoring.Alert with Severity=Warning, Destination=Ops, and
// Details carrying the mismatch's classification + identifier +
// resolved DID + structural reason.
//
// Audit-time errors (the MaterializedSource returning a non-nil
// error — typically a log-scan failure) surface as a single
// Critical alert so the alert pipeline sees the audit itself
// failed (vs no drift detected).
//
// logger is the slog.Logger threaded into the underlying
// crosslog.RunAdvisoryCrossChecks call (which uses it for
// per-mismatch slog.Warn lines + per-skip slog.Debug lines).
// nil routes to slog.Default(). Mirrors the CheckAnchorFreshness
// shape — no SlogLike shim, just plain *slog.Logger.
func CheckURLDrift(
	ctx context.Context,
	cfg URLDriftAuditConfig,
	logger *slog.Logger,
	now time.Time,
) ([]monitoring.Alert, error) {
	if cfg.MaterializedSource == nil {
		return nil, fmt.Errorf("monitoring/url_drift: MaterializedSource is required")
	}
	if cfg.Resolver == nil {
		// Audit disabled — return empty alerts. Operators see this
		// at the call site (the scheduler reports zero alerts) and
		// know to wire a resolver if drift detection is wanted.
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	mat, err := cfg.MaterializedSource(ctx)
	if err != nil {
		// Surface the audit-failure as a Critical alert so the
		// alert pipeline distinguishes "audit succeeded, no drift"
		// from "audit itself failed". The alert details carry the
		// underlying error so an operator can debug.
		return []monitoring.Alert{
			{
				Monitor:     MonitorURLDrift,
				Severity:    monitoring.Critical,
				Destination: monitoring.Ops,
				Message:     fmt.Sprintf("url_drift audit failed: %v", err),
				Details: map[string]any{
					"local_log": cfg.LocalLogDID,
					"error":     err.Error(),
				},
				EmittedAt: now,
			},
		}, nil
	}

	mismatches := crosslog.RunAdvisoryCrossChecks(ctx, mat, cfg.Resolver, logger)
	if len(mismatches) == 0 {
		return nil, nil
	}

	alerts := make([]monitoring.Alert, 0, len(mismatches))
	for _, m := range mismatches {
		alerts = append(alerts, monitoring.Alert{
			Monitor:     MonitorURLDrift,
			Severity:    monitoring.Warning,
			Destination: monitoring.Ops,
			Message: fmt.Sprintf("url drift: %s %s did:web disagrees with on-log record",
				m.Kind, m.Identifier),
			Details: map[string]any{
				"local_log":  cfg.LocalLogDID,
				"kind":       string(m.Kind),
				"identifier": m.Identifier,
				"did":        m.DID,
				"reason":     m.Reason,
			},
			EmittedAt: now,
		})
	}
	return alerts, nil
}
