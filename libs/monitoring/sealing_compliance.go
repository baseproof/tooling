/*
FILE PATH: libs/monitoring/sealing_compliance.go
DESCRIPTION: Monitors sealing orders for premature activation (activation entry

	published before activation delay elapsed) and overdue activation (conditions
	met but no activation entry seen within a slack window).

KEY ARCHITECTURAL DECISIONS:
  - Uses verifier.EvaluateConditions (with Now + Cosignatures, required by
    SDK v1.3.3) to determine per-entry readiness.
  - Uses enforcement.ScanComplianceRange for range iteration.
  - Premature activation is Critical (protocol violation). Overdue is Warning.

OVERVIEW: CheckSealingCompliance scans Path C entries in a range and checks

	their condition timing against current state.

KEY DEPENDENCIES: baseproof/builder, baseproof/verifier, baseproof/log
*/
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/schema"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

const MonitorSealingCompliance monitoring.MonitorID = "platform.sealing_compliance"

// SealingComplianceConfig configures the sealing compliance monitor.
type SealingComplianceConfig struct {
	LocalLogDID  string
	ScanStartSeq uint64
	ScanCount    int
	// OverdueSlack allows some buffer after conditions become met before
	// flagging an activation as overdue. Typical: 1 hour.
	OverdueSlack time.Duration
}

// CheckSealingCompliance walks the scan range and flags:
//   - Pending sealing orders whose conditions met long ago (overdue).
//   - Activation entries whose referenced order's conditions weren't met
//     at activation time (premature; protocol violation).
func CheckSealingCompliance(
	ctx context.Context,
	cfg SealingComplianceConfig,
	queryAPI sdklog.LedgerQueryAPI,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	extractor schema.SchemaParameterExtractor,
	now time.Time,
) ([]monitoring.Alert, error) {
	if queryAPI == nil {
		return nil, fmt.Errorf("monitoring/sealing: nil query API")
	}
	count := cfg.ScanCount
	if count <= 0 {
		count = 500
	}

	entries, err := queryAPI.ScanFromPosition(ctx, cfg.ScanStartSeq, count)
	if err != nil {
		return nil, fmt.Errorf("monitoring/sealing: scan: %w", err)
	}

	var alerts []monitoring.Alert

	for _, meta := range entries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil {
			continue
		}

		classification, cErr := builder.ClassifyEntry(ctx, builder.ClassifyParams{
			Entry:       entry,
			Position:    meta.Position,
			LeafReader:  leafReader,
			Fetcher:     fetcher,
			LocalLogDID: cfg.LocalLogDID,
		})

		if cErr != nil || classification == nil || classification.Path != builder.PathResultPathC {
			continue
		}

		// Fetch cosignatures referencing this entry (required for threshold checks).
		cosigs, _ := queryAPI.QueryByCosignatureOf(ctx, meta.Position)

		condResult, ceErr := verifier.EvaluateConditions(ctx, verifier.EvaluateConditionsParams{
			PendingPos:   meta.Position,
			Fetcher:      fetcher,
			Extractor:    extractor,
			Cosignatures: cosigs,
			Now:          now,
		})

		if ceErr != nil || condResult == nil {
			continue
		}

		// Overdue: conditions have been met for longer than OverdueSlack and
		// we're still looking at the pending entry (no activation entry
		// follow-on has superseded it in the authority chain).
		if condResult.AllMet && cfg.OverdueSlack > 0 {
			effectiveAt := meta.LogTime
			if condResult.EarliestActivation != nil {
				effectiveAt = *condResult.EarliestActivation
			}
			age := now.Sub(effectiveAt)
			if age > cfg.OverdueSlack {
				alerts = append(alerts, makeComplianceAlert(
					monitoring.Warning,
					"overdue",
					meta.Position,
					entry.Header.SignerDID,
					fmt.Sprintf("sealing order ready %s ago but still pending", age.Round(time.Second)),
					map[string]any{
						"effective_at":  effectiveAt,
						"age_seconds":   age.Seconds(),
						"slack_seconds": cfg.OverdueSlack.Seconds(),
					},
					now,
				))
			}
		}

		// Premature detection: if an entry's conditions weren't met at its
		// OWN log-time but it's in the authority chain anyway, the ledger
		// admitted it prematurely. This is detected by re-evaluating at
		// meta.LogTime.
		earlyCheck, _ := verifier.EvaluateConditions(ctx, verifier.EvaluateConditionsParams{
			PendingPos:   meta.Position,
			Fetcher:      fetcher,
			Extractor:    extractor,
			Cosignatures: cosigs,
			Now:          meta.LogTime,
		})

		if earlyCheck != nil && !earlyCheck.AllMet {
			// Conditions weren't met at publication time. For pending entries this
			// is normal. For entries that have advanced AuthorityTip (already in
			// the chain) this is a protocol violation.
			// We use the condition result to detect the advance: if conditions
			// ARE met now AND weren't met at publication, someone waited correctly.
			// If conditions still aren't met now, entry is still pending — fine.
			// Premature = already active but shouldn't be. We detect this by
			// checking whether the entry's TargetRoot leaf's AuthorityTip equals
			// this position and conditions still aren't met.
			if entry.Header.TargetRoot != nil && !condResult.AllMet {
				leafKey := smt.DeriveKey(*entry.Header.TargetRoot)
				if leaf, _ := leafReader.Get(ctx, leafKey); leaf != nil &&
					leaf.AuthorityTip.Equal(meta.Position) {
					alerts = append(alerts, makeComplianceAlert(
						monitoring.Critical,
						"premature",
						meta.Position,
						entry.Header.SignerDID,
						"authority tip advanced but activation conditions not met",
						map[string]any{
							"target_root":    entry.Header.TargetRoot.String(),
							"authority_tip":  leaf.AuthorityTip.String(),
							"conditions_met": condResult.AllMet,
						},
						now,
					))
				}
			}
		}
	}

	return alerts, nil
}

func makeComplianceAlert(
	sev monitoring.Severity,
	kind string,
	pos types.LogPosition,
	signer string,
	message string,
	extraDetails map[string]any,
	now time.Time,
) monitoring.Alert {
	details := map[string]any{
		"entry_pos": pos.String(),
		"signer":    signer,
		"kind":      kind,
	}
	for k, v := range extraDetails {
		details[k] = v
	}
	return monitoring.Alert{
		Monitor:     MonitorSealingCompliance,
		Severity:    sev,
		Destination: monitoring.Both,
		Message:     message,
		Details:     details,
		EmittedAt:   now,
	}
}
