// FILE PATH: cmd/auditor/rotation_wiring.go
//
// The AT-2 wiring seams main.go composes, extracted as testable functions —
// the original position-aware-resolver gap was a WIRING omission, so the
// wiring itself gets functional tests (rotation_wiring_test.go), not just the
// components it connects.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"

	"github.com/baseproof/tooling/libs/witnessrotation"
	"github.com/baseproof/tooling/services/auditor/internal/store"
)

// currentSetResolver is the narrow seam boot-time anchor reconstruction needs.
// *store.JournalWitnessSetResolver satisfies it.
type currentSetResolver interface {
	CurrentSet(ctx context.Context, logDID string) (*cosign.WitnessKeySet, error)
}

// reseedWitnessSets replaces each log's GENESIS seed in the live trust map
// with the journal-reconstructed CURRENT set (AT-2/B). After any past rotation
// the genesis seed can no longer verify the live horizon — keeping it would
// silently re-open the stale-trust gap on every restart. Fail-static per log:
// an unreadable chain keeps the genesis seed (exactly correct for a
// never-rotated log; loudly logged otherwise).
func reseedWitnessSets(
	ctx context.Context,
	roots []store.LogTrustRoot,
	resolver currentSetResolver,
	witnessSets map[string]*cosign.WitnessKeySet,
	originatorByLog map[string]string,
	logger *slog.Logger,
) {
	for _, root := range roots {
		cur, err := resolver.CurrentSet(ctx, root.LogDID)
		if err != nil {
			logger.Warn("auditor: witness-set anchor reconstruction failed; keeping genesis seed",
				"log_did", root.LogDID, "err", err.Error())
			continue
		}
		if cur != root.Genesis {
			logger.Info("auditor: live witness set re-seeded from journaled rotation chain",
				"log_did", root.LogDID, "originator", originatorByLog[root.LogDID])
		}
		witnessSets[originatorByLog[root.LogDID]] = cur
	}
}

// rotationScanner is the narrow seam the scan job drives.
// *witnessrotation.ScanReconciler satisfies it.
type rotationScanner interface {
	RunOnce(ctx context.Context) (witnessrotation.ScanReport, error)
}

// buildRotationScanJob returns the scheduler job that runs every per-log scan
// reconciler once and converts outcomes to alerts:
//
//   - trust-integrity failures (no verifiable target / broken journal chain /
//     invalid on-log rotation) → Critical: the log's cosigner set cannot be
//     explained, or evidence of an unauthorized rotation;
//   - transport/transient failures → Warning (the next pass re-covers the
//     window; the cursor never advanced);
//   - NewlyJournaled > 0 → Warning: the scan found rotations gossip never
//     delivered — the tail-omission the scan exists to catch, surfaced as
//     evidence rather than silently absorbed.
//
// One log's failure never mutes the others.
func buildRotationScanJob(scanners []rotationScanner, now func() time.Time) func(context.Context) ([]sdkmonitoring.Alert, error) {
	return func(ctx context.Context) ([]sdkmonitoring.Alert, error) {
		ts := now().UTC()
		var alerts []sdkmonitoring.Alert
		for _, sc := range scanners {
			report, err := sc.RunOnce(ctx)
			if err != nil {
				sev := sdkmonitoring.Warning // transport/transient by default
				if errors.Is(err, witnessrotation.ErrNoVerifiableTarget) ||
					errors.Is(err, witnessrotation.ErrJournalChainBroken) ||
					errors.Is(err, witnessrotation.ErrOnLogRotationInvalid) {
					sev = sdkmonitoring.Critical
				}
				alerts = append(alerts, sdkmonitoring.Alert{
					Monitor:     "witness_rotation_scan",
					Severity:    sev,
					Destination: sdkmonitoring.Ops,
					Message:     fmt.Sprintf("rotation scan for %s failed: %v", report.LogDID, err),
					Details:     map[string]any{"log_did": report.LogDID, "from": report.From},
					EmittedAt:   ts,
				})
				continue
			}
			if report.NewlyJournaled > 0 {
				alerts = append(alerts, sdkmonitoring.Alert{
					Monitor:     "witness_rotation_scan",
					Severity:    sdkmonitoring.Warning,
					Destination: sdkmonitoring.Ops,
					Message: fmt.Sprintf("scan journaled %d on-log rotation(s) for %s that gossip never delivered (window [%d,%d))",
						report.NewlyJournaled, report.LogDID, report.From, report.Until),
					Details: map[string]any{
						"log_did": report.LogDID, "newly_journaled": report.NewlyJournaled,
						"from": report.From, "until": report.Until,
					},
					EmittedAt: ts,
				})
			}
		}
		return alerts, nil
	}
}
