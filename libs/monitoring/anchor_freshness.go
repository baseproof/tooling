/*
FILE PATH: libs/monitoring/anchor_freshness.go
DESCRIPTION: Monitors anchor publication cadence. Detects when a county log

	falls behind its configured anchor schedule or when the parent (state)
	log's tree head becomes stale from the county's perspective.

KEY ARCHITECTURAL DECISIONS:
  - Uses witness.TreeHeadClient to fetch parent log head + staleness check.
  - Uses log.LedgerQueryAPI.ScanFromPosition to find recent anchor
    commentary entries on the county log and compute gap since last anchor.
  - Emits monitoring.Alert via the Alert() channel pattern; caller routes
    to BuildCommentary (on-log) or PagerDuty (ops) per Alert.Destination.

# SCOPE BOUNDARY

This file is the client-side freshness check. The two complementary
pieces — KindAnchorStaleness gossip emission, and the Postgres-backed
historical retention of staleness events — are SDK-side concerns
(baseproof/monitoring + ledger schema) and intentionally not implemented
here. tooling polls and alerts; the SDK serializes the resulting
gossip envelopes and the ledger persists them.

OVERVIEW: CheckAnchorFreshness returns AlertSet describing lag conditions.
KEY DEPENDENCIES: baseproof/witness, baseproof/log, baseproof/monitoring
*/
package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

const MonitorAnchorFreshness monitoring.MonitorID = "judicial.anchor_freshness"

// AnchorFreshnessConfig configures the anchor freshness monitor.
type AnchorFreshnessConfig struct {
	// LocalLogDID is the county log being monitored.
	LocalLogDID string

	// ParentLogDID is the state/anchor log this county publishes to.
	ParentLogDID string

	// AnchorIntervalTarget is the configured publish cadence (e.g. 1 hour).
	AnchorIntervalTarget time.Duration

	// WarningThreshold defines the first threshold above which an alert fires.
	// Typical: 1.5x the target interval.
	WarningThreshold time.Duration

	// CriticalThreshold defines the threshold for Critical severity.
	// Typical: 3x the target interval.
	CriticalThreshold time.Duration

	// ParentStaleness bounds the caller's tolerance for an old parent head.
	// Typical: StalenessMonitoring (60s).
	ParentStaleness witness.StalenessConfig

	// LedgerSignerDID is the ledger DID that signs anchor entries.
	// Used to filter scan results to our own anchors.
	LedgerSignerDID string
}

// CheckAnchorFreshness evaluates whether the county log is keeping up with
// its anchor schedule and whether the parent log's head is fresh.
//
// Returns up to two alerts: one for anchor lag, one for parent staleness.
// Empty slice means everything is fine.
func CheckAnchorFreshness(
	ctx context.Context,
	cfg AnchorFreshnessConfig,
	queryAPI sdklog.LedgerQueryAPI,
	treeHeadClient *witness.TreeHeadClient,
	now time.Time,
) ([]monitoring.Alert, error) {
	if queryAPI == nil {
		return nil, fmt.Errorf("monitoring/anchor: nil query API")
	}
	if treeHeadClient == nil {
		return nil, fmt.Errorf("monitoring/anchor: nil tree head client")
	}

	var alerts []monitoring.Alert

	// Check 1: when did we last publish an anchor?
	entries, err := queryAPI.QueryBySignerDID(ctx, cfg.LedgerSignerDID)
	if err != nil {
		return nil, fmt.Errorf("monitoring/anchor: query anchors: %w", err)
	}

	lastAnchorTime, lastAnchorSeq := findLatestAnchor(entries, cfg.ParentLogDID)

	if !lastAnchorTime.IsZero() {
		gap := now.Sub(lastAnchorTime)
		sev, trigger := classifyAnchorGap(gap, cfg)
		if sev != 0 {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorAnchorFreshness,
				Severity:    sev,
				Destination: monitoring.Ops,
				Message: fmt.Sprintf(
					"anchor to %s lagging: last anchor %s ago (threshold %s)",
					cfg.ParentLogDID, gap.Round(time.Second), trigger,
				),
				Details: map[string]any{
					"local_log":         cfg.LocalLogDID,
					"parent_log":        cfg.ParentLogDID,
					"last_anchor_time":  lastAnchorTime,
					"last_anchor_seq":   lastAnchorSeq,
					"gap_seconds":       gap.Seconds(),
					"target_interval_s": cfg.AnchorIntervalTarget.Seconds(),
				},
				EmittedAt: now,
			})
		}
	} else {
		// No anchors found at all — critical for any production deployment.
		alerts = append(alerts, monitoring.Alert{
			Monitor:     MonitorAnchorFreshness,
			Severity:    monitoring.Critical,
			Destination: monitoring.Both,
			Message: fmt.Sprintf(
				"no anchor entries to %s found in recent history",
				cfg.ParentLogDID,
			),
			Details:   map[string]any{"local_log": cfg.LocalLogDID, "parent_log": cfg.ParentLogDID},
			EmittedAt: now,
		})
	}

	// Check 2: is the parent log's cached head fresh?
	_, fetchedAt, found := treeHeadClient.CachedHead(cfg.ParentLogDID)
	if found {
		_, fErr := witness.CheckFreshness(fetchedAt, now, cfg.ParentStaleness)
		if fErr != nil {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorAnchorFreshness,
				Severity:    monitoring.Warning,
				Destination: monitoring.Ops,
				Message:     fmt.Sprintf("parent log head stale: %v", fErr),
				Details: map[string]any{
					"parent_log":  cfg.ParentLogDID,
					"fetched_at":  fetchedAt,
					"max_age_sec": cfg.ParentStaleness.MaxAge.Seconds(),
				},
				EmittedAt: now,
			})
		}
	}

	return alerts, nil
}

// findLatestAnchor scans commentary entries for the most recent anchor
// entry referencing the given parent log.
func findLatestAnchor(entries []types.EntryWithMetadata, parentLogDID string) (time.Time, uint64) {
	var latestTime time.Time
	var latestSeq uint64

	for _, meta := range entries {
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		// Anchor entries are commentary (no TargetRoot, no AuthorityPath).
		if entry.Header.TargetRoot != nil || entry.Header.AuthorityPath != nil {
			continue
		}
		if len(entry.DomainPayload) == 0 {
			continue
		}

		var payload struct {
			AnchorType   string `json:"anchor_type"`
			SourceLogDID string `json:"source_log_did"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}
		if payload.AnchorType != anchor.CosignedAnchorType || payload.SourceLogDID != parentLogDID {
			continue
		}

		if meta.LogTime.After(latestTime) {
			latestTime = meta.LogTime
			latestSeq = meta.Position.Sequence
		}
	}

	return latestTime, latestSeq
}

func classifyAnchorGap(gap time.Duration, cfg AnchorFreshnessConfig) (monitoring.Severity, string) {
	if cfg.CriticalThreshold > 0 && gap >= cfg.CriticalThreshold {
		return monitoring.Critical, cfg.CriticalThreshold.String()
	}
	if cfg.WarningThreshold > 0 && gap >= cfg.WarningThreshold {
		return monitoring.Warning, cfg.WarningThreshold.String()
	}
	// No threshold exceeded.
	return 0, ""
}
