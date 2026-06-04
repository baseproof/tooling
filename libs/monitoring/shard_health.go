/*
FILE PATH: libs/monitoring/shard_health.go
DESCRIPTION: Monitors shard chain integrity and per-shard size thresholds.

	Uses SDK verifier.VerifyShardChain for link verification and tracks
	size against configured freeze thresholds.

KEY ARCHITECTURAL DECISIONS:
  - Caller provides the full shard chain (from ledger's shard manager).
  - Uses verifier.VerifyShardChain to detect genesis link breaks.
  - Flags shards approaching freeze threshold (warning) and over it (critical).

OVERVIEW: CheckShardHealth returns alerts for chain breaks + threshold crossings.
KEY DEPENDENCIES: baseproof/verifier
*/
package monitoring

import (
	"fmt"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/verifier"
)

const MonitorShardHealth monitoring.MonitorID = "judicial.shard_health"

// ShardHealthConfig configures the shard health monitor.
type ShardHealthConfig struct {
	// Shards is the ordered shard chain.
	Shards []verifier.ShardInfo

	// NetworkID binds shard-chain link verification to a specific
	// network/fork — cross-network shard-chain replay is rejected
	// at the link-validation step.
	NetworkID cosign.NetworkID

	// FreezeThreshold is the entry count at which a shard should be frozen
	// and a new shard started.
	FreezeThreshold uint64

	// WarnAtFraction triggers a Warning when current shard size >= threshold * fraction.
	// Typical: 0.8 (warn at 80% full).
	WarnAtFraction float64

	// LogDID identifies the log being monitored (for alert details).
	LogDID string
}

// CheckShardHealth verifies the chain and evaluates size thresholds.
func CheckShardHealth(cfg ShardHealthConfig, now time.Time) ([]monitoring.Alert, error) {
	var alerts []monitoring.Alert

	if len(cfg.Shards) == 0 {
		return alerts, nil
	}

	// Chain verification via SDK.
	result, err := verifier.VerifyShardChain(cfg.Shards, cfg.NetworkID)
	if err != nil || result == nil || !result.Valid {
		brokenAt := -1
		if result != nil {
			brokenAt = result.BrokenAt
		}
		alerts = append(alerts, monitoring.Alert{
			Monitor:     MonitorShardHealth,
			Severity:    monitoring.Critical,
			Destination: monitoring.Both,
			Message:     fmt.Sprintf("shard chain broken at index %d", brokenAt),
			Details: map[string]any{
				"log_did":   cfg.LogDID,
				"chain_len": len(cfg.Shards),
				"broken_at": brokenAt,
				"error":     errorString(err),
			},
			EmittedAt: now,
		})
	}

	// Size threshold checks — only the latest shard can grow.
	if cfg.FreezeThreshold > 0 {
		latest := cfg.Shards[len(cfg.Shards)-1]
		warnFraction := cfg.WarnAtFraction
		if warnFraction <= 0 {
			warnFraction = 0.8
		}
		warnThreshold := uint64(float64(cfg.FreezeThreshold) * warnFraction)

		if latest.FinalSize >= cfg.FreezeThreshold {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorShardHealth,
				Severity:    monitoring.Critical,
				Destination: monitoring.Both,
				Message: fmt.Sprintf(
					"shard %s at %d entries, exceeds freeze threshold %d",
					latest.ShardID, latest.FinalSize, cfg.FreezeThreshold,
				),
				Details: map[string]any{
					"log_did":   cfg.LogDID,
					"shard_id":  latest.ShardID,
					"size":      latest.FinalSize,
					"threshold": cfg.FreezeThreshold,
					"action":    "freeze_and_shard",
				},
				EmittedAt: now,
			})
		} else if latest.FinalSize >= warnThreshold {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorShardHealth,
				Severity:    monitoring.Warning,
				Destination: monitoring.Ops,
				Message: fmt.Sprintf(
					"shard %s approaching freeze: %d of %d entries (%.0f%%)",
					latest.ShardID, latest.FinalSize, cfg.FreezeThreshold,
					float64(latest.FinalSize)/float64(cfg.FreezeThreshold)*100,
				),
				Details: map[string]any{
					"log_did":   cfg.LogDID,
					"shard_id":  latest.ShardID,
					"size":      latest.FinalSize,
					"threshold": cfg.FreezeThreshold,
				},
				EmittedAt: now,
			})
		}
	}

	return alerts, nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
