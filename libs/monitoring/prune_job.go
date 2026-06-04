package monitoring

import (
	"context"
	"log/slog"

	"github.com/baseproof/baseproof/monitoring"
)

// Pruner is the subset of a durable gossip store the retention job needs. An
// in-memory store does not implement it, so callers self-gate with a type
// assertion before registering the job.
type Pruner interface {
	Prune(ctx context.Context, retentionDays int) (int64, error)
}

// PruneJob is the universal retention job: it enforces a durable gossip store's
// retention TTL by deleting events older than retentionDays. It is domain-free —
// the external auditor and a network enforcer schedule the SAME job; only the
// configured retention differs. A custodian that must keep all evidence simply
// does not register it (retentionDays <= 0).
func PruneJob(p Pruner, retentionDays int, logger *slog.Logger) JobFunc {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context) ([]monitoring.Alert, error) {
		n, err := p.Prune(ctx, retentionDays)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			logger.Info("monitoring: pruned expired gossip events",
				"count", n, "retention_days", retentionDays)
		}
		return nil, nil
	}
}
