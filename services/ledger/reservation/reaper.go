/*
FILE PATH:

	reservation/reaper.go

DESCRIPTION:

	Reaper — a background goroutine that periodically runs Manager.Reap, moving
	expired pending/uploaded reservations to EXPIRED and GC'ing their staged
	bytes. This closes the store-as-free-storage abuse vector: bytes uploaded
	against a reservation that never reaches a validated FINISH are reclaimed.
*/
package reservation

import (
	"context"
	"log/slog"
	"time"
)

// Reaper runs Manager.Reap on an interval until its context is cancelled.
type Reaper struct {
	mgr      *Manager
	interval time.Duration
	batch    int
	logger   *slog.Logger
}

// NewReaper builds a Reaper. interval defaults to 1m, batch to 256.
func NewReaper(mgr *Manager, interval time.Duration, batch int, logger *slog.Logger) *Reaper {
	if interval <= 0 {
		interval = time.Minute
	}
	if batch <= 0 {
		batch = 256
	}
	return &Reaper{mgr: mgr, interval: interval, batch: batch, logger: logger}
}

// Run sweeps until ctx is cancelled. Intended to be launched in its own goroutine.
func (r *Reaper) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := r.mgr.Reap(ctx, r.batch)
			if err != nil {
				r.logger.Error("reservation reaper: sweep failed", "error", err)
				continue
			}
			if n > 0 {
				r.logger.Info("reservation reaper: expired reservations", "count", n)
			}
		}
	}
}
