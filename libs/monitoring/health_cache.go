// FILE PATH: libs/monitoring/health_cache.go
//
// DESCRIPTION:
//
//	The O(1)-readable health record the scheduler maintains for every
//	job. The scheduler computes health on a ticker and writes the latest
//	outcome here; HTTP readers and metric scrapers read the cache without
//	ever triggering a recompute. This is the "melt-proof / edge-optimized"
//	contract: an external poller can hammer the health surface for free,
//	because the expensive math already ran on the schedule, not on the
//	request.
package monitoring

import (
	"sync"
	"time"
)

// Result is a scheduled job's most recent outcome.
type Result struct {
	Job              string         `json:"job"`
	LastRun          time.Time      `json:"last_run"`
	Duration         time.Duration  `json:"duration_ns"`
	OK               bool           `json:"ok"`
	Err              string         `json:"error,omitempty"`
	AlertsBySeverity map[string]int `json:"alerts_by_severity,omitempty"`
}

// HealthCache holds the latest Result per job name. Safe for concurrent
// use; every read is an O(1) snapshot.
type HealthCache struct {
	mu      sync.RWMutex
	results map[string]Result
}

// NewHealthCache returns an empty cache.
func NewHealthCache() *HealthCache {
	return &HealthCache{results: make(map[string]Result)}
}

func (c *HealthCache) put(r Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results[r.Job] = r
}

// Get returns the latest result for one job.
func (c *HealthCache) Get(job string) (Result, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.results[job]
	return r, ok
}

// Snapshot returns a copy of every job's latest result — safe to
// serialize without holding the lock.
func (c *HealthCache) Snapshot() map[string]Result {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]Result, len(c.results))
	for k, v := range c.results {
		out[k] = v
	}
	return out
}
