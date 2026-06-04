/*
FILE PATH: store/recent_entry_cache_instruments.go

OTel observable instruments for the F1 RecentEntryCache.

	baseproof_recent_entry_cache_size            (Int64ObservableGauge,   "1")
	baseproof_recent_entry_cache_bytes_used      (Int64ObservableGauge,   "By")
	baseproof_recent_entry_cache_hits_total      (Int64ObservableCounter, "1")
	baseproof_recent_entry_cache_misses_total    (Int64ObservableCounter, "1")
	baseproof_recent_entry_cache_evictions_total (Int64ObservableCounter, "1")
	baseproof_recent_entry_cache_rejects_total   (Int64ObservableCounter, "1")
	baseproof_recent_entry_cache_log_did_drops_total (Int64ObservableCounter, "1")

All seven series are sampled at scrape time from cache.Stats() inside a
single RegisterCallback — one round-trip per scrape, no per-Get/Put
metric overhead. The five COUNTERS (hits / misses / evictions / rejects /
log_did_drops) are monotonic by construction. SIZE + BYTES_USED are
Gauges — they rise and fall with inserts and evictions, NOT monotonic.

Operators care about:
  - hits / (hits + misses) ≈ steady-state cache hit ratio. Should be
    > 0.99 once warm; a sustained dip below ~0.95 usually means the
    builder is lagging > cache capacity (the F2 soft-503 back-pressure
    addresses that at the source).
  - size: should hover near capacity in steady state. Persistent
    size = capacity AND a rising evictions rate together signal the
    builder isn't keeping up with the sequencer.
  - bytes_used / bytes_capacity: the load-bearing memory-pressure
    signal. At production scale with large-entry mixes this fires
    before size approaches MaxEntries. Pair with rejects_total to
    detect MaxBytes being undersized for the workload.
  - evictions per second: a non-zero rate is normal under load (the
    FIFO discards entries the builder has long since consumed); a
    rapidly-rising rate means the cache is churning faster than the
    builder is reading.
  - rejects_total: a non-zero rate means individual entries exceed
    MaxBytes and the cache refused them. Operator action: bump
    LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES or investigate why those
    entries are pathologically large.
  - log_did_drops_total: MUST stay zero in steady state. Non-zero
    means a programming error upstream — the caller is feeding the
    cache EntryWithMetadata for a different log. The cache silently
    drops these; the counter is the only signal.

LIFECYCLE & MULTI-CACHE:

	Install returns an io.Closer; Close unregisters the OTel callback so
	tests can isolate runs and hot-reload paths can recycle meters. No
	process-global "installed" flag — that would have blocked multi-log
	deployments (which the cache itself was designed to support per its
	docstring) AND tests that need a fresh install per case. Idempotency
	is the caller's contract: install once per (cache, meter) pair.
*/
package store

import (
	"context"
	"fmt"
	"io"

	"go.opentelemetry.io/otel/metric"
)

// recentEntryCacheRegistration owns the OTel callback handle so Close
// can unregister it. Returned from InstallRecentEntryCacheInstruments;
// callers store it on AppDeps and Close on teardown.
type recentEntryCacheRegistration struct {
	reg metric.Registration
}

// Close unregisters the OTel callback. Idempotent (the underlying
// metric.Registration.Unregister is). Safe to call once; subsequent
// calls are no-ops on most OTel SDKs but the SDK's contract is
// unspecified — Close once per Install.
func (r *recentEntryCacheRegistration) Close() error {
	if r == nil || r.reg == nil {
		return nil
	}
	err := r.reg.Unregister()
	r.reg = nil
	return err
}

// InstallRecentEntryCacheInstruments wires the four observable series
// from the supplied meter against the supplied cache. Returns:
//
//   - (nil, nil)  → meter is nil OR cache is nil (caching disabled);
//     the caller has nothing to install and nothing to close.
//   - (nil, err)  → instrument or callback creation failed; the caller
//     MUST log the error (observability dark-spot otherwise) and may
//     proceed without cache metrics — the cache itself still works.
//   - (Closer, nil) → success. The Closer unregisters the callback;
//     call it from teardown so tests can isolate runs.
//
// No process-global state. Multiple caches can be observed by the same
// process (each Install call gets its own registration handle). The
// caller owns idempotency — calling Install twice on the same
// (cache, meter) pair will fail at the SDK level on the second call
// (duplicate instrument name within the meter), and that error is
// surfaced honestly via the returned err.
func InstallRecentEntryCacheInstruments(meter metric.Meter, cache RecentEntryCache) (io.Closer, error) {
	if meter == nil || cache == nil {
		return nil, nil
	}

	size, err := meter.Int64ObservableGauge(
		"baseproof_recent_entry_cache_size",
		metric.WithDescription("Current entry count in the in-process recent-entry cache (F1 bytes hand-off between sequencer post-commit and builder fetch)."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: gauge size: %w", err)
	}
	bytesUsed, err := meter.Int64ObservableGauge(
		"baseproof_recent_entry_cache_bytes_used",
		metric.WithDescription("Cumulative bytes of CanonicalBytes across cached entries. Primary memory-pressure signal — pair with the configured MaxBytes to derive headroom."),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: gauge bytes_used: %w", err)
	}
	hits, err := meter.Int64ObservableCounter(
		"baseproof_recent_entry_cache_hits_total",
		metric.WithDescription("Total RecentEntryCache.Get hits. Pair with misses_total for hit ratio."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: counter hits: %w", err)
	}
	misses, err := meter.Int64ObservableCounter(
		"baseproof_recent_entry_cache_misses_total",
		metric.WithDescription("Total RecentEntryCache.Get misses. A non-zero rate is normal on cold starts and for historical reads; sustained > 0 in steady state means the builder is lagging beyond cache capacity."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: counter misses: %w", err)
	}
	evictions, err := meter.Int64ObservableCounter(
		"baseproof_recent_entry_cache_evictions_total",
		metric.WithDescription("FIFO evictions from the RecentEntryCache. Non-zero is normal under load; the rate should track sequencer commit rate once steady-state."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: counter evictions: %w", err)
	}
	rejects, err := meter.Int64ObservableCounter(
		"baseproof_recent_entry_cache_rejects_total",
		metric.WithDescription("Entries refused at Put because they alone exceed MaxBytes. Non-zero means MaxBytes is undersized for the workload — bump LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES or shrink entry size upstream."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: counter rejects: %w", err)
	}
	logDIDDrops, err := meter.Int64ObservableCounter(
		"baseproof_recent_entry_cache_log_did_drops_total",
		metric.WithDescription("Foreign-log EntryWithMetadata Puts refused by the cache's LogDID check. MUST stay zero in steady state — non-zero indicates a programming error upstream (the caller is feeding the cache entries from a different log)."),
		metric.WithUnit("1"),
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: counter log_did_drops: %w", err)
	}

	reg, err := meter.RegisterCallback(
		func(_ context.Context, obs metric.Observer) error {
			s := cache.Stats()
			obs.ObserveInt64(size, int64(s.Size))
			obs.ObserveInt64(bytesUsed, s.BytesUsed)
			obs.ObserveInt64(hits, int64(s.Hits))
			obs.ObserveInt64(misses, int64(s.Misses))
			obs.ObserveInt64(evictions, int64(s.Evictions))
			obs.ObserveInt64(rejects, int64(s.Rejects))
			obs.ObserveInt64(logDIDDrops, int64(s.LogDIDDrops))
			return nil
		},
		size,
		bytesUsed,
		hits,
		misses,
		evictions,
		rejects,
		logDIDDrops,
	)
	if err != nil {
		return nil, fmt.Errorf("recent-entry-cache: register callback: %w", err)
	}

	return &recentEntryCacheRegistration{reg: reg}, nil
}
