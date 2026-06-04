// Telemetry-instrument installation.
//
// FILE PATH:
//
//	cmd/ledger/boot/wire/instruments.go
//
// DESCRIPTION:
//
//	Installs the cross-package OTel histograms + counters on the
//	MeterProvider that alloc.allocateTelemetry already constructed.
//	Each install* helper is a no-op when the meter is nil so this
//	file is safe to call unconditionally.
//
//	Two phases of instrument install:
//
//	  - prebuilder: histograms + counters that depend only on the
//	    MeterProvider (api error counter, request duration, WAL
//	    submit duration, Tessera append, Postgres pool acquire,
//	    bytestore PUT, gossip witness/equivocation counters).
//	    Called from Wire BEFORE composeSequencer / composeShipper.
//
//	  - late-bound gauges: those that need the sequencer + shipper
//	    instances. Lives in wire.go's installLateBoundGauges.
package wire

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/deps"
	"github.com/baseproof/tooling/services/ledger/gossipnet"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/tessera"
	"github.com/baseproof/tooling/services/ledger/wal"
)

// installPrebuilderInstruments installs the OTel histograms / counters
// that exist independent of the sequencer + shipper instances. No-op
// when MeterProvider is nil.
func installPrebuilderInstruments(d *deps.AppDeps) {
	if d.MeterProvider == nil {
		return
	}
	mp := otel.GetMeterProvider()
	apiMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/api")
	if installed := api.InstallErrorCounter(apiMeter); installed {
		d.Logger.Info("metrics: api error counter installed",
			"metric", "baseproof_api_errors_total")
	}
	if installed := api.InstallRequestDurationHistogram(apiMeter); installed {
		d.Logger.Info("metrics: api request duration installed",
			"metric", "baseproof_api_request_duration_seconds")
	}

	walMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/wal")
	if installed := wal.InstallSubmitDurationHistogram(walMeter); installed {
		d.Logger.Info("metrics: wal submit duration installed",
			"metric", "baseproof_wal_submit_duration_seconds")
	}

	tesseraMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/tessera")
	if installed := tessera.InstallAppendDurationHistogram(tesseraMeter); installed {
		d.Logger.Info("metrics: tessera append duration installed",
			"metric", "baseproof_tessera_append_duration_seconds")
	}
	if installed := tessera.InstallCloseDrainResidualGauge(tesseraMeter); installed {
		// Sampled at EmbeddedAppender.Close exit. Persistent positive
		// values indicate upstream tessera.NewAppender's background
		// goroutines aren't draining within the configured budget —
		// see tessera/instruments.go for the operational rationale.
		d.Logger.Info("metrics: tessera close drain residual installed",
			"metric", "baseproof_tessera_close_drain_residual_goroutines")
	}

	storeMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/store")
	if installed := store.InstallPoolAcquireDurationHistogram(storeMeter); installed {
		d.Logger.Info("metrics: postgres pool acquire installed",
			"metric", "baseproof_postgres_pool_acquire_seconds")
	}
	// F1: only registers when the cache is wired (cfg.RecentEntryCacheSize > 0).
	// closer is stashed on AppDeps so teardown can unregister the OTel
	// callback — keeps tests isolated and avoids leaked callbacks under
	// hot-reload paths that might recycle the meter provider.
	closer, err := store.InstallRecentEntryCacheInstruments(storeMeter, d.RecentEntryCache)
	if err != nil {
		// Honest failure: log the underlying cause. The cache itself
		// still works without metrics — we don't crash.
		d.Logger.Warn("metrics: recent-entry cache observability NOT installed",
			"error", err)
	} else if closer != nil {
		d.RecentEntryCacheMetrics = closer
		d.AppendCloser(deps.NamedCloser{
			Name:    "recent-entry-cache-metrics",
			Timeout: 5 * time.Second,
			Close: func(_ context.Context) error {
				return closer.Close()
			},
		})
		d.Logger.Info("metrics: recent-entry cache observability installed",
			"metric", "baseproof_recent_entry_cache_{size,hits_total,misses_total,evictions_total}")
	}

	bsMeter := mp.Meter("github.com/baseproof/tooling/services/ledger/bytestore")
	if installed := bytestore.InstallPutDurationHistogram(bsMeter); installed {
		d.Logger.Info("metrics: bytestore put duration installed",
			"metric", "baseproof_bytestore_put_duration_seconds")
	}

	if d.GossipMeter != nil {
		if installed := gossipnet.InstallWitnessQuorumFailureCounter(d.GossipMeter); installed {
			d.Logger.Info("metrics: witness quorum failures installed",
				"metric", "baseproof_witness_quorum_failures_total")
		}
		if installed := gossipnet.InstallEquivocationDetectedCounter(d.GossipMeter); installed {
			d.Logger.Info("metrics: equivocation detected installed",
				"metric", "baseproof_equivocation_detected_total")
		}
	}
}
