/*
FILE PATH: libs/monitoring/auditor_scope_observability.go

B2 — OTel Int64Counter for auditor-scope gate rejections (issue #21).

# WHAT THIS PROVIDES

The reconciler's authorizedForKind logs every rejection at slog.Warn,
but at fleet scale (15 networks × 1K+ TPS) slog alone is
operations-blind under load: no PromQL bisect, no alertable signal, no
cross-network rate comparison. This file adds the parallel OTel counter.

# DESIGN

  - Counter name: baseproof.auditor_scope.reject (OTel-native; Prometheus
    exporter appends "_total").
  - Labels: reason (one of scopeRejectReason* below), kind (the SDK
    gossip Kind string). Both bounded-cardinality — kind is a closed
    SDK enum, reason is a closed set defined in this file. Safe for
    Prometheus.
  - Lazy initialization: the global OTel meter is consulted on FIRST
    call only, then cached. The reconciler never has to thread a
    MetricsRegistry through its constructor.
  - Failure mode: if the OTel SDK is not configured (test environments,
    operator forgot to wire metrics), the global meter returns a no-op
    counter — Add() is a noop, no panic, no error. Production
    deployments wire the meter via httpmw/observability or equivalent.

# WHY NOT A REGISTERED INSTRUMENT VIA MetricsRegistry

The existing libs/httpmw/observability/MetricsRegistry pattern requires
threading the registry through constructors. The reconciler is
constructed in libs/gossipingest/pipeline.go via Config; adding
ObservabilityRegistry there would ripple to every caller of
gossipingest.Build, every test, every cmd/.../main.go. The lazy-global
pattern keeps the reject-counting concern local to this package while
still emitting on the same OTel pipeline.

When a future patch refactors monitoring to take a MetricsRegistry
constructor argument, this file's recordAuditorScopeReject body
becomes a thin wrapper over the registry's instrument — no caller
changes.
*/
package monitoring

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Scope rejection reason labels. Closed set; new reasons are added by
// the gate site in gossip_reconciler.go::authorizedForKind. Each
// constant is the label VALUE; the label KEY is "reason".
const (
	scopeRejectReasonNotRegistered = "not_registered"
	scopeRejectReasonRetired       = "retired"
	scopeRejectReasonNoRegistry    = "no_registry"
	scopeRejectReasonScopeMismatch = "scope_mismatch"
	scopeRejectReasonUnsorted      = "unsorted"
)

var (
	auditorScopeRejectOnce    sync.Once
	auditorScopeRejectCounter metric.Int64Counter
)

// recordAuditorScopeReject emits one count on the
// baseproof.auditor_scope.reject counter with the supplied reason + kind
// labels. Lazily initializes the counter on first call; subsequent
// calls are a single Int64Counter.Add. Safe for concurrent use.
//
// Operators alert on:
//
//	sum(rate(baseproof_auditor_scope_reject_total[5m])) by (reason, kind)
//
// A spike in reason="unsorted" surfaces an operator-config bug at one
// network; reason="not_registered" or "scope_mismatch" surfacing on a
// previously-quiet network surfaces an inbound attack attempt or a
// drift between the auditor registry and the network's published
// auditors.
func recordAuditorScopeReject(ctx context.Context, reason, kind string) {
	auditorScopeRejectOnce.Do(func() {
		meter := otel.GetMeterProvider().Meter(
			"github.com/baseproof/tooling/libs/monitoring",
		)
		counter, err := meter.Int64Counter(
			"baseproof.auditor_scope.reject",
			metric.WithDescription(
				"Auditor-scope gate rejections, labeled by reason and gossip Kind."),
			metric.WithUnit("1"),
		)
		if err != nil {
			// Instrument creation failed — fall back to a no-op so the
			// reconciler hot path never panics. The OTel SDK only
			// fails on missing required args; we supply all, so this
			// arm is defensive.
			return
		}
		auditorScopeRejectCounter = counter
	})
	if auditorScopeRejectCounter == nil {
		return
	}
	auditorScopeRejectCounter.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("reason", reason),
			attribute.String("kind", kind),
		),
	)
}
