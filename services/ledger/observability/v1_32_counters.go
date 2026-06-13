/*
FILE PATH: observability/v1_32_counters.go

v1.32.0 SDK adoption — Tier E observability. Two OTel Int64Counters
for operator visibility into the L1 / L2 / L5 backdoor closures:

	endpoint_source{source, surface}
	  - source:   "on_log_resolver" | "config_canary_fallback" | "none"
	  - surface:  "witness" (L1 head-sync snapshot) | "parent" (L5 anchor publish)
	  NOTE: PRE-11 Phase B made the on-log resolver the SOLE witness-endpoint
	  source, so surface="witness" now only ever emits source="on_log_resolver"
	  (the config dial-list is deleted; an unresolvable set fails loud rather
	  than falling back). source="config_canary_fallback" survives ONLY on the
	  parent (L5) surface, which still has a LEDGER_PARENT_ADMISSION_URL canary.

	auditor_scope_reject_total{reason, kind}
	  - reason:   "no_registry" | "registry_error" | "not_registered" |
	              "retired" | "scope_mismatch"
	  - kind:     the SDK gossip.Kind string of the rejected event

# WHY THIS PACKAGE

The L1 / L2 / L5 closures fall back to canary paths transparently
during the bootstrap window. Without instrumentation, operators
have no way to see WHICH publishes are still on the canary path
across the 15-network footprint — and therefore no way to track
the cutover from canary → on-log as the rollout progresses.

These counters answer the load-bearing rollout question:

	"How many of my publishes today went through the on-log
	 authoritative source vs the LEDGER_*_URL canary?"

When endpoint_source{surface="parent", source="config_canary_fallback"}
hits zero across a peer set, that peer set has completed the parent-side
(L5) cutover and the LEDGER_PARENT_ADMISSION_URL env var can be removed
from deployment manifests. (The witness-side LEDGER_WITNESS_ENDPOINTS
dial-list was deleted outright in PRE-11 Phase B — there is no witness
canary left to watch.)

Auditor-scope rejects are higher-priority signals: a
{reason="not_registered"} reject in production is either an
operator-config drift or an attempted unauthorized claim. Either
warrants an alert.

# GLOBAL METER PROVIDER

The counters bind to OTel's global MeterProvider via otel.Meter.
The L1 / L2 / L5 sites call into this package directly; threading
a meter parameter through every constructor would touch too many
files for marginal benefit. Binaries that don't wire an OTel
provider (test rigs, the offline CLI) silently get a no-op meter
— the package is safe to call from any context.
*/
package observability

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/baseproof/tooling/services/ledger/v1_32"

var (
	once            sync.Once
	endpointSource  metric.Int64Counter
	auditorScopeRej metric.Int64Counter
)

// ensureInit lazily builds the counters against the current
// global meter provider. Idempotent under sync.Once so the cost
// is one resolution per process even when L1/L2/L5 fire at every
// publish.
func ensureInit() {
	once.Do(func() {
		m := otel.Meter(meterName)
		c1, err := m.Int64Counter(
			"endpoint_source",
			metric.WithDescription("v1.32.0 — endpoint URL source selection per snapshot/publish."),
		)
		if err == nil {
			endpointSource = c1
		}
		c2, err := m.Int64Counter(
			"auditor_scope_reject_total",
			metric.WithDescription("v1.32.0 — inbound finding events rejected by AuditorScopeGate."),
		)
		if err == nil {
			auditorScopeRej = c2
		}
	})
}

// EndpointSource records one snapshot/publish through the
// v1.32.0 endpoint-resolution precedence. Callers:
//
//   - witnessclient/head_sync.go — once per HeadSync construction.
//     PRE-11 Phase B made the on-log resolver the SOLE source, so this
//     always records source="on_log_resolver", surface="witness" (an
//     unresolvable set fails construction rather than emitting a canary
//     label). surface="witness" never carries config_canary_fallback.
//   - anchor/resolved_submit.go — once per parent publish,
//     surface="parent". Per-publish (not per-snapshot) because the
//     parent path resolves fresh on every entry; this is the surface
//     that can still emit source="config_canary_fallback".
//
// Operators alert on
// endpoint_source{surface="parent", source="config_canary_fallback"}
// crossing zero — that is the parent-side rollout-complete signal.
func EndpointSource(source, surface string) {
	ensureInit()
	if endpointSource == nil {
		return
	}
	endpointSource.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("source", source),
			attribute.String("surface", surface),
		),
	)
}

// AuditorScopeReject records one rejection by the L2
// AuditorScopeGate. Callers: gossipnet/auditor_scope_gate.go on
// every fail-closed path (no registry, registry error, not
// registered, retired, scope mismatch).
//
// Operators alert on:
//   - reason="not_registered" — config drift or attempted
//     unauthorized claim.
//   - reason="registry_error" — walker outage; check the on-log
//     scan health.
//   - reason="scope_mismatch" — an auditor exceeded its
//     authorized capability set. High-signal: either a stale
//     deployment running on an out-of-date scope mask, or an
//     auditor genuinely trying to publish out of scope.
func AuditorScopeReject(reason, kind string) {
	ensureInit()
	if auditorScopeRej == nil {
		return
	}
	auditorScopeRej.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("reason", reason),
			attribute.String("kind", kind),
		),
	)
}

// ResetForTests wipes the lazy-init state. Tests that wire a
// MeterProvider after process start use this to force the
// counters to re-bind against the new provider. Production code
// MUST NOT call this — the once.Do contract is broken
// intentionally.
func ResetForTests() {
	once = sync.Once{}
	endpointSource = nil
	auditorScopeRej = nil
}
