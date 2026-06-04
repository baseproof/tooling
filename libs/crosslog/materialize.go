/*
FILE PATH: libs/crosslog/materialize.go

v1.32.0 SDK adoption — materialize the three new on-log network
entry kinds from a flat slice of pre-positioned envelope entries
into the *ByPosition record slices that
*discover.DefaultAuthoritativeResolver consumes.

# WHY THIS HELPER EXISTS

The SDK's v1.32.0 walkers (ResolveWitnessEndpointsAt,
ResolveWitnessLabelAt, ResolveAuditorAt) consume three sorted-
by-EffectivePos record slices:

  - network.WitnessEndpointDeclarationByPosition
  - network.WitnessIdentityLabelByPosition
  - network.AuditorRegistrationByPosition

A consumer (auditor, witness, CLI tool) that has scanned a log
holds a flat slice of envelope.Entry — each with a known
position. This helper does the kind-discriminated decode + sort
in one place so every consumer assembles the resolver's input
the same way.

# WARN-AND-CONTINUE ERROR MODEL

Mirrors the libs/aggregator/scanner.go:114-126 pattern: per-
entry decode failures log a structured warn and continue to
the next entry. A single malformed entry does NOT abort the
materialization — the surviving records are returned and the
resolver gets a partial-but-valid view.

Per-entry errors fall into two classes:
  - Kind mismatch — the entry's wire "kind" field doesn't match
    any of the three network kinds. This is the COMMON case (the
    entry is some other kind — admission policy amendment,
    rotation, finding, application payload). Silently skip; no
    log noise.
  - Validation failure — the entry's wire "kind" DID match a
    network kind but the SDK's Validate rejected the payload
    (malformed URL, empty PubKeyID, etc.). Log a warn so the
    operator who published the entry sees the rejection.

# SORT DISCIPLINE

The SDK's ResolveXxxAt walkers return ErrRecordsUnsorted when
their input is not sorted by EffectivePos ascending. Each
returned slice is sorted before return.

# DEFAULT CHECKPOINT

Records carry an optional Checkpoint [32]byte. Callers that
have the checkpoint pass it via EntryAtPosition.Checkpoint;
callers without (e.g., a fresh log scan that hasn't seen the
cosigned tree-head yet) pass the zero value and the SDK walker
treats Checkpoint as advisory metadata.
*/
package crosslog

import (
	"errors"
	"log/slog"
	"sort"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// Ladder 2 D3 (#21): MaterializeFromEntries now dispatches via
// DecodeNetworkEntry (the sum-type kind-probe path) instead of the
// previous try-each-decoder cascade. Eliminates C1 fragility: a future
// SDK that returns a JSON-level error from a Decode (instead of the
// kind-mismatch sentinel) used to exit the cascade early and
// mis-label entries; the kind-probe pattern dispatches to exactly one
// decoder per payload and surfaces its error verbatim.

// EntryAtPosition pairs a decoded envelope.Entry with its
// EffectivePos and optional Checkpoint. Callers (auditor's
// log scanner, witness's bootstrap walker, the CLI) construct
// this once per scanned entry.
//
// Checkpoint is optional — zero [32]byte means "no checkpoint
// recorded"; the SDK walkers treat it as advisory metadata
// (it's surfaced to consumers but not used for resolution).
type EntryAtPosition struct {
	Position   types.LogPosition
	Entry      *envelope.Entry
	Checkpoint [32]byte
}

// MaterializedNetwork is the tuple of v1.33.x *ByPosition record
// slices that *discover.DefaultAuthoritativeResolver consumes.
//
// All four slices are sorted by EffectivePos ascending — the SDK
// walkers' ErrRecordsUnsorted contract is satisfied at the boundary
// so the consumer can plug the slices straight into the resolver
// without re-sorting.
//
// v1.33.x: Amendments carries on-log AuditorScopeAmendmentV1 records
// (SDK Gap 2 — lightweight scope changes without re-issuing the full
// AuditorRegistration). The reconciler merges these with Auditors
// when resolving an auditor at a position. Nil-permitted: empty
// Amendments means "no amendments published yet", equivalent to
// v1.32.x registration-only behavior.
type MaterializedNetwork struct {
	Endpoints  network.WitnessEndpointDeclarationByPosition
	Labels     network.WitnessIdentityLabelByPosition
	Auditors   network.AuditorRegistrationByPosition
	Amendments network.AuditorScopeAmendmentByPosition
}

// MaterializeFromEntries decodes each entry into one of the three
// v1.32.0 network record types and returns the assembled
// MaterializedNetwork. Per-entry decode failures log a structured
// warn and continue (no abort). Kind-mismatched entries (the
// majority — admission policy amendments, gossip findings,
// application payloads) are silently skipped without log noise.
//
// logger receives:
//   - DEBUG level: every materialized record (one line per kind +
//     position), so operators tailing the auditor's boot output
//     can see what was materialized.
//   - WARN  level: per-entry validation failures, naming the
//     position and the SDK's structural error.
//
// Pass slog.Default() if you don't want explicit routing.
func MaterializeFromEntries(
	entries []EntryAtPosition,
	logger *slog.Logger,
) MaterializedNetwork {
	if logger == nil {
		logger = slog.Default()
	}

	var out MaterializedNetwork
	for _, e := range entries {
		if e.Entry == nil {
			continue
		}
		payload := e.Entry.DomainPayload
		if len(payload) == 0 {
			continue
		}
		decoded, err := DecodeNetworkEntry(payload)
		if err != nil {
			// Two paths here. ErrMalformedNetworkPayload means the wire
			// bytes didn't even parse as JSON — log and skip; this is
			// the SDK's "broken bytes survived envelope decode" case
			// (rare; surfaces a producer bug, not a consumer concern).
			// All other errors are SDK-validate failures for a matched
			// kind: log with the SDK's structural error text so the
			// operator who published the entry sees the rejection.
			if errors.Is(err, ErrMalformedNetworkPayload) {
				logger.Warn("crosslog/materialize: payload not JSON-parseable",
					"seq", e.Position.Sequence,
					"err", err,
				)
			} else {
				logger.Warn("crosslog/materialize: SDK validate rejected payload",
					"seq", e.Position.Sequence,
					"err", err,
				)
			}
			continue
		}
		if decoded == nil {
			// Entry was a different kind — silently skip.
			// (This is the COMMON case: admission policy amendments,
			// gossip findings, application payloads etc. all fall here.)
			continue
		}
		switch decoded.Kind {
		case network.WitnessEndpointDeclarationKindV1:
			out.Endpoints = append(out.Endpoints, network.WitnessEndpointDeclarationRecord{
				EffectivePos: e.Position,
				Payload:      *decoded.Endpoint,
				Checkpoint:   e.Checkpoint,
			})
			logger.Debug("crosslog/materialize: witness_endpoint_declaration",
				"seq", e.Position.Sequence,
				"pub_key_id_prefix", shortPubKeyID(decoded.Endpoint.PubKeyID),
			)
		case network.WitnessIdentityLabelKindV1:
			out.Labels = append(out.Labels, network.WitnessIdentityLabelRecord{
				EffectivePos: e.Position,
				Payload:      *decoded.Label,
				Checkpoint:   e.Checkpoint,
			})
			logger.Debug("crosslog/materialize: witness_identity_label",
				"seq", e.Position.Sequence,
				"label", decoded.Label.Label,
			)
		case network.AuditorRegistrationKindV1:
			out.Auditors = append(out.Auditors, network.AuditorRegistrationRecord{
				EffectivePos: e.Position,
				Payload:      *decoded.Auditor,
				Checkpoint:   e.Checkpoint,
			})
			logger.Debug("crosslog/materialize: auditor_registration",
				"seq", e.Position.Sequence,
				"auditor_did", decoded.Auditor.AuditorDID,
				"scope", decoded.Auditor.Scope.String(),
			)
		case network.AuditorScopeAmendmentKindV1:
			// v1.33.x Gap 2: amendments are sorted into Amendments and
			// merged at resolver-walker time with the Auditors stream
			// (SDK's ResolveAuditorAt 4-arg signature).
			out.Amendments = append(out.Amendments, network.AuditorScopeAmendmentRecord{
				EffectivePos: e.Position,
				Payload:      *decoded.Amendment,
				Checkpoint:   e.Checkpoint,
			})
			logger.Debug("crosslog/materialize: auditor_scope_amendment",
				"seq", e.Position.Sequence,
				"auditor_did", decoded.Amendment.AuditorDID,
				"new_scope", decoded.Amendment.NewScope.String(),
			)
		}
	}

	// Sort each slice by EffectivePos ascending so the SDK walkers'
	// ErrRecordsUnsorted contract is satisfied at the boundary.
	sort.Sort(out.Endpoints)
	sort.Sort(out.Labels)
	sort.Sort(out.Auditors)
	sort.Sort(out.Amendments)

	logger.Info("crosslog/materialize: complete",
		"endpoints", len(out.Endpoints),
		"labels", len(out.Labels),
		"auditors", len(out.Auditors),
		"amendments", len(out.Amendments),
	)
	return out
}

// shortPubKeyID renders the first 4 bytes of a 32-byte PubKeyID
// as 8 lowercase hex characters — concise enough for boot-time
// log lines without overwhelming the terminal.
func shortPubKeyID(id [32]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 0; i < 4; i++ {
		out[i*2] = hex[id[i]>>4]
		out[i*2+1] = hex[id[i]&0x0f]
	}
	return string(out)
}
