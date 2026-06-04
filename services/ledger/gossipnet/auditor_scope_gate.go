/*
FILE PATH: gossipnet/auditor_scope_gate.go

Auditor-scope authorization gate on inbound gossip findings —
v1.32.0 SDK adoption (closes Layer 5 backdoor L2 in the SDK
adoption plan).

# THE BACKDOOR THIS CLOSES

Pre-v1.32.0 the ledger's gossip Handler chain accepted any
properly-signed event from any DID. There was NO check that the
signing DID was an authorized auditor for the event's Kind. A
peer holding witness cosignatures (or any did:key keypair) could
publish a `KindEquivocationFinding` against an arbitrary log and
the ledger would persist it — making the ledger a megaphone for
attacker-fabricated audit claims.

The SDK ships `network.AuditorRegistration.AuthorizedForClaim(kind)`
(network/auditor_registration.go) precisely as the wire for this
gate. This file consumes it.

# v1.33.1: TWO AUTHORIZATION METHODS, ONE GATE

v1.33.1 split the single `AuthorizedFor(kind)` method into:

  - AuthorizedForClaim(kind) — for OBSERVATION-class findings
    (KindEquivocationFinding, KindSMTReplayFinding,
    KindHistoryRewriteFinding). The auditor registry is the trust
    gate because the publisher is asserting something the
    consumer cannot independently re-derive.
  - AuthorizedForProof(kind) — for CRYPTOGRAPHICALLY-PROVEN kinds
    (KindCrossLogInclusion, KindWitnessRotation). The embedded
    proof IS the authority; layered auditor-scope gating is
    optional and inappropriate for our deployment posture.

This gate calls ONLY `AuthorizedForClaim` because the early-exit
`if !isFindingKind(ev.Kind)` at the top of Append routes every
non-claim Kind to passthrough — proof-class events never reach
the authorization branch. Calling `AuthorizedForProof` here
would be dead code at best and a confused-authority bug at
worst (silently rejecting legitimate witness-self-published
rotations).

# WHERE IT INTERPOSES

`AuditorScopeGate` wraps `sdkgossip.Store` and decorates
`Append`. The wrap is placed in `gossipnet.Build` between the
underlying `cfg.Store` and the `sdkgossip.NewHandler`'s
`HandlerConfig.Store`. Every event flowing through the POST
/v1/gossip handler (and any other ingest path that goes through
the wrapped Store) is gated before persistence.

The decoration is FAIL-CLOSED for events whose Kind is a
finding-class Kind: an unregistered originator → reject; a
registered originator whose Scope mask doesn't cover the event
Kind → reject. Non-finding-class Kinds (cosigned tree heads,
witness rotations, originator rotations) pass through unmodified
— the auditor-registration concept does not apply to them.

# REFRESH MODEL

The gate consults a `network.AuditorRegistrationByPosition`
slice via the injected RegistrySource closure. The closure is
called once per Append (cheap — the underlying QueryAPI fetch
is TTL-cached at the wire layer, mirroring
admission/onlog_signature_policy.go). asOf is the latest
committed log position from the closure's perspective — auditor
registrations effective AT or BEFORE the current cosigned head
are honored.

# OBSERVABILITY

Every reject emits an slog.Warn under
`gossipnet.auditor_scope.reject` with structured forensic
context (originator, kind, scope, reason). Persisted accepts
emit slog.Debug under `gossipnet.auditor_scope.accept`. An
operator grepping for the reject events sees an exhaustive
trail of every unauthorized auditor attempt.

# TIER E COUNTERS

Each fail-closed path increments
observability.AuditorScopeReject(reason, kind) — an OTel
Int64Counter bound to the global meter. Operators alert on
{reason="not_registered"} (config drift or unauthorized claim)
and {reason="scope_mismatch"} (out-of-scope publish).
*/
package gossipnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/observability"
)

// AuditorRegistrySource returns the on-log
// AuditorRegistrationV1 records the gate dispatches against.
// Typically wired in cmd/ledger/boot/wire from a QueryAPI scan
// behind a short-TTL cache (mirrors
// admission.SignaturePolicyAmendmentSource shape).
//
// A nil or empty slice MEANS NO AUDITORS ARE REGISTERED — the
// gate then rejects every finding-class event regardless of
// signature validity, which is the high-assurance default. To
// onboard an auditor, the network must publish an
// AuditorRegistrationV1 entry on-log (admitted via the existing
// SignaturePolicy + AttestationPolicy machinery — no new gate
// code) and re-scan.
type AuditorRegistrySource func(ctx context.Context) ([]network.AuditorRegistrationRecord, error)

// AuditorAmendmentSource returns the on-log
// AuditorScopeAmendmentV1 records the gate merges with the
// registration stream when resolving an auditor at a position.
// v1.33.0 (Gap 2): networks publish lightweight Scope changes
// without re-issuing a full AuditorRegistration; the SDK's
// network.ResolveAuditorAt walks both streams to produce the
// effective record. Nil source is permitted — equivalent to "no
// amendments published yet."
type AuditorAmendmentSource func(ctx context.Context) ([]network.AuditorScopeAmendmentRecord, error)

// AsOfProvider returns the log position the gate uses for the
// auditor-registration walker's asOf. Typically the latest
// cosigned tree head's position. Nil ⇒ the gate uses a zero
// LogPosition (treats every record as in-effect — appropriate
// only when records are pre-filtered).
type AsOfProvider interface {
	LatestPosition(ctx context.Context) (types.LogPosition, error)
}

// AuditorScopeGate is a sdkgossip.Store decorator that gates
// finding-class Append calls on AuditorRegistration.AuthorizedForClaim
// (v1.33.1 — was AuthorizedFor pre-split). Proof-class kinds
// (KindCrossLogInclusion, KindWitnessRotation) are intentionally NOT
// gated here — their authority lives in the embedded cryptographic
// proof, not the auditor registry. The isFindingKind helper restricts
// the authorization branch to the three claim-class kinds.
// All non-Append methods delegate through the embedded Store so
// read paths (Iterate, Get, Head, Stats, IterSince, LatestSTH,
// Close) are unaffected by the gate.
type AuditorScopeGate struct {
	sdkgossip.Store // embedded for transparent passthrough of read methods

	registry   AuditorRegistrySource
	amendments AuditorAmendmentSource
	asOf       AsOfProvider
	logger     *slog.Logger

	// compromiseSeen tracks auditor DIDs that have self-broadcast
	// a KindAuditorCompromise event. Key: auditor DID. Value: the
	// CompromisedAtSeq from the broadcast. Once recorded, future
	// finding-class events from that DID at or after the
	// CompromisedAtSeq are rejected (Gap 3 fast-path).
	//
	// Protected by compromiseMu so concurrent gossip ingest
	// serializes the read/write of the compromise set.
	compromiseMu   sync.RWMutex
	compromiseSeen map[string]uint64
}

// AuditorScopeGateConfig configures NewAuditorScopeGate.
type AuditorScopeGateConfig struct {
	// Underlying is the wrapped store. Required.
	Underlying sdkgossip.Store
	// Registry returns the AuditorRegistrationV1 records. Required.
	// Nil makes the gate fail-closed for every finding event.
	Registry AuditorRegistrySource
	// Amendments returns the AuditorScopeAmendmentV1 records (v1.33.0
	// Gap 2). Optional — nil is "no amendments published yet."
	Amendments AuditorAmendmentSource
	// AsOf returns the log position for the walker. Optional — nil
	// means "use the latest at-rest registration" (zero asOf treats
	// all in-slice records as in-effect).
	AsOf AsOfProvider
	// Logger receives the per-event accept/reject diagnostics.
	// Nil ⇒ slog.Default().
	Logger *slog.Logger
}

// NewAuditorScopeGate constructs the gate. Returns an error
// when Underlying is nil; nil Registry is permitted (and
// fail-closed by design).
func NewAuditorScopeGate(cfg AuditorScopeGateConfig) (*AuditorScopeGate, error) {
	if cfg.Underlying == nil {
		return nil, fmt.Errorf("gossipnet/auditor_scope_gate: Underlying store required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &AuditorScopeGate{
		Store:          cfg.Underlying,
		registry:       cfg.Registry,
		amendments:     cfg.Amendments,
		asOf:           cfg.AsOf,
		logger:         cfg.Logger,
		compromiseSeen: map[string]uint64{},
	}, nil
}

// Append implements sdkgossip.Store. Finding-class events
// (sdkgossip.IsFindingKind) MUST resolve to a registered auditor
// AND pass AuditorRegistration.AuthorizedForClaim(ev.Kind); non-
// finding events pass through unmodified.
func (g *AuditorScopeGate) Append(ctx context.Context, ev sdkgossip.SignedEvent) error {
	// v1.33.0 (Gap 3): a KindAuditorCompromise event is the canonical
	// self-broadcast cutoff. It is NOT a claim-class finding (so it
	// bypasses the AuthorizedForClaim gate) but the gate still has to
	// record the (DID, CompromisedAtSeq) tuple so future findings from
	// the same DID at asOf >= CompromisedAtSeq are rejected by the
	// compromise check below. This branch MUST sit ABOVE the
	// isFindingKind early-exit — otherwise compromise events
	// short-circuit to passthrough and recordCompromise is never
	// reached (the load-bearing reason this case is hoisted).
	if ev.Kind == sdkgossip.KindAuditorCompromise {
		if err := g.recordCompromise(ev); err != nil {
			// Record-failure is non-fatal: the event is still
			// persisted because the underlying gossip Store is the
			// authoritative log of broadcasts, and a decode hiccup
			// at the gate layer should not drop a security-critical
			// event. The operator sees the warning and can inspect
			// the gossip store directly to back-fill the cutoff.
			g.logger.Warn("gossipnet.auditor_scope.compromise_record_failed",
				"originator", ev.Originator,
				"error", err.Error(),
			)
		}
		return g.Store.Append(ctx, ev)
	}

	if !isFindingKind(ev.Kind) {
		return g.Store.Append(ctx, ev)
	}

	// Fail-closed without a registry source — by design.
	if g.registry == nil {
		g.logger.Warn("gossipnet.auditor_scope.reject",
			"originator", ev.Originator,
			"kind", string(ev.Kind),
			"reason", "no AuditorRegistrySource wired",
		)
		observability.AuditorScopeReject("no_registry", string(ev.Kind))
		return fmt.Errorf("gossipnet/auditor_scope_gate: no AuditorRegistrySource wired (fail-closed)")
	}
	records, err := g.registry(ctx)
	if err != nil {
		g.logger.Warn("gossipnet.auditor_scope.reject",
			"originator", ev.Originator,
			"kind", string(ev.Kind),
			"reason", "AuditorRegistrySource error",
			"error", err.Error(),
		)
		observability.AuditorScopeReject("registry_error", string(ev.Kind))
		return fmt.Errorf("gossipnet/auditor_scope_gate: registry source failed: %w", err)
	}

	// v1.33.0 (Gap 2): fetch amendments alongside registrations.
	// Nil source is permitted — equivalent to "no amendments yet."
	var amendments []network.AuditorScopeAmendmentRecord
	if g.amendments != nil {
		amendments, err = g.amendments(ctx)
		if err != nil {
			g.logger.Warn("gossipnet.auditor_scope.reject",
				"originator", ev.Originator,
				"kind", string(ev.Kind),
				"reason", "AuditorAmendmentSource error",
				"error", err.Error(),
			)
			observability.AuditorScopeReject("amendment_error", string(ev.Kind))
			return fmt.Errorf("gossipnet/auditor_scope_gate: amendment source failed: %w", err)
		}
	}

	asOf := types.LogPosition{}
	if g.asOf != nil {
		pos, perr := g.asOf.LatestPosition(ctx)
		if perr == nil {
			asOf = pos
		}
	}

	// v1.33.0 (Gap 3): reject finding events from an auditor whose
	// key was self-broadcast as compromised at or before asOf.
	// KindAuditorCompromise itself can never reach here — it is
	// handled at the top of Append and returns before the
	// finding-class path.
	if compromiseSeq, compromised := g.compromiseAt(ev.Originator); compromised {
		if asOf.Sequence >= compromiseSeq {
			g.logger.Warn("gossipnet.auditor_scope.reject",
				"originator", ev.Originator,
				"kind", string(ev.Kind),
				"as_of_seq", asOf.Sequence,
				"compromised_at_seq", compromiseSeq,
				"reason", "auditor key compromised at or before this position",
			)
			observability.AuditorScopeReject("auditor_compromised", string(ev.Kind))
			return fmt.Errorf(
				"gossipnet/auditor_scope_gate: auditor %q compromised at seq=%d (asOf=%d)",
				ev.Originator, compromiseSeq, asOf.Sequence)
		}
	}

	reg, err := network.ResolveAuditorAt(records, amendments, ev.Originator, asOf)
	if err != nil {
		reason := "originator not registered as auditor"
		counterReason := "not_registered"
		switch {
		case errors.Is(err, network.ErrAuditorRetired):
			reason = "auditor retired at this log position"
			counterReason = "retired"
		case errors.Is(err, network.ErrAuditorRecordsEmpty):
			reason = "no auditors registered on this log"
			counterReason = "no_registry"
		}
		g.logger.Warn("gossipnet.auditor_scope.reject",
			"originator", ev.Originator,
			"kind", string(ev.Kind),
			"as_of_seq", asOf.Sequence,
			"reason", reason,
		)
		observability.AuditorScopeReject(counterReason, string(ev.Kind))
		return fmt.Errorf("gossipnet/auditor_scope_gate: %s: %w", reason, err)
	}
	if !reg.AuthorizedForClaim(ev.Kind) {
		g.logger.Warn("gossipnet.auditor_scope.reject",
			"originator", ev.Originator,
			"kind", string(ev.Kind),
			"scope", reg.Scope.String(),
			"as_of_seq", asOf.Sequence,
			"reason", "registered but scope does not cover event Kind",
		)
		observability.AuditorScopeReject("scope_mismatch", string(ev.Kind))
		return fmt.Errorf("gossipnet/auditor_scope_gate: originator %q scope=%s rejects kind=%s",
			ev.Originator, reg.Scope.String(), ev.Kind)
	}

	g.logger.Debug("gossipnet.auditor_scope.accept",
		"originator", ev.Originator,
		"kind", string(ev.Kind),
		"scope", reg.Scope.String(),
	)
	return g.Store.Append(ctx, ev)
}

// recordCompromise decodes a KindAuditorCompromise envelope body
// and inserts (AuditorDID → CompromisedAtSeq) into the compromise
// set. Idempotent on repeat broadcast: keeps the lowest seq seen so
// the strictest cutoff wins (the first compromise broadcast is the
// trusted one; any later broadcast under the same — now compromised
// — key is not authoritative for raising the cutoff).
func (g *AuditorScopeGate) recordCompromise(ev sdkgossip.SignedEvent) error {
	body, err := sdkgossip.DecodeWireBody(sdkgossip.KindAuditorCompromise, ev.Body)
	if err != nil {
		return fmt.Errorf("decode AuditorCompromise body: %w", err)
	}
	wire, ok := body.(sdkgossip.WireAuditorCompromiseBody)
	if !ok {
		return fmt.Errorf("unexpected wire-body type %T for KindAuditorCompromise", body)
	}
	parsed, err := findings.AuditorCompromiseFromWire(wire)
	if err != nil {
		return fmt.Errorf("promote AuditorCompromise: %w", err)
	}
	g.compromiseMu.Lock()
	defer g.compromiseMu.Unlock()
	prev, seen := g.compromiseSeen[parsed.AuditorDID]
	if !seen || parsed.CompromisedAtSeq < prev {
		g.compromiseSeen[parsed.AuditorDID] = parsed.CompromisedAtSeq
		g.logger.Info("gossipnet.auditor_scope.compromise_recorded",
			"auditor_did", parsed.AuditorDID,
			"compromised_at_seq", parsed.CompromisedAtSeq,
		)
	}
	return nil
}

// compromiseAt reports whether did has been recorded as compromised
// and returns the lowest CompromisedAtSeq seen. The "lowest wins"
// rule reflects that the FIRST compromise broadcast is the trusted
// cutoff; any subsequent broadcast under the now-compromised key is
// not authoritative for raising the cutoff.
func (g *AuditorScopeGate) compromiseAt(did string) (uint64, bool) {
	g.compromiseMu.RLock()
	defer g.compromiseMu.RUnlock()
	seq, ok := g.compromiseSeen[did]
	return seq, ok
}

// Compile-time guard: *AuditorScopeGate decorates the same
// Append surface the SDK's gossip Store interface declares.
var _ sdkgossip.Store = (*AuditorScopeGate)(nil)

// isFindingKind reports whether the event kind is one of the
// auditor-published CLAIM-class findings the AuditorRegistration
// scope mask gates. Mirrors the SDK's claim-class kind set (the
// AuthorizedForClaim coverage at v1.33.1: KindEquivocationFinding,
// KindSMTReplayFinding, KindHistoryRewriteFinding). Proof-class
// kinds (KindCrossLogInclusion, KindWitnessRotation) carry their
// authority in the wire body's cryptographic proof and are
// intentionally NOT gated by the auditor registry — gating them
// here would reject legitimate witness-self-published rotations.
// Non-finding kinds (cosigned tree heads, originator rotations)
// have their own admission chains.
func isFindingKind(k sdkgossip.Kind) bool {
	switch k {
	case sdkgossip.KindEquivocationFinding,
		sdkgossip.KindSMTReplayFinding,
		sdkgossip.KindHistoryRewriteFinding:
		return true
	}
	return false
}
