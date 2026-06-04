// FILE PATH: libs/monitoring/gossip_reconciler.go
//
// DESCRIPTION:
//
//	Reconciler is the sink end of the inbound gossip pipeline: it receives raw
//	SignedEvents from the topology PeerPuller, runs the zero-trust two-tier
//	verifier, and routes each VERIFIED, strongly-typed finding to its enforcer.
//	It is the "Smart Edge brain" — the active agent that turns cryptographically
//	proven peer events into Judicial Network state changes.
//
//	  CosignedTreeHead         → TrustedHeadStore (advance JN's verified view of
//	                             the peer log's head; flag forks/regressions)
//	  Equivocation             → EquivocationResponder (slash the offending log)
//	  EntryCommitmentEquiv.    → alert (entry-level double-spend evidence)
//	  others (escrow / rotation / ghost / cross-log inclusion) → verified +
//	                             logged; their enforcers attach here as they land
//
//	The verifier and slasher are referenced through minimal local interfaces, so
//	monitoring stays free of verification/ and equivocation/ imports — the
//	concrete types are wired at the composition root. Reconciler satisfies
//	topology.SignedEventSink structurally (HandleSignedEvent).
//
//	FAIL-CLOSED: an event that fails verification returns an error (the puller
//	logs + skips it) and NEVER reaches an enforcer.
//
// v1.32.0 ADOPTION — AUDITOR-SCOPE GATE (T3.2):
//
//	When ReconcilerConfig.AuditorRegistry is non-nil, every verified
//	event runs through AuditorRegistration.AuthorizedFor(kind) BEFORE
//	the kind switch. Originators that are not registered as auditors at
//	the configured asOf position, or whose Scope mask does not cover the
//	event Kind, are rejected silently (logged, but no error to the puller
//	— the puller would re-fetch on next poll and a stuck-bad event would
//	hammer the verifier).
//
//	This is the SYMMETRIC ingest gate to the ledger's
//	gossipnet/auditor_scope_gate.go: same L5 authorization check, same
//	fail-closed-when-wired posture. AuditorRegistry nil preserves the
//	pre-v1.32 behavior so existing deployments are unaffected until
//	operators explicitly opt in.
package monitoring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// FindingVerifier runs the two-tier (envelope + finding proof) check on a
// pulled event and returns the verified, typed finding.
// *verification.GossipVerifier satisfies it.
type FindingVerifier interface {
	Verify(ctx context.Context, ev gossip.SignedEvent) (gossip.Event, error)
}

// WitnessSetRotator installs a verified witness-set rotation into the live
// trust root, using the rotating log's standing (inherited) quorum.
// *verification.WitnessSetRegistry satisfies it. Optional in ReconcilerConfig;
// nil ⇒ verified rotations are logged but the trust root does not advance.
type WitnessSetRotator interface {
	ApplyVerifiedRotation(logDID string, rotation types.WitnessRotation) error
}

// RotationJournal durably records each verified witness-set rotation as a
// position-bearing types.WitnessRotationRecord (the historical rotation
// chain), so witness.WitnessSetAt can reconstruct the set that was
// authoritative at any historical asOf years later — the Year-15
// reproducibility primitive (ZT-SCN-02). *store.PostgresWitnessRotationJournal
// satisfies it. Optional in ReconcilerConfig; nil ⇒ rotations advance the live
// trust root but are not durably journaled, so historical reconstruction is
// unavailable (pre-AT-1 behavior).
type RotationJournal interface {
	RecordRotation(ctx context.Context, record types.WitnessRotationRecord) error
}

// Reconciler verifies pulled events and dispatches them to enforcers.
//
// # CONCURRENCY (Ladder 3 C3, #21)
//
// auditorRegistry and auditorAmendments are atomic.Pointer-typed so that
// readers on the per-event hot path (authorizedForKind, called at
// 1K+ TPS per network) take a single-word atomic load instead of a
// race-prone slice-header read or an RWMutex CAS.
//
//   - Read path: ptr := r.auditorRegistry.Load(); if ptr == nil { ... }
//     A nil pointer means "gate disabled" (the pre-v1.32 path).
//     A non-nil pointer is a pointer to a snapshot SLICE — the reader
//     dereferences for the duration of one ResolveAuditorAt call.
//
//   - Write path (future hot-reload): r.auditorRegistry.Store(&newSlice).
//     atomic.Pointer guarantees an entire-pointer-snapshot swap. Each
//     in-flight reader keeps its (old) pointer until it returns; GC
//     reclaims the old backing array once the last reader is done.
//
// Why atomic.Pointer beats the alternatives at 1K+ TPS:
//   - Plain field — slice headers are 3 words; without atomic load a
//     reader can observe a torn header (pointer from update N, length
//     from update N+1). Undefined behavior under Go's memory model.
//   - sync.RWMutex — RLock is a CAS on the reader counter; cache-line
//     bouncing across NUMA nodes under sustained throughput materially
//     bumps P99 latency. atomic.Pointer is a plain word load — zero
//     reader-side contention.
//   - Channel broadcast — way more complex; needed only when readers
//     also want change-notification (the reconciler doesn't).
type Reconciler struct {
	verifier          FindingVerifier
	heads             *TrustedHeadStore
	journal           HeadsJournal
	now               func() time.Time
	equiv             *EquivocationResponder
	rotator           WitnessSetRotator
	store             gossip.Store
	logger            *slog.Logger
	auditorRegistry   atomic.Pointer[network.AuditorRegistrationByPosition]
	auditorAmendments atomic.Pointer[network.AuditorScopeAmendmentByPosition]
	auditorScopeAsOf  func(ctx context.Context) types.LogPosition
	rotationJournal   RotationJournal
}

// ReconcilerConfig configures a Reconciler.
type ReconcilerConfig struct {
	// Verifier runs the zero-trust check. Required.
	Verifier FindingVerifier
	// Heads records verified cosigned tree heads. Required (also the merkle
	// trust anchor).
	Heads *TrustedHeadStore
	// Journal is the OPTIONAL durable archive. When non-nil, every verified
	// CosignedTreeHeadFinding is additionally Recorded into the journal —
	// the same head fans out to both the live in-memory anchor (Heads) AND
	// the historical-asOf store. Journal failures are logged but do NOT
	// block the live advance: live verification stays available even if the
	// archive is down. nil disables the fan-out (pre-v1.34 behavior).
	//
	// Wire-format preservation: the SignedEvent envelope's CanonicalBytes
	// are journaled verbatim (the bytes that fed the verifier — the only
	// stable cryptographic representation across a 15-year retention).
	Journal HeadsJournal
	// Now returns the wall clock the journal stamps each Record with
	// (Head.CommittedAt). Optional; nil falls back to time.Now().UTC().
	// Tests inject a fixed clock for deterministic ordering assertions.
	Now func() time.Time
	// Equivocation responds to verified equivocation findings. Optional; nil ⇒
	// equivocation findings are verified + logged but not slashed.
	Equivocation *EquivocationResponder
	// Rotator installs verified witness-set rotations into the live trust root.
	// Optional; nil ⇒ verified rotations are logged but not applied (the
	// witness set cannot advance at runtime).
	Rotator WitnessSetRotator
	// RotationJournal durably records each verified witness-set rotation as a
	// position-bearing types.WitnessRotationRecord (the historical rotation
	// chain), so witness.WitnessSetAt can reconstruct the set authoritative at
	// any asOf years later (ZT-SCN-02). Optional; nil ⇒ rotations advance the
	// live trust root but are not journaled (no historical reconstruction).
	RotationJournal RotationJournal
	// Store durably persists every VERIFIED inbound event (D7) so the JN's
	// worldview survives a restart. Optional; nil ⇒ events are enforced but
	// not persisted (ephemeral, pre-durability behaviour).
	Store gossip.Store
	// Logger; nil ⇒ slog.Default().
	Logger *slog.Logger

	// AuditorRegistry is the v1.32.0 on-log AuditorRegistrationV1 record
	// slice the scope gate dispatches against. When non-nil, every verified
	// event is checked against network.ResolveAuditorAt + AuditorRegistration.
	// AuthorizedFor(Kind) BEFORE the kind switch — originators not registered
	// at AuditorScopeAsOf, or whose Scope mask does not cover the event Kind,
	// are silently rejected (logged with structured forensic context).
	//
	// nil PRESERVES the pre-v1.32 behavior (verified events flow through the
	// kind switch unmodified). The audit's D7 backward-compat env var
	// (AUDITOR_ENFORCE_SCOPES) toggles whether the auditor's main wires this
	// field or leaves it nil.
	//
	// Typically populated via crosslog.BuildAuditorRegistryFromConfig (config-
	// driven) or crosslog.MaterializeFromEntries (on-log-driven). The records
	// MUST be sorted by EffectivePos ascending. BuildAuditorRegistryFromConfig
	// sorts before returning; MaterializeFromEntries sorts before returning.
	// If a hand-assembled slice is supplied unsorted, the gate logs reason
	// "registry unsorted (operator config bug)" and rejects every event.
	AuditorRegistry network.AuditorRegistrationByPosition

	// AuditorAmendments is the v1.33.0+ on-log AuditorScopeAmendmentV1 record
	// slice the scope gate merges with the registration stream when resolving
	// an auditor at a position (SDK Gap 2). Optional — nil means "no
	// amendments published yet", equivalent to v1.32.0 registration-only
	// behavior. The records MUST be sorted by EffectivePos ascending; same
	// reject-with-explicit-reason semantics as AuditorRegistry.
	AuditorAmendments network.AuditorScopeAmendmentByPosition

	// AuditorScopeAsOf returns the LogPosition the scope gate's
	// network.ResolveAuditorAt walker uses for its asOf. Optional — nil
	// means "use the zero LogPosition" (every record is treated as
	// in-effect; appropriate when AuditorRegistry was assembled from a
	// fully-walked snapshot).
	//
	// Production deployments wire this to the latest cosigned tree head's
	// position so auditor registrations effective AT or BEFORE the current
	// head are honored while still-pending future registrations are not.
	AuditorScopeAsOf func(ctx context.Context) types.LogPosition
}

// NewReconciler validates config and returns a Reconciler.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("monitoring/gossip_reconciler: nil Verifier")
	}
	if cfg.Heads == nil {
		return nil, errors.New("monitoring/gossip_reconciler: nil Heads")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	r := &Reconciler{
		verifier:         cfg.Verifier,
		heads:            cfg.Heads,
		journal:          cfg.Journal,
		now:              now,
		equiv:            cfg.Equivocation,
		rotator:          cfg.Rotator,
		rotationJournal:  cfg.RotationJournal,
		store:            cfg.Store,
		logger:           logger,
		auditorScopeAsOf: cfg.AuditorScopeAsOf,
	}
	// Ladder 3 C3 (#21): seed the atomic.Pointer fields. nil-config
	// means "gate disabled" — Store(nil) is the explicit way to keep
	// the field's zero value of *T == nil so Load() returns nil and
	// authorizedForKind takes the pre-v1.32 pass-through path.
	if cfg.AuditorRegistry != nil {
		r.auditorRegistry.Store(&cfg.AuditorRegistry)
	}
	if cfg.AuditorAmendments != nil {
		r.auditorAmendments.Store(&cfg.AuditorAmendments)
	}
	return r, nil
}

// RefreshRegistry atomically swaps the auditor-registration snapshot the
// scope gate dispatches against. Safe for concurrent invocation while
// authorizedForKind is reading on N other goroutines — atomic.Pointer
// guarantees each reader sees a consistent slice header throughout its
// ResolveAuditorAt call, and the old backing array stays alive for any
// in-flight readers that loaded the previous pointer.
//
// nil disables the gate (Load returns nil → authorizedForKind takes the
// pre-v1.32 pass-through path); non-nil enables it with the new snapshot.
//
// Operators wire this to an on-log walker (or to a config-reload SIGHUP)
// so a network's registry update propagates to the running auditor
// without a restart.
func (r *Reconciler) RefreshRegistry(records network.AuditorRegistrationByPosition) {
	if records == nil {
		r.auditorRegistry.Store(nil)
		return
	}
	r.auditorRegistry.Store(&records)
}

// RefreshAmendments atomically swaps the auditor-scope-amendment
// snapshot. Same atomic-pointer semantics as RefreshRegistry.
func (r *Reconciler) RefreshAmendments(records network.AuditorScopeAmendmentByPosition) {
	if records == nil {
		r.auditorAmendments.Store(nil)
		return
	}
	r.auditorAmendments.Store(&records)
}

// HandleSignedEvent verifies one pulled event and acts on it. Satisfies
// topology.SignedEventSink. A verification failure returns an error so the
// puller records the rejection; a successful verify is dispatched by Kind.
func (r *Reconciler) HandleSignedEvent(ctx context.Context, ev gossip.SignedEvent) error {
	event, err := r.verifier.Verify(ctx, ev)
	if err != nil {
		return fmt.Errorf("monitoring/gossip_reconciler: verify: %w", err)
	}

	// v1.32.0 AUDITOR-SCOPE GATE — runs BEFORE the kind switch.
	// When AuditorRegistry is wired, finding-class events from an
	// originator that is either not registered or whose Scope mask
	// doesn't cover the event Kind are silently rejected. The check
	// is permissive for non-finding events (cosigned tree heads,
	// witness rotations) — those have their own SDK-level admission
	// chains and are not gated by the auditor registry.
	if !r.authorizedForKind(ctx, ev.Originator, event.Kind()) {
		// Already logged inside authorizedForKind. Return nil so the
		// puller advances past this event; we do NOT return an error
		// because a stuck-bad event would otherwise hammer the verifier
		// on every poll. Persistence is also skipped — the event is
		// effectively dropped from the JN's worldview.
		return nil
	}

	// D7: persist every verified event so the JN's worldview survives a
	// restart. Durability is the async clock — a store hiccup is logged
	// but never blocks enforcement (the action clock). Idempotent
	// re-receipt returns nil; chain/lamport rejects are observable.
	if r.store != nil {
		if err := r.store.Append(ctx, ev); err != nil {
			r.logger.Warn("monitoring/gossip_reconciler: persist verified event failed",
				slog.String("originator", ev.Originator),
				slog.String("kind", string(event.Kind())),
				slog.String("error", err.Error()))
		}
	}
	switch f := event.(type) {
	case *findings.CosignedTreeHeadFinding:
		verdict := r.heads.RecordCosignedHead(ev.Originator, f.Head.TreeHead)
		if verdict == VerdictForkSuspected {
			r.logger.Error("monitoring/gossip_reconciler: peer log fork — same size, different root",
				slog.String("source_log", ev.Originator),
				slog.Uint64("tree_size", f.Head.TreeSize))
		}
		// Journal fan-out (v1.34+). The in-memory advance has already
		// succeeded; a journal outage must not block live verification
		// (LAW 4 — durability is async, live verification is the action
		// clock). The journal observes its own BurnTransition for
		// equivocations; the live-anchor's VerdictForkSuspected and the
		// journal's burn are two independent signals on the same
		// underlying fact.
		if r.journal != nil {
			rv, err := r.journal.Record(ctx, Head{
				LogDID:         ev.Originator,
				TreeHead:       f.Head.TreeHead,
				Signatures:     f.Head.Signatures,
				CanonicalBytes: f.CanonicalBytes(),
				LamportTime:    ev.LamportTime,
				CommittedAt:    r.now(),
			})
			if err != nil {
				r.logger.Error("monitoring/gossip_reconciler: journal.Record failed; in-memory path succeeded",
					slog.String("source_log", ev.Originator),
					slog.Uint64("tree_size", f.Head.TreeSize),
					slog.String("error", err.Error()))
			} else if rv.BurnTransition {
				r.logger.Error("monitoring/gossip_reconciler: BURN — equivocation detected, journal frozen",
					slog.String("source_log", ev.Originator),
					slog.Uint64("fork_sequence", f.Head.TreeSize))
			}
		}
		return nil

	case *findings.EquivocationFinding:
		if r.equiv == nil {
			r.logger.Error("monitoring/gossip_reconciler: verified equivocation but no responder wired",
				slog.String("ledger_endpoint", f.LedgerEndpoint))
			return nil
		}
		return r.equiv.Respond(ctx, f)

	case *findings.EntryCommitmentEquivocationFinding:
		r.logger.Error("monitoring/gossip_reconciler: verified entry-commitment equivocation",
			slog.String("equivocator", f.EquivocatorDID),
			slog.String("schema_id", f.SchemaID))
		return nil

	case *findings.WitnessRotationFinding:
		// The finding is already Tier-2 verified (K-of-N of the CURRENT set
		// signed this rotation) and its EffectivePos is proven by the carried
		// inclusion proof. Decode the rotation from the self-contained on-log
		// entry bytes (v1.40 finding API). logDID is the originator — the same
		// key the verifier resolved the witness set under.
		rot, decErr := f.Rotation()
		if decErr != nil {
			// Unreachable for a verified finding (Validate already decoded it);
			// surface loudly rather than silently drop (ZT-ENG-GO-03).
			r.logger.Error("monitoring/gossip_reconciler: verified witness rotation failed to decode",
				slog.String("source_log", ev.Originator),
				slog.String("error", decErr.Error()))
			return nil
		}

		// (a) Advance the live trust root: the registry re-runs
		// verify-before-swap and installs the new set under the rotating log's
		// standing quorum.
		if r.rotator == nil {
			r.logger.Error("monitoring/gossip_reconciler: verified witness-set rotation but no rotator wired",
				slog.String("source_log", ev.Originator))
		} else if err := r.rotator.ApplyVerifiedRotation(ev.Originator, rot); err != nil {
			// Non-fatal: typically "no current set for this log" (we do not
			// track that peer's witness set) or a monotonic reject (a newer
			// set already won the race). Observable, not a pull failure.
			r.logger.Error("monitoring/gossip_reconciler: witness-set rotation not applied",
				slog.String("source_log", ev.Originator),
				slog.String("error", err.Error()))
		} else {
			r.logger.Info("monitoring/gossip_reconciler: witness set rotated",
				slog.String("source_log", ev.Originator))
		}

		// (b) Durably journal the rotation as a position-bearing record so the
		// historically-authoritative set is reconstructable at any asOf years
		// later (ZT-SCN-02). Independent of (a): journal every verified rotation
		// chain, even for a log whose live set we do not track. Best-effort —
		// a journal outage must not block live verification (same posture as
		// the heads journal).
		if r.rotationJournal != nil {
			if err := r.rotationJournal.RecordRotation(ctx, types.WitnessRotationRecord{
				Rotation:     rot,
				EffectivePos: f.EffectivePos,
			}); err != nil {
				r.logger.Error("monitoring/gossip_reconciler: rotation journal Record failed; live path succeeded",
					slog.String("source_log", ev.Originator),
					slog.Uint64("effective_seq", f.EffectivePos.Sequence),
					slog.String("error", err.Error()))
			}
		}
		return nil

	default:
		// Verified but no enforcer attached yet (escrow override, originator
		// rotation, ghost leaf, cross-log inclusion). Logged so the event is
		// observable; future enforcers slot into the switch above.
		r.logger.Info("monitoring/gossip_reconciler: verified finding (no enforcer)",
			slog.String("kind", string(event.Kind())),
			slog.String("originator", ev.Originator))
		return nil
	}
}

// authorizedForKind runs the v1.33.1 auditor-scope check on a verified
// event. Returns true when the event should proceed to the kind switch;
// false when the gate rejects (logged + counted inside; caller drops the
// event without error).
//
// When auditorRegistry is nil, returns true unconditionally (preserves
// pre-v1.32 behavior). Non-claim kinds — including the cryptographically-
// proven KindWitnessRotation and KindCrossLogInclusion — also return true
// unconditionally. The auditor registry gates ONLY claim-class events
// (KindEquivocationFinding / KindSMTReplayFinding / KindHistoryRewriteFinding),
// because the originator-DID gate adds nothing to the embedded cryptographic
// proof in the proof-class kinds and would reject legitimate witness-self
// publication. See SDK v1.33.1 AuthorizedForClaim docstring + the
// claim-vs-proof CHANGELOG fragment for the structural argument.
func (r *Reconciler) authorizedForKind(ctx context.Context, originator string, kind gossip.Kind) bool {
	// Ladder 3 C3 (#21): single-word atomic loads on the hot path.
	// records nil ⇒ gate disabled (pre-v1.32 pass-through). amendments
	// nil ⇒ no Gap 2 amendments published yet; the SDK's ResolveAuditorAt
	// accepts a nil-or-empty amendments slice as "amendment-stream is
	// empty", reducing to v1.32.0 registration-only semantics.
	registryPtr := r.auditorRegistry.Load()
	if registryPtr == nil {
		return true
	}
	if !isClaimKind(kind) {
		return true
	}

	asOf := types.LogPosition{}
	if r.auditorScopeAsOf != nil {
		asOf = r.auditorScopeAsOf(ctx)
	}

	var amendments network.AuditorScopeAmendmentByPosition
	if amendmentsPtr := r.auditorAmendments.Load(); amendmentsPtr != nil {
		amendments = *amendmentsPtr
	}
	reg, err := network.ResolveAuditorAt(*registryPtr, amendments, originator, asOf)
	if err != nil {
		reason := "originator not registered as auditor"
		counterReason := scopeRejectReasonNotRegistered
		switch {
		case errors.Is(err, network.ErrAuditorRetired):
			reason = "auditor retired at this log position"
			counterReason = scopeRejectReasonRetired
		case errors.Is(err, network.ErrAuditorRecordsEmpty):
			reason = "no auditors registered on this log"
			counterReason = scopeRejectReasonNoRegistry
		case errors.Is(err, network.ErrAuditorRecordsUnsorted):
			reason = "registry unsorted (operator config bug)"
			counterReason = scopeRejectReasonUnsorted
		}
		r.logger.Warn("monitoring/gossip_reconciler: auditor-scope rejection",
			slog.String("originator", originator),
			slog.String("kind", string(kind)),
			slog.Uint64("as_of_seq", asOf.Sequence),
			slog.String("reason", reason),
		)
		recordAuditorScopeReject(ctx, counterReason, string(kind))
		return false
	}
	if !reg.AuthorizedForClaim(kind) {
		r.logger.Warn("monitoring/gossip_reconciler: auditor-scope rejection",
			slog.String("originator", originator),
			slog.String("kind", string(kind)),
			slog.String("scope", reg.Scope.String()),
			slog.Uint64("as_of_seq", asOf.Sequence),
			slog.String("reason", "registered but Scope does not cover Kind"),
		)
		recordAuditorScopeReject(ctx, scopeRejectReasonScopeMismatch, string(kind))
		return false
	}
	return true
}

// isClaimKind reports whether the SDK gossip Kind is a CLAIM-class
// finding the AuditorRegistration scope mask gates. Mirrors the SDK
// v1.33.1 AuthorizedForClaim dispatch table.
//
// Claim-class kinds are observations the publisher asserts; the auditor
// registry is the trust gate because the cosignatures in the body prove
// WHAT was observed but not that the OBSERVER is trustworthy.
//
// Proof-class kinds (KindWitnessRotation, KindCrossLogInclusion) are
// INTENTIONALLY NOT in this set: their authority comes from the embedded
// cryptographic proof (K-of-N of the old witness set, or a Merkle
// inclusion path). Gating them on the auditor registry would silently
// reject legitimate witness-self-published rotations and ledger-self-
// published inclusion proofs while adding nothing over the cryptographic
// verification. Operators wanting layered DID-level restriction on
// proof-class kinds can enable it via a SEPARATE config flag (not yet
// exposed) — kept out of this gate to preserve the structural distinction.
func isClaimKind(k gossip.Kind) bool {
	switch k {
	case gossip.KindEquivocationFinding,
		gossip.KindSMTReplayFinding,
		gossip.KindHistoryRewriteFinding:
		return true
	}
	return false
}
