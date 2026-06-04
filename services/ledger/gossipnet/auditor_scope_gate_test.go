/*
FILE PATH: gossipnet/auditor_scope_gate_test.go

v1.32.0 SDK adoption — Tier C tests for the L2 backdoor closure:
auditor-scope authorization on inbound gossip findings.

# WHAT THIS LOCKS

Every fail-closed path in AuditorScopeGate.Append. The gate's
correctness IS the L2 backdoor closure; if any of these tests
regress, the ledger again accepts arbitrary signed findings from
arbitrary DIDs, turning the gossip plane into an amplification
surface for fabricated audit claims.

Coverage:
  - Non-finding kinds pass through unmodified (cosigned tree
    heads, witness rotations, originator rotations are NOT gated).
  - All three finding kinds (Equivocation, SMTReplay,
    HistoryRewrite) are gated when nil registry source is wired
    (fail-closed by design).
  - Finding kind + registry source returns error → reject.
  - Finding kind + registry source returns empty records → reject.
  - Finding kind + registered auditor whose scope COVERS the
    Kind → accept (delegates to underlying Store.Append).
  - Finding kind + registered auditor whose scope DOES NOT
    cover the Kind → reject.
  - Finding kind + auditor retired at asOf → reject.
  - Underlying Store.Append error surfaces unmodified for
    accepted events.
  - Embedded Store passthrough: Get / Head / Stats / Iterate /
    Close all delegate to the embedded Store without
    modification.

Pure unit tests; no real gossip wire, no on-log walk. The L2
contract is the AUTHORIZATION decision; this file pins it.
*/
package gossipnet

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// recordingStore is a sdkgossip.Store decorator-target. It
// records Append calls and lets each call's error be steered.
// All other Store methods are no-ops returning zero values —
// the L2 gate only intercepts Append, so the other paths are
// not exercised by gate tests.
type recordingStore struct {
	appendCalls []sdkgossip.SignedEvent
	appendErr   error
	closed      bool
}

func (r *recordingStore) Append(_ context.Context, ev sdkgossip.SignedEvent) error {
	r.appendCalls = append(r.appendCalls, ev)
	return r.appendErr
}

func (r *recordingStore) Head(_ context.Context, _ string) ([32]byte, uint64, error) {
	return [32]byte{}, 0, nil
}

func (r *recordingStore) Get(_ context.Context, _ [32]byte) (sdkgossip.SignedEvent, error) {
	return sdkgossip.SignedEvent{}, nil
}

func (r *recordingStore) Iterate(_ context.Context, _ sdkgossip.Filter, _ func(sdkgossip.SignedEvent) error) error {
	return nil
}

func (r *recordingStore) Stats(_ context.Context) (sdkgossip.StoreStats, error) {
	return sdkgossip.StoreStats{}, nil
}

func (r *recordingStore) IterSince(_ context.Context, _ sdkgossip.IterCursor, _ int) ([]sdkgossip.SignedEvent, sdkgossip.IterCursor, error) {
	return nil, sdkgossip.IterCursor{}, nil
}

func (r *recordingStore) LatestSTH(_ context.Context, _ string) (sdkgossip.SignedEvent, bool, error) {
	return sdkgossip.SignedEvent{}, false, nil
}

func (r *recordingStore) Close(_ context.Context) error {
	r.closed = true
	return nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// validRegistration returns a syntactically-valid
// AuditorRegistration with the requested DID + scope, structured
// for AuthorizedFor dispatch in the gate. The validation is
// real: we exercise the SDK's validator so the test fixtures
// can never construct payloads the wire schema would reject —
// rejecting invalid registrations is the L4 gate's job, not L2.
func validRegistration(t *testing.T, did string, scope network.AuditorScope) network.AuditorRegistration {
	t.Helper()
	r := network.AuditorRegistration{
		AuditorDID: did,
		// 33-byte ECDSA-shaped key (compressed secp256k1) so length
		// validators are happy without us pulling crypto primitives.
		PublicKey:   make([]byte, 33),
		SchemeTag:   1, // ECDSA
		FindingsURL: "https://auditor.example.org/v1/findings",
		Scope:       scope,
	}
	r.PublicKey[0] = 0x02
	if err := r.Validate(); err != nil {
		t.Fatalf("test fixture validRegistration is itself invalid: %v", err)
	}
	return r
}

// recordsFor wraps the registration into an AuditorRegistrationRecord
// at a fixed test position. Walker sort discipline is preserved.
//
// EffectivePos starts at Sequence=0 (not 1): the gate's default
// asOf is the zero LogPosition, and network.ResolveAuditorAt skips
// any record where asOf.Less(EffectivePos) — so a record at
// Sequence=1 would be invisible to a zero-asOf gate. Starting at
// 0 makes records "effective from the beginning" and visible to
// the gate by default. The retired-auditor test injects its own
// AsOfProvider so the relative ordering still works there
// (RetiredAt=10 vs asOf.Sequence=20 → ErrAuditorRetired).
func recordsFor(regs ...network.AuditorRegistration) []network.AuditorRegistrationRecord {
	out := make([]network.AuditorRegistrationRecord, 0, len(regs))
	for i, r := range regs {
		out = append(out, network.AuditorRegistrationRecord{
			EffectivePos: types.LogPosition{Sequence: uint64(i)},
			Payload:      r,
		})
	}
	return out
}

// ── Non-finding kind passthrough ────────────────────────────────

// TestAuditorScopeGate_NonFindingPassesThrough exercises every
// non-finding kind known to the SDK at the time of v1.32.0. They
// MUST flow to the underlying Store regardless of registry state.
// A regression that gated cosigned tree heads or rotations would
// brick the entire gossip plane on every fresh deployment.
func TestAuditorScopeGate_NonFindingPassesThrough(t *testing.T) {
	cases := []sdkgossip.Kind{
		sdkgossip.KindCosignedTreeHead,
		sdkgossip.KindOriginatorRotation,
		sdkgossip.KindWitnessRotation,
		sdkgossip.KindEscrowOverrideAuth,
		sdkgossip.KindGhostLeaf,
		sdkgossip.KindCrossLogInclusion,
		sdkgossip.KindEntryCommitmentEquivocation,
	}
	for _, k := range cases {
		k := k
		t.Run(k.String(), func(t *testing.T) {
			rs := &recordingStore{}
			gate, err := NewAuditorScopeGate(AuditorScopeGateConfig{
				Underlying: rs,
				Registry:   nil, // would fail-close findings, but not these
				Logger:     discardLogger(),
			})
			if err != nil {
				t.Fatalf("NewAuditorScopeGate: %v", err)
			}
			ev := sdkgossip.SignedEvent{
				Kind:       k,
				Originator: "did:web:noisy",
			}
			if err := gate.Append(context.Background(), ev); err != nil {
				t.Fatalf("non-finding kind %s must pass through, got %v", k, err)
			}
			if len(rs.appendCalls) != 1 {
				t.Errorf("expected 1 underlying Append, got %d", len(rs.appendCalls))
			}
		})
	}
}

// ── Finding kinds — fail-closed without registry ───────────────────

// TestAuditorScopeGate_FindingRejectedWithNilRegistry is the
// load-bearing fail-closed posture. A gate without a registry
// source has no basis for any auditor decision; every finding
// MUST be rejected so the ledger can never persist an
// unauthorized claim during the bootstrap window before any
// AuditorRegistrationV1 entry has been admitted.
func TestAuditorScopeGate_FindingRejectedWithNilRegistry(t *testing.T) {
	cases := []sdkgossip.Kind{
		sdkgossip.KindEquivocationFinding,
		sdkgossip.KindSMTReplayFinding,
		sdkgossip.KindHistoryRewriteFinding,
	}
	for _, k := range cases {
		k := k
		t.Run(k.String(), func(t *testing.T) {
			rs := &recordingStore{}
			gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
				Underlying: rs,
				Registry:   nil,
				Logger:     discardLogger(),
			})
			ev := sdkgossip.SignedEvent{
				Kind:       k,
				Originator: "did:web:rogue-auditor",
			}
			if err := gate.Append(context.Background(), ev); err == nil {
				t.Fatalf("finding %s with nil registry must be rejected (fail-closed)", k)
			}
			if len(rs.appendCalls) != 0 {
				t.Errorf("rejected event MUST NOT reach underlying store: got %d Append calls", len(rs.appendCalls))
			}
		})
	}
}

// TestAuditorScopeGate_FindingRejectedWhenRegistryErrors mirrors
// the nil-registry case for transient walker failures: the
// registry source returning an error MUST cause Append to
// reject. A regression that silently accepted on registry error
// would mean the ledger drops the gate every time the walker
// has a hiccup.
func TestAuditorScopeGate_FindingRejectedWhenRegistryErrors(t *testing.T) {
	rs := &recordingStore{}
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return nil, errors.New("walker down")
		},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindEquivocationFinding,
		Originator: "did:web:any",
	}
	if err := gate.Append(context.Background(), ev); err == nil {
		t.Fatal("finding with registry error must be rejected")
	}
	if len(rs.appendCalls) != 0 {
		t.Errorf("rejected event MUST NOT reach underlying store")
	}
}

// TestAuditorScopeGate_FindingRejectedWhenRegistryEmpty covers the
// "registry source is wired but no auditors registered" case —
// the more common bootstrap-window state. Same fail-closed
// behavior as nil registry.
func TestAuditorScopeGate_FindingRejectedWhenRegistryEmpty(t *testing.T) {
	rs := &recordingStore{}
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return nil, nil
		},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindEquivocationFinding,
		Originator: "did:web:any",
	}
	if err := gate.Append(context.Background(), ev); err == nil {
		t.Fatal("finding with empty records must be rejected")
	}
}

// ── Finding kinds — accept / reject by scope ───────────────────────

// TestAuditorScopeGate_AcceptsAuthorizedAuditor exercises the
// success path: a registered auditor whose Scope mask covers
// the event Kind. The underlying Store.Append MUST be called
// exactly once.
func TestAuditorScopeGate_AcceptsAuthorizedAuditor(t *testing.T) {
	const auditorDID = "did:web:auditor-a.example.org"
	rs := &recordingStore{}
	reg := validRegistration(t, auditorDID, network.ScopeEquivocation)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return recordsFor(reg), nil
		},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindEquivocationFinding,
		Originator: auditorDID,
	}
	if err := gate.Append(context.Background(), ev); err != nil {
		t.Fatalf("authorized auditor must be accepted: %v", err)
	}
	if len(rs.appendCalls) != 1 {
		t.Errorf("expected 1 underlying Append, got %d", len(rs.appendCalls))
	}
}

// TestAuditorScopeGate_RejectsUnauthorizedAuditor exercises the
// L5-extension authorization gate: a registered auditor whose
// Scope mask does NOT cover the event Kind. This is the case
// that distinguishes "knows who is an auditor" from "knows what
// THAT auditor is authorized to publish" — the load-bearing
// novelty of v1.32.0's AuditorScope.
func TestAuditorScopeGate_RejectsUnauthorizedAuditor(t *testing.T) {
	const auditorDID = "did:web:auditor-equiv-only.example.org"
	rs := &recordingStore{}
	// Scope: ONLY equivocation. The event is a history-rewrite
	// finding — out of scope.
	reg := validRegistration(t, auditorDID, network.ScopeEquivocation)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return recordsFor(reg), nil
		},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindHistoryRewriteFinding,
		Originator: auditorDID,
	}
	if err := gate.Append(context.Background(), ev); err == nil {
		t.Fatal("auditor outside scope must be rejected")
	}
	if len(rs.appendCalls) != 0 {
		t.Errorf("rejected event MUST NOT reach underlying store")
	}
}

// TestAuditorScopeGate_RejectsRetiredAuditor exercises the
// time-of-effect semantics. An auditor registered, then retired,
// MUST be rejected for events at/after the retirement position.
// asOf is supplied via AsOfProvider; here we wire a deterministic
// provider to make the test asof match the retirement boundary.
func TestAuditorScopeGate_RejectsRetiredAuditor(t *testing.T) {
	const auditorDID = "did:web:auditor-retired.example.org"
	rs := &recordingStore{}

	reg := validRegistration(t, auditorDID, network.ScopeEquivocation)
	retiredAt := uint64(10)
	reg.RetiredAt = &retiredAt

	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return recordsFor(reg), nil
		},
		AsOf:   fixedAsOf{seq: 20}, // well after retirement
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindEquivocationFinding,
		Originator: auditorDID,
	}
	if err := gate.Append(context.Background(), ev); err == nil {
		t.Fatal("retired auditor must be rejected")
	}
}

// TestAuditorScopeGate_RejectsUnregisteredOriginator exercises
// the "valid registry, but originator not in it" case. The
// originator string is a DID nobody has registered as an
// auditor; the gate MUST reject regardless of how many other
// auditors are valid.
func TestAuditorScopeGate_RejectsUnregisteredOriginator(t *testing.T) {
	rs := &recordingStore{}
	reg := validRegistration(t, "did:web:legitimate.example.org", network.ScopeAll)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return recordsFor(reg), nil
		},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindEquivocationFinding,
		Originator: "did:web:imposter.example.org",
	}
	if err := gate.Append(context.Background(), ev); err == nil {
		t.Fatal("unregistered originator must be rejected")
	}
}

// TestAuditorScopeGate_UnderlyingErrorSurfaces verifies that when
// the gate accepts an event, the underlying Store's error
// (chain-break, lamport regression, store-full) propagates back
// to the caller verbatim. The gate is a decorator, not a swallow.
func TestAuditorScopeGate_UnderlyingErrorSurfaces(t *testing.T) {
	const auditorDID = "did:web:auditor-ok.example.org"
	boom := errors.New("store full")
	rs := &recordingStore{appendErr: boom}
	reg := validRegistration(t, auditorDID, network.ScopeAll)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return recordsFor(reg), nil
		},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindEquivocationFinding,
		Originator: auditorDID,
	}
	err := gate.Append(context.Background(), ev)
	if !errors.Is(err, boom) {
		t.Fatalf("underlying error must propagate, got %v", err)
	}
}

// TestAuditorScopeGate_AllThreeFindingScopesAcceptedIndependently
// pins the Scope→Kind mapping: each scope bit independently
// authorizes its corresponding finding kind. A regression that
// crossed the wires (granting Equivocation also enables
// HistoryRewrite, say) would silently expand auditor authority.
func TestAuditorScopeGate_AllThreeFindingScopesAcceptedIndependently(t *testing.T) {
	cases := []struct {
		scope network.AuditorScope
		kind  sdkgossip.Kind
		label string
	}{
		{network.ScopeEquivocation, sdkgossip.KindEquivocationFinding, "equivocation"},
		{network.ScopeSMTReplay, sdkgossip.KindSMTReplayFinding, "smt_replay"},
		{network.ScopeHistoryRewrite, sdkgossip.KindHistoryRewriteFinding, "history_rewrite"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.label, func(t *testing.T) {
			const auditorDID = "did:web:scoped.example.org"
			rs := &recordingStore{}
			reg := validRegistration(t, auditorDID, c.scope)
			gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
				Underlying: rs,
				Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
					return recordsFor(reg), nil
				},
				Logger: discardLogger(),
			})
			ev := sdkgossip.SignedEvent{Kind: c.kind, Originator: auditorDID}
			if err := gate.Append(context.Background(), ev); err != nil {
				t.Errorf("scope %s should authorize kind %s; got %v", c.label, c.kind, err)
			}
		})
	}
}

// ── Constructor and embedded-Store passthrough ─────────────────────

// TestNewAuditorScopeGate_RejectsNilUnderlying locks the
// constructor's nil-check. A decorator with no target would
// either NPE on every Append (bad) or silently swallow events
// (catastrophic). Refuse at construction.
func TestNewAuditorScopeGate_RejectsNilUnderlying(t *testing.T) {
	_, err := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: nil,
	})
	if err == nil {
		t.Fatal("nil Underlying must be rejected at construction")
	}
}

// TestAuditorScopeGate_NilLoggerDefaults guards against a panic
// when a deployment forgets to wire a logger — slog.Default()
// is the right fallback for production observability.
func TestAuditorScopeGate_NilLoggerDefaults(t *testing.T) {
	rs := &recordingStore{}
	gate, err := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Logger:     nil,
	})
	if err != nil {
		t.Fatalf("nil logger must default, got %v", err)
	}
	if gate.logger == nil {
		t.Error("logger should default when Config.Logger is nil")
	}
}

// TestAuditorScopeGate_CloseDelegates verifies the embedded-Store
// passthrough: Close on the gate calls Close on the embedded
// store. The same delegation applies to Iterate/Get/Head/Stats —
// they're all method-promoted through the embedded interface
// field, so one explicit test pins the discipline.
func TestAuditorScopeGate_CloseDelegates(t *testing.T) {
	rs := &recordingStore{}
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Logger:     discardLogger(),
	})
	if err := gate.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !rs.closed {
		t.Error("Close must delegate to embedded Store")
	}
}

// fixedAsOf is a deterministic AsOfProvider used by the
// retired-auditor test. Returning a known sequence makes the
// retirement boundary computable from the test.
type fixedAsOf struct {
	seq uint64
}

func (f fixedAsOf) LatestPosition(_ context.Context) (types.LogPosition, error) {
	return types.LogPosition{Sequence: f.seq}, nil
}

// ──────────────────────────────────────────────────────────────────
// v1.33.1 SDK adoption — Gap 2 (amendment merge) + Gap 3 (compromise)
// ──────────────────────────────────────────────────────────────────

// regAtPos wraps a single AuditorRegistration at a caller-supplied
// EffectivePos. The default recordsFor helper above places records at
// sequential indexes starting at 0, which is fine for one-record
// fixtures but the amendment tests need explicit ordering across
// reg-then-amendment-then-reg interleavings, so this gives the test
// case full control over the per-record position.
func regAtPos(r network.AuditorRegistration, seq uint64) network.AuditorRegistrationRecord {
	return network.AuditorRegistrationRecord{
		EffectivePos: types.LogPosition{Sequence: seq},
		Payload:      r,
	}
}

// validAmendment returns a syntactically-valid
// AuditorScopeAmendmentRecord. The SDK's amendment Validate() runs
// inside the helper so the fixtures cannot construct payloads the
// wire schema would reject — keeping the L4 admission gate's
// responsibility cleanly separated from the L2 gate's tests.
func validAmendment(t *testing.T, did string, newScope network.AuditorScope, effectivePos uint64) network.AuditorScopeAmendmentRecord {
	t.Helper()
	a := network.AuditorScopeAmendment{
		AuditorDID: did,
		NewScope:   newScope,
		Reason:     "test fixture",
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("validAmendment fixture invalid: %v", err)
	}
	return network.AuditorScopeAmendmentRecord{
		EffectivePos: types.LogPosition{Sequence: effectivePos},
		Payload:      a,
	}
}

// amendmentRecordsFor returns a sorted-by-EffectivePos slice — the
// SDK's ResolveAuditorAt requires ascending order or returns
// ErrScopeAmendmentRecordsUnsorted. The fixture asserts the input
// is already sorted (test author's responsibility) so tests fail
// loudly on a fixture mistake rather than tripping the SDK's
// ErrScopeAmendmentRecordsUnsorted at runtime.
func amendmentRecordsFor(amends ...network.AuditorScopeAmendmentRecord) []network.AuditorScopeAmendmentRecord {
	for i := 1; i < len(amends); i++ {
		if amends[i].EffectivePos.Less(amends[i-1].EffectivePos) {
			panic("amendmentRecordsFor: input not sorted by EffectivePos ascending")
		}
	}
	out := make([]network.AuditorScopeAmendmentRecord, len(amends))
	copy(out, amends)
	return out
}

// validCompromiseEvent constructs a SignedEvent for
// KindAuditorCompromise whose Body decodes via the SDK's
// findings.AuditorCompromiseFromWire. Mirrors the gate's
// recordCompromise() decode chain so the test fixture exercises
// the same wire path production does.
func validCompromiseEvent(t *testing.T, did string, compromisedAtSeq uint64) sdkgossip.SignedEvent {
	t.Helper()
	f, err := findings.NewAuditorCompromiseFinding(did, compromisedAtSeq, "test fixture")
	if err != nil {
		t.Fatalf("NewAuditorCompromiseFinding: %v", err)
	}
	body, err := f.EncodeWireBody()
	if err != nil {
		t.Fatalf("EncodeWireBody: %v", err)
	}
	return sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindAuditorCompromise,
		Originator: did,
		Body:       body,
	}
}

// ── Gap 2: amendment-merge tests ───────────────────────────────

// TestAuditorScopeGate_AmendmentExpandsScope locks the v1.33.0 Gap 2
// load-bearing semantic: an AuditorScopeAmendmentV1 with a LATER
// EffectivePos than the registration replaces the registration's
// Scope mask with its NewScope. Registration is ScopeEquivocation;
// amendment expands to ScopeAll; gate at asOf > amendmentPos MUST
// accept an SMT-replay finding that registration-only scope would
// have rejected.
func TestAuditorScopeGate_AmendmentExpandsScope(t *testing.T) {
	const did = "did:web:auditor-expand.example.org"
	rs := &recordingStore{}
	reg := regAtPos(validRegistration(t, did, network.ScopeEquivocation), 0)
	amend := validAmendment(t, did, network.ScopeAll, 5)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return []network.AuditorRegistrationRecord{reg}, nil
		},
		Amendments: func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
			return amendmentRecordsFor(amend), nil
		},
		AsOf:   fixedAsOf{seq: 10},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindSMTReplayFinding,
		Originator: did,
	}
	if err := gate.Append(context.Background(), ev); err != nil {
		t.Fatalf("amendment-expanded scope must authorize SMTReplay; got %v", err)
	}
	if len(rs.appendCalls) != 1 {
		t.Errorf("accepted event should reach store: got %d Append calls", len(rs.appendCalls))
	}
}

// TestAuditorScopeGate_AmendmentReducesScope locks the inverse
// direction: an amendment narrowing scope from ScopeAll to
// ScopeEquivocation MUST cause SMTReplay rejection at the gate
// even though the original registration would have allowed it.
// A regression that ignored amendments or merged the wider scope
// would re-open the L2 backdoor for any auditor the network had
// since restricted.
func TestAuditorScopeGate_AmendmentReducesScope(t *testing.T) {
	const did = "did:web:auditor-reduce.example.org"
	rs := &recordingStore{}
	reg := regAtPos(validRegistration(t, did, network.ScopeAll), 0)
	amend := validAmendment(t, did, network.ScopeEquivocation, 5)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return []network.AuditorRegistrationRecord{reg}, nil
		},
		Amendments: func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
			return amendmentRecordsFor(amend), nil
		},
		AsOf:   fixedAsOf{seq: 10},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindSMTReplayFinding,
		Originator: did,
	}
	if err := gate.Append(context.Background(), ev); err == nil {
		t.Fatal("amendment-reduced scope must reject SMTReplay")
	}
	if len(rs.appendCalls) != 0 {
		t.Errorf("rejected event MUST NOT reach underlying store")
	}
}

// TestAuditorScopeGate_FreshRegistrationSupersedesAmendment locks
// the supersession semantic. A registration with EffectivePos
// later than the amendment's window resets the baseline: the
// fresh registration's own Scope becomes the new effective scope,
// and the older amendment is no longer in window. Sequence is
// reg(seq=0,ScopeEquivocation) → amend(seq=5,ScopeAll) →
// reg(seq=10,ScopeEquivocation). At asOf=20 the gate's resolved
// auditor MUST come from the seq=10 registration with
// ScopeEquivocation only, so SMTReplay is rejected.
func TestAuditorScopeGate_FreshRegistrationSupersedesAmendment(t *testing.T) {
	const did = "did:web:auditor-supersede.example.org"
	reg1 := regAtPos(validRegistration(t, did, network.ScopeEquivocation), 0)
	reg2 := regAtPos(validRegistration(t, did, network.ScopeEquivocation), 10)
	amend := validAmendment(t, did, network.ScopeAll, 5)
	registryFn := func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
		return []network.AuditorRegistrationRecord{reg1, reg2}, nil
	}
	amendmentFn := func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
		return amendmentRecordsFor(amend), nil
	}

	// Equivocation MUST still be allowed (covered by the fresh
	// registration's ScopeEquivocation).
	rs1 := &recordingStore{}
	gate1, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs1, Registry: registryFn, Amendments: amendmentFn,
		AsOf: fixedAsOf{seq: 20}, Logger: discardLogger(),
	})
	if err := gate1.Append(context.Background(), sdkgossip.SignedEvent{
		Kind: sdkgossip.KindEquivocationFinding, Originator: did,
	}); err != nil {
		t.Fatalf("post-supersession Equivocation must be authorized: %v", err)
	}

	// SMTReplay MUST be rejected — the fresh seq=10 registration
	// replaced the amendment's wider scope at asOf=20.
	rs2 := &recordingStore{}
	gate2, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs2, Registry: registryFn, Amendments: amendmentFn,
		AsOf: fixedAsOf{seq: 20}, Logger: discardLogger(),
	})
	if err := gate2.Append(context.Background(), sdkgossip.SignedEvent{
		Kind: sdkgossip.KindSMTReplayFinding, Originator: did,
	}); err == nil {
		t.Fatal("post-supersession SMTReplay must be rejected (amendment no longer in window)")
	}
	if len(rs2.appendCalls) != 0 {
		t.Errorf("rejected event MUST NOT reach underlying store")
	}
}

// TestAuditorScopeGate_RejectsWhenAmendmentSourceErrors mirrors
// the registry-source fail-closed posture for the new amendment
// source. A walker hiccup on amendments MUST cause finding
// rejection — silently dropping the amendment lookup and using
// only registration scope would re-open the L2 backdoor for any
// auditor whose scope was meant to be restricted by amendment.
func TestAuditorScopeGate_RejectsWhenAmendmentSourceErrors(t *testing.T) {
	const did = "did:web:auditor-broken.example.org"
	rs := &recordingStore{}
	reg := regAtPos(validRegistration(t, did, network.ScopeAll), 0)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return []network.AuditorRegistrationRecord{reg}, nil
		},
		Amendments: func(_ context.Context) ([]network.AuditorScopeAmendmentRecord, error) {
			return nil, errors.New("amendment walker down")
		},
		Logger: discardLogger(),
	})
	ev := sdkgossip.SignedEvent{
		Kind:       sdkgossip.KindEquivocationFinding,
		Originator: did,
	}
	if err := gate.Append(context.Background(), ev); err == nil {
		t.Fatal("amendment source error MUST cause finding rejection (fail-closed)")
	}
	if len(rs.appendCalls) != 0 {
		t.Errorf("rejected event MUST NOT reach underlying store")
	}
}

// ── Gap 3: KindAuditorCompromise tests ──────────────────────────

// TestAuditorScopeGate_CompromiseBroadcastAccepted exercises the
// happy-path: a legitimate auditor self-broadcasts a
// KindAuditorCompromise event; the gate authorizes it (compromise
// is intentionally NOT in the claim-class gating set — but it
// flows through the gate via Append so recordCompromise() is
// invoked, persisting the cutoff for future findings).
//
// Note: KindAuditorCompromise is not a finding-class kind per
// isFindingKind, so it passes the gate's claim-class check via
// the early-exit. The recordCompromise hook fires AFTER the
// underlying Store.Append, so the order is: Store.Append → record.
func TestAuditorScopeGate_CompromiseBroadcastAccepted(t *testing.T) {
	const did = "did:web:auditor-self-compromise.example.org"
	rs := &recordingStore{}
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry:   nil, // non-finding kind: registry is not consulted
		Logger:     discardLogger(),
	})
	ev := validCompromiseEvent(t, did, 7)
	if err := gate.Append(context.Background(), ev); err != nil {
		t.Fatalf("compromise broadcast must be accepted: %v", err)
	}
	if len(rs.appendCalls) != 1 {
		t.Errorf("compromise event should reach store: got %d", len(rs.appendCalls))
	}
	gotSeq, seen := gate.compromiseAt(did)
	if !seen {
		t.Fatal("compromiseAt MUST report the broadcast was recorded")
	}
	if gotSeq != 7 {
		t.Errorf("compromiseAt seq: got %d, want 7", gotSeq)
	}
}

// TestAuditorScopeGate_RejectsFindingFromCompromisedAuditor locks
// the load-bearing forward-only rejection. After a compromise
// broadcast at seq=10, any future finding from the SAME DID at
// asOf.Sequence >= 10 MUST be rejected with the
// auditor_compromised counter — even if the auditor's
// registration scope would otherwise authorize the kind.
func TestAuditorScopeGate_RejectsFindingFromCompromisedAuditor(t *testing.T) {
	const did = "did:web:auditor-burned.example.org"
	rs := &recordingStore{}
	reg := regAtPos(validRegistration(t, did, network.ScopeAll), 0)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return []network.AuditorRegistrationRecord{reg}, nil
		},
		AsOf:   fixedAsOf{seq: 20}, // well after compromise
		Logger: discardLogger(),
	})
	// First broadcast the compromise at seq=10.
	if err := gate.Append(context.Background(), validCompromiseEvent(t, did, 10)); err != nil {
		t.Fatalf("compromise broadcast: %v", err)
	}
	// Then a finding at asOf.Sequence=20 (post compromise) MUST be
	// rejected even though the registration's ScopeAll would
	// authorize an Equivocation finding in normal conditions.
	rs.appendCalls = rs.appendCalls[:0] // clear the compromise Append
	err := gate.Append(context.Background(), sdkgossip.SignedEvent{
		Kind: sdkgossip.KindEquivocationFinding, Originator: did,
	})
	if err == nil {
		t.Fatal("finding from compromised auditor must be rejected")
	}
	if len(rs.appendCalls) != 0 {
		t.Errorf("rejected finding MUST NOT reach underlying store; got %d Append calls", len(rs.appendCalls))
	}
}

// TestAuditorScopeGate_CompromiseLowestSeqWins locks the
// "first broadcast is the trusted cutoff" idempotency rule. If
// an auditor's key is compromised, the FIRST broadcast under
// that key is presumed to be from the legitimate owner reacting
// to the breach (or from the attacker, in which case the
// strictest cutoff is still operator-protective). A LATER
// broadcast under the now-compromised key MUST NOT raise the
// cutoff — that would let an attacker undo the protection by
// rebroadcasting with a later compromisedAtSeq.
func TestAuditorScopeGate_CompromiseLowestSeqWins(t *testing.T) {
	const did = "did:web:auditor-twice.example.org"
	rs := &recordingStore{}
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Logger:     discardLogger(),
	})
	// Broadcast the higher cutoff FIRST (seq=20), then a lower
	// cutoff (seq=10). Result: stored cutoff must be 10.
	if err := gate.Append(context.Background(), validCompromiseEvent(t, did, 20)); err != nil {
		t.Fatalf("first compromise: %v", err)
	}
	if err := gate.Append(context.Background(), validCompromiseEvent(t, did, 10)); err != nil {
		t.Fatalf("second compromise: %v", err)
	}
	gotSeq, seen := gate.compromiseAt(did)
	if !seen {
		t.Fatal("compromiseAt MUST report at least one broadcast was recorded")
	}
	if gotSeq != 10 {
		t.Errorf("lowest-seq-wins: got %d, want 10", gotSeq)
	}
}

// TestAuditorScopeGate_PriorFindingNotRetroactivelyRejected pins
// the forward-only semantic. A compromise at seq=10 only invalidates
// findings whose asOf.Sequence >= 10 — older findings (already
// admitted at asOf < 10) are out of scope for the gate's
// compromise check. The gate's branch is
// `if asOf.Sequence >= compromiseSeq`, so asOf=5 with cutoff=10
// MUST pass through the compromise check (and then through normal
// scope authorization).
func TestAuditorScopeGate_PriorFindingNotRetroactivelyRejected(t *testing.T) {
	const did = "did:web:auditor-prior.example.org"
	rs := &recordingStore{}
	reg := regAtPos(validRegistration(t, did, network.ScopeAll), 0)
	gate, _ := NewAuditorScopeGate(AuditorScopeGateConfig{
		Underlying: rs,
		Registry: func(_ context.Context) ([]network.AuditorRegistrationRecord, error) {
			return []network.AuditorRegistrationRecord{reg}, nil
		},
		AsOf:   fixedAsOf{seq: 5}, // BEFORE compromise
		Logger: discardLogger(),
	})
	// Record a compromise at seq=10 first.
	if err := gate.Append(context.Background(), validCompromiseEvent(t, did, 10)); err != nil {
		t.Fatalf("compromise: %v", err)
	}
	rs.appendCalls = rs.appendCalls[:0] // ignore the compromise Append
	// A finding at asOf=5 (BEFORE the compromise seq=10) MUST pass.
	if err := gate.Append(context.Background(), sdkgossip.SignedEvent{
		Kind: sdkgossip.KindEquivocationFinding, Originator: did,
	}); err != nil {
		t.Fatalf("finding before compromise seq must be accepted: %v", err)
	}
	if len(rs.appendCalls) != 1 {
		t.Errorf("pre-compromise finding should reach store: got %d Append calls", len(rs.appendCalls))
	}
}
