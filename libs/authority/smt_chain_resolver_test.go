package authority

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// ─── fakes: the data substrate, keyed by sequence ──────────────────

type fakeFetcher struct{ bySeq map[uint64][]byte }

func (f *fakeFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	b, ok := f.bySeq[pos.Sequence]
	if !ok {
		return nil, nil // missing → EvaluateOrigin reads this as a revoked tip
	}
	return &types.EntryWithMetadata{Position: pos, CanonicalBytes: b}, nil
}

// fakeLeaf is the SMT liveness oracle, keyed by position → OriginTip. A live
// delegation's leaf points OriginTip at the delegation's OWN position
// (OriginTip == pos); a revoked one points OriginTip at the revocation (a
// different position). A key with no entry reads as "leaf-not-found", which the
// resolver fails CLOSED on (a committed delegation always has a self-pointing
// leaf — see liveAt).
type fakeLeaf struct{ tips map[[32]byte]types.LogPosition }

func (f *fakeLeaf) Get(_ context.Context, key [32]byte) (*types.SMTLeaf, error) {
	tip, ok := f.tips[key]
	if !ok {
		return nil, nil // not found ⇒ fail-closed (not live)
	}
	return &types.SMTLeaf{Key: key, OriginTip: tip}, nil
}

// liveLeaves builds a fakeLeaf where every given position is LIVE — its leaf
// OriginTip equals its own position, the SDK's delegation-live invariant.
func liveLeaves(ps ...types.LogPosition) *fakeLeaf {
	m := make(map[[32]byte]types.LogPosition, len(ps))
	for _, p := range ps {
		m[smt.DeriveKey(p)] = p
	}
	return &fakeLeaf{tips: m}
}

const logDID = "did:web:l"

func pos(seq uint64) types.LogPosition { return types.LogPosition{LogDID: logDID, Sequence: seq} }

// signedBytes serializes a built entry with a synthetic single signature so the
// resolver's Deserialize path accepts it (signature crypto is the SDK's own
// surface; the resolver reads header fields + the SMT).
func signedBytes(t *testing.T, e *envelope.Entry, signerDID string) []byte {
	t.Helper()
	e.Signatures = []envelope.Signature{{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
	if err := e.Validate(); err != nil {
		t.Fatalf("entry validate: %v", err)
	}
	b, err := envelope.Serialize(e)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return b
}

func mustDelegation(t *testing.T, granter, grantee string) *envelope.Entry {
	t.Helper()
	e, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:x", SignerDID: granter, DelegateDID: grantee,
		Payload: []byte(`{"role":"judge"}`),
	})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	return e
}

// noParent / noScope are the trivial domain extractors for single-hop fixtures.
func noParent(*envelope.Entry) (types.LogPosition, bool) { return types.LogPosition{}, false }
func noScope(*envelope.Entry) []string                   { return nil }

func resolverFor(fetcher *fakeFetcher, leaf *fakeLeaf, startPos types.LogPosition) *SMTChainResolver {
	return &SMTChainResolver{
		Fetcher:    fetcher,
		LeafReader: leaf,
		Start: func(_ context.Context, _ string) (types.LogPosition, bool, error) {
			return startPos, true, nil
		},
		ParentRef: noParent,
		Scope:     noScope,
	}
}

// TestSMTChainResolver_LiveDelegation: a live grant (leaf OriginTip == its own
// position) ⇒ Hop.Live == true.
func TestSMTChainResolver_LiveDelegation(t *testing.T) {
	pJudge := pos(100)
	fetcher := &fakeFetcher{bySeq: map[uint64][]byte{
		100: signedBytes(t, mustDelegation(t, "did:web:authority", "did:web:judge"), "did:web:authority"),
	}}
	leaf := liveLeaves(pJudge) // OriginTip == pJudge ⇒ live

	chain, err := resolverFor(fetcher, leaf, pJudge).ResolveChain(context.Background(), "did:web:judge")
	if err != nil {
		t.Fatalf("ResolveChain: %v", err)
	}
	if len(chain.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1", len(chain.Hops))
	}
	if !chain.Hops[0].Live {
		t.Error("fresh delegation must be Live")
	}
	if chain.Hops[0].DelegateDID != "did:web:judge" || chain.Hops[0].DelegatorDID != "did:web:authority" {
		t.Errorf("hop DIDs = (%q,%q)", chain.Hops[0].DelegateDID, chain.Hops[0].DelegatorDID)
	}
	if !chain.IsLive() {
		t.Error("chain must be live")
	}
}

// TestSMTChainResolver_RevokedViaSMT is the LIVENESS LOCK, modelling a REAL
// delegation.Revoke EXACTLY: a BuildRevocation whose TargetRoot is the revoked
// delegation ITSELF (Path A, same signer), carrying NO DelegateDID (invisible to
// any index). The ledger's Path A advances the revoked delegation's leaf
// OriginTip OFF its own position (to the revocation), so OriginTip != pos and the
// resolver derives Hop.Live=false. This is the SDK's delegation-liveness test
// (delegation_tree.go: OriginTip.Equal(pos)). NOTE: verifier.EvaluateOrigin would
// MISS this exact revocation — it reads a self-targeting revocation as Amended
// (live); that is precisely why liveAt uses OriginTip==position, not
// EvaluateOrigin. A resolver that read an index would also set Live=true and fail
// here — the false green is structurally impossible.
func TestSMTChainResolver_RevokedViaSMT(t *testing.T) {
	pJudge := pos(100)
	pRevoke := pos(200)

	deleg := mustDelegation(t, "did:web:authority", "did:web:judge")
	revoke, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: "did:web:x",
		SignerDID:   "did:web:authority",
		TargetRoot:  pJudge, // revokes the judge's grant — TargetRoot == the delegation itself
		Payload:     []byte(`{"reason":"performance"}`),
	})
	if err != nil {
		t.Fatalf("BuildRevocation: %v", err)
	}
	// Confirm the producer reality: a revocation carries NO DelegateDID, so it
	// can never appear in a delegate_did index.
	if revoke.Header.DelegateDID != nil {
		t.Fatal("BuildRevocation unexpectedly set DelegateDID")
	}

	fetcher := &fakeFetcher{bySeq: map[uint64][]byte{
		100: signedBytes(t, deleg, "did:web:authority"),
		200: signedBytes(t, revoke, "did:web:authority"),
	}}
	// The SMT after Path A: the judge grant's leaf OriginTip advanced to the
	// revocation's position (≠ pJudge) — the revoked signal.
	leaf := &fakeLeaf{tips: map[[32]byte]types.LogPosition{
		smt.DeriveKey(pJudge): pRevoke,
	}}

	chain, err := resolverFor(fetcher, leaf, pJudge).ResolveChain(context.Background(), "did:web:judge")
	if err != nil {
		t.Fatalf("ResolveChain: %v", err)
	}
	if len(chain.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1", len(chain.Hops))
	}
	if chain.Hops[0].Live {
		t.Error("a delegation the SMT reports Revoked MUST be not-live (the index-walk bug must be impossible here)")
	}
	if chain.IsLive() {
		t.Error("chain with a revoked hop must not be live")
	}
}

// TestSMTChainResolver_SpliceRejected is the LOCK for grantee-chain linkage.
// Both entries are REAL producer output; the splice lives only in the
// NAVIGATION — the parent pointer leads the walk to a legitimate grant that was
// issued to someone OTHER than the leaf's granter. Without the header
// grantee-link check the walk would reach an origin it was never given; with it
// the forged link is ErrChainBroken (the SDK's documented signal for a parent
// authority that did not actually sign the hop). This is the splice attack made
// unconstructible.
func TestSMTChainResolver_SpliceRejected(t *testing.T) {
	pLeaf := pos(100)
	pParent := pos(200)

	// Leaf: judge → signer (a real grant to the signer).
	leafEntry := mustDelegation(t, "did:web:judge", "did:web:signer")
	// Parent the pointer leads to: authority → someone-else. A real grant, but
	// NOT to the judge — so it cannot authorise the judge's grant to the signer.
	parentEntry := mustDelegation(t, "did:web:authority", "did:web:someone-else")

	fetcher := &fakeFetcher{bySeq: map[uint64][]byte{
		100: signedBytes(t, leafEntry, "did:web:judge"),
		200: signedBytes(t, parentEntry, "did:web:authority"),
	}}
	leaf := liveLeaves(pLeaf, pParent) // both live on the SMT axis — isolate the splice

	r := &SMTChainResolver{
		Fetcher:    fetcher,
		LeafReader: leaf,
		Start: func(_ context.Context, _ string) (types.LogPosition, bool, error) {
			return pLeaf, true, nil
		},
		// The leaf's domain granter_delegation_ref points at pParent — the splice.
		ParentRef: func(e *envelope.Entry) (types.LogPosition, bool) {
			if e.Header.DelegateDID != nil && *e.Header.DelegateDID == "did:web:signer" {
				return pParent, true
			}
			return types.LogPosition{}, false
		},
		Scope: noScope,
	}

	chain, err := r.ResolveChain(context.Background(), "did:web:signer")
	if !errors.Is(err, attestation.ErrChainBroken) {
		t.Fatalf("spliced chain must return ErrChainBroken, got err=%v", err)
	}
	// The leaf was valid and got appended; the walk broke at the spliced parent.
	if len(chain.Hops) != 1 {
		t.Errorf("Hops = %d, want 1 (walk stops at the broken link)", len(chain.Hops))
	}
}

// TestSMTChainResolver_ExpiryNotLive is the LOCK for the expiry invariant. The
// entry is live on the SMT axis (no revocation); only the domain expiry hook
// distinguishes the two sub-cases. Proving BOTH directions — a past expiry makes
// the hop not-live, a future expiry keeps it live — shows the check genuinely
// opens and closes (it is not a constant).
func TestSMTChainResolver_ExpiryNotLive(t *testing.T) {
	pJudge := pos(100)
	clock := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

	newResolver := func(expiresAt time.Time) *SMTChainResolver {
		fetcher := &fakeFetcher{bySeq: map[uint64][]byte{
			100: signedBytes(t, mustDelegation(t, "did:web:authority", "did:web:judge"), "did:web:authority"),
		}}
		return &SMTChainResolver{
			Fetcher:    fetcher,
			LeafReader: liveLeaves(pJudge), // live on the SMT axis — isolate expiry
			Start: func(_ context.Context, _ string) (types.LogPosition, bool, error) {
				return pJudge, true, nil
			},
			ParentRef: noParent,
			Scope:     noScope,
			ExpiresAt: func(*envelope.Entry) (time.Time, bool) { return expiresAt, true },
			Now:       func() time.Time { return clock },
		}
	}

	t.Run("past expiry ⇒ not live", func(t *testing.T) {
		chain, err := newResolver(clock.Add(-time.Hour)).ResolveChain(context.Background(), "did:web:judge")
		if err != nil {
			t.Fatalf("ResolveChain: %v", err)
		}
		if chain.Hops[0].Live {
			t.Error("an expired hop must not be Live")
		}
		if chain.IsLive() {
			t.Error("chain with an expired hop must not be live")
		}
	})

	t.Run("future expiry ⇒ live", func(t *testing.T) {
		chain, err := newResolver(clock.Add(time.Hour)).ResolveChain(context.Background(), "did:web:judge")
		if err != nil {
			t.Fatalf("ResolveChain: %v", err)
		}
		if !chain.Hops[0].Live {
			t.Error("an unexpired hop must be Live")
		}
	})
}

// TestSMTChainResolver_GateViaConstraint is the PRE-13a integration LOCK: it runs
// the SDK's own attestation.EvaluateConstraint over this resolver — the exact
// resolve→evaluate seam the JN gate will use — and proves the role (leaf
// attribute) and origin clauses decide correctly. No JN code, no hand-rolled
// walk: the SDK evaluator is the judge; the resolver supplies the chain.
func TestSMTChainResolver_GateViaConstraint(t *testing.T) {
	pJudge := pos(100)
	fetcher := &fakeFetcher{bySeq: map[uint64][]byte{
		100: signedBytes(t, mustDelegation(t, "did:web:authority", "did:web:judge"), "did:web:authority"),
	}}
	r := &SMTChainResolver{
		Fetcher:    fetcher,
		LeafReader: liveLeaves(pJudge),
		Start: func(_ context.Context, _ string) (types.LogPosition, bool, error) {
			return pJudge, true, nil
		},
		ParentRef:  noParent,
		Scope:      noScope,
		Attributes: func(*envelope.Entry) map[string]string { return map[string]string{"role": "judge"} },
	}
	ctx := context.Background()
	const signer = "did:web:judge"

	// Origin + role both satisfied ⇒ admitted.
	if err := attestation.EvaluateConstraint(ctx, attestation.Constraint{
		DelegationOriginDID:    "did:web:authority",
		RequiredLeafAttributes: map[string]string{"role": "judge"},
	}, signer, r); err != nil {
		t.Fatalf("origin+role match must admit, got %v", err)
	}

	// Wrong claimed role ⇒ attribute mismatch.
	if err := attestation.EvaluateConstraint(ctx, attestation.Constraint{
		RequiredLeafAttributes: map[string]string{"role": "clerk"},
	}, signer, r); !errors.Is(err, attestation.ErrConstraintAttributeMismatch) {
		t.Fatalf("wrong role must be ErrConstraintAttributeMismatch, got %v", err)
	}

	// Wrong origin ⇒ origin mismatch.
	if err := attestation.EvaluateConstraint(ctx, attestation.Constraint{
		DelegationOriginDID: "did:web:imposter",
	}, signer, r); !errors.Is(err, attestation.ErrConstraintOriginMismatch) {
		t.Fatalf("wrong origin must be ErrConstraintOriginMismatch, got %v", err)
	}
}
