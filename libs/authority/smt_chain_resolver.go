/*
FILE PATH: libs/authority/smt_chain_resolver.go

PRE-13a — the ONE canonical delegation-chain resolver, the single home for the
authority walk. Implements the SDK's attestation.DelegationResolver so any
domain pairs it with attestation.EvaluateConstraint; no domain writes a walk.

# The full per-hop invariant set

The SDK's EvaluateConstraintOverChain checks ORIGIN / SCOPE / ATTRIBUTE /
LIVENESS over the chain this resolver returns — but it does NOT re-derive the
chain's structure. The DelegationResolver contract (attestation/delegation.go)
is explicit that the resolver owns hop validation: "Validate each hop's
signature + binding before returning … Return ErrChainBroken when an
intermediate hop's authorising entry is invalid or missing … Mark Hops[i].Live
=false when the hop's delegation entry has been revoked." So this loop enforces,
per hop, the SAME three invariants the JN AuthorityResolver enforces, each
mapped to its SDK signal:

  1. LIVENESS — the SDK's delegation-liveness test on the hop's SMT leaf: a
     delegation is live iff its leaf's OriginTip still equals its own position.
     A revocation (BuildRevocation: Path A, same signer) advances OriginTip away
     from the delegation's position, so OriginTip != pos ⇒ Hop.Live=false (the
     SDK liveness clause rejects via ErrConstraintChainRevoked). The chain is
     RETURNED, not errored, so a caller may still evaluate a historically-valid
     attestation (the SDK's documented reason Live is a bit, not an error). This
     is NOT verifier.EvaluateOrigin: that primitive is for ROOT-ENTITY status and
     classifies a self-targeting revocation (TargetRoot == the revoked entity) as
     Amended — a false negative for delegation liveness. See liveAt.

  2. EXPIRY — the domain ExpiresAt hook against the resolver's clock. An expired
     hop is a liveness LAPSE, structurally identical to a revocation, so it
     likewise sets Hop.Live=false. (AuthorityResolver's RejectExpired.)

  3. GRANTEE-CHAIN LINK (splice-prevention) — each hop's grantee must be the
     PREVIOUS hop's granter (the leaf's grantee must be the queried signer).
     This is the check that makes a forged chain unconstructible: without it, a
     low-authority delegate could point granter_delegation_ref at an unrelated
     high-authority grant and inherit an origin it was never given. A mismatch
     is NOT a liveness lapse — the chain was never valid — so it returns
     attestation.ErrChainBroken (a hard error, never admissible under any
     policy). This is exactly the case ErrChainBroken documents: "a delegation
     chain references a parent authority that did not actually sign the hop."

LIVENESS IS THE SMT, ALWAYS. Hop.Live's revocation component is set EXCLUSIVELY
from each hop's committed SMT leaf (OriginTip == position) — never from the Start
locator, never from the domain. The Start locator and ParentRef only NAVIGATE
(which entry to examine); the committed tree decides whether that entry's
authority is live. This is why a revocation-blind navigation (e.g. the
delegate_did index, which never sees a BuildRevocation) cannot hide a revoked
hop: every hop is re-derived against the committed tree. The index-walk bug —
Live read from the index — is structurally impossible here.

# Binding anchor

Like the JN AuthorityResolver, this resolver does NOT re-verify each entry's raw
signature at read time. The binding anchor is committed-tree membership: an entry
that is fetchable from the log AND has a live SMT leaf was signature-verified at
admission, and the grantee-link reads header fields (DelegateDID / SignerDID)
that the admission signature covers and that mirror the domain payload
(GranteeDID / GranterDID). EvaluateOrigin against the committed leaf is therefore
the binding proof the SDK contract calls for.

# The chain link is domain

A Path A delegation entry carries the granter pointer in its DOMAIN payload
(granter_delegation_ref), NOT in the SDK header (BuildDelegation sets only
DelegateDID; DelegationPointers is the Path B multi-sig field). So the walk LOOP
lives here, but the parent link, the scope, the capability attributes (role …),
and the expiry are injected as pure domain extractors. DelegateDID /
DelegatorDID come from the header (agnostic), and the grantee-link is therefore
header-checkable without a domain hook.
*/
package authority

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// defaultMaxDepth is the protocol maximum delegation depth.
const defaultMaxDepth = 3

// StartFunc locates the signer's own delegation entry (the chain tip) from
// signerDID. It is a NON-AUTHORITY convenience (e.g. the delegate_did index): it
// only LOCATES the starting position and never decides liveness OR linkage — the
// leaf-grantee guard below re-checks that the located entry actually grants to
// signerDID, so a buggy/hostile locator cannot smuggle in the wrong leaf.
// ok=false means the signer has no on-log delegation (the resolver returns an
// empty chain, which the SDK constraint evaluator rejects on the origin clause).
type StartFunc func(ctx context.Context, signerDID string) (types.LogPosition, bool, error)

// ParentRefFunc extracts a delegation entry's parent (granter) delegation
// position — the chain link, which lives in the DOMAIN payload, not the SDK
// header. ok=false at the root (no parent). Pure domain vocabulary; it navigates
// and cannot affect liveness or linkage (the grantee-link guard validates where
// it points).
type ParentRefFunc func(entry *envelope.Entry) (types.LogPosition, bool)

// ScopeFunc extracts the scope tokens a delegation grants, from its domain
// payload. Pure domain vocabulary. Surfaced on Hop.Scopes; the SDK constraint
// matches RequiredScopes against the LEAF hop.
type ScopeFunc func(entry *envelope.Entry) []string

// AttributesFunc extracts the opaque capability set (role, exchange,
// bar_status, …) a delegation declares, from its domain payload. Pure domain
// vocabulary; the SDK never interprets the keys. Surfaced on Hop.Attributes; the
// SDK constraint matches RequiredLeafAttributes against the LEAF hop. This is
// how the G19 role check rides the SDK model: the domain extracts role=<token>,
// the gate's constraint requires it.
type AttributesFunc func(entry *envelope.Entry) map[string]string

// ExpiresAtFunc extracts a delegation's expiry instant from its domain payload.
// ok=false means the entry declares no expiry (never expires on this axis). A
// declared expiry at or before the resolver's clock makes the hop not-live.
type ExpiresAtFunc func(entry *envelope.Entry) (time.Time, bool)

// SMTChainResolver implements attestation.DelegationResolver.
type SMTChainResolver struct {
	// Fetcher reads entries by position. Required.
	Fetcher types.EntryFetcher
	// LeafReader reads SMT leaf state — the liveness oracle (OriginTip ==
	// position). Required at the gate; a nil reader treats every hop as live on
	// the revocation axis (test-only, no SMT).
	LeafReader smt.LeafReader
	// Start locates the chain tip from signerDID (convenience). Required.
	Start StartFunc
	// ParentRef follows the chain tip→root (domain). Required.
	ParentRef ParentRefFunc
	// Scope extracts per-hop scope (domain). nil ⇒ empty scopes.
	Scope ScopeFunc
	// Attributes extracts the per-hop capability map incl. role (domain).
	// nil ⇒ no attributes (the gate's RequiredLeafAttributes would then miss).
	Attributes AttributesFunc
	// ExpiresAt extracts the per-hop expiry (domain). nil ⇒ expiry not enforced
	// (the SMT liveness axis still applies).
	ExpiresAt ExpiresAtFunc
	// Now is the clock the expiry check reads. nil ⇒ time.Now.
	Now func() time.Time
	// MaxDepth bounds the walk. Default defaultMaxDepth.
	MaxDepth int
}

// ResolveChain walks signerDID's delegation chain tip→root and returns it with
// per-hop Live derived from the SMT + expiry, enforcing the grantee-chain link
// as it goes. Implements attestation.DelegationResolver.
//
//   - A grantee-link mismatch (splice) returns ErrChainBroken — the chain was
//     never valid.
//   - A revoked or expired hop is RETURNED with Live=false — the SDK liveness
//     clause rejects, but a caller may still evaluate a historical attestation.
func (r *SMTChainResolver) ResolveChain(ctx context.Context, signerDID string) (attestation.DelegationChain, error) {
	if signerDID == "" {
		return attestation.DelegationChain{}, nil
	}
	pos, ok, err := r.Start(ctx, signerDID)
	if err != nil {
		return attestation.DelegationChain{}, fmt.Errorf("authority: locate chain tip for %q: %w", signerDID, err)
	}
	if !ok {
		return attestation.DelegationChain{}, nil // no on-log delegation
	}

	maxDepth := r.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}

	hops := make([]attestation.DelegationHop, 0, maxDepth)
	visited := make(map[string]struct{}, maxDepth)

	// expectedGrantee is the chain rule: each hop's grantee must be the previous
	// hop's granter; the leaf's grantee must be the queried signer. Starts at
	// signerDID and advances to each hop's granter (header SignerDID).
	expectedGrantee := signerDID

	for i := 0; i < maxDepth; i++ {
		if _, seen := visited[pos.String()]; seen {
			break // cycle — return what we have; the chain won't reach a clean root
		}
		visited[pos.String()] = struct{}{}

		meta, err := r.Fetcher.Fetch(ctx, pos)
		if err != nil {
			return attestation.DelegationChain{Hops: hops}, fmt.Errorf("authority: fetch %s: %w", pos.String(), err)
		}
		if meta == nil || meta.CanonicalBytes == nil {
			// Missing entry: the chain references a hop that cannot be resolved
			// on the log. The SDK contract names this ErrChainBroken.
			return attestation.DelegationChain{Hops: hops},
				fmt.Errorf("authority: hop %s: %w", pos.String(), attestation.ErrChainBroken)
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			return attestation.DelegationChain{Hops: hops}, fmt.Errorf("authority: deserialize %s: %w", pos.String(), err)
		}

		delegateDID := ""
		if entry.Header.DelegateDID != nil {
			delegateDID = *entry.Header.DelegateDID
		}

		// GRANTEE-CHAIN LINK (splice-prevention). The entry the locator/parent
		// pointer led us to MUST actually grant to the grantee the chain
		// expects. A mismatch means the chain references a parent authority that
		// did not sign this hop — a forged link — so it is ErrChainBroken, never
		// a recoverable liveness state.
		if delegateDID != expectedGrantee {
			return attestation.DelegationChain{Hops: hops},
				fmt.Errorf("authority: hop %s grantee=%q, chain expected %q: %w",
					pos.String(), delegateDID, expectedGrantee, attestation.ErrChainBroken)
		}

		// LIVENESS (SMT) ∧ EXPIRY (domain). Both collapse to Live=false — a hop
		// that is revoked OR expired no longer confers authority right now.
		live := r.liveAt(ctx, pos)
		if live && r.ExpiresAt != nil {
			if exp, ok := r.ExpiresAt(entry); ok && !exp.After(now) {
				live = false
			}
		}

		var scopes []string
		if r.Scope != nil {
			scopes = r.Scope(entry)
		}
		var attrs map[string]string
		if r.Attributes != nil {
			attrs = r.Attributes(entry)
		}

		hops = append(hops, attestation.DelegationHop{
			DelegateDID:  delegateDID,
			DelegatorDID: entry.Header.SignerDID,
			Scopes:       scopes,
			Live:         live,
			Attributes:   attrs,
			LogDID:       pos.LogDID,
		})

		parent, ok := r.ParentRef(entry)
		if !ok {
			break // reached the root (no granter pointer)
		}
		// The next hop's grantee must be THIS hop's granter.
		expectedGrantee = entry.Header.SignerDID
		pos = parent
	}
	return attestation.DelegationChain{Hops: hops}, nil
}

// liveAt derives a hop's SMT liveness — the revocation axis, the only source for
// which is the committed tree. It applies the SDK's DELEGATION-liveness test: a
// delegation is live iff its leaf's OriginTip still equals its own position. This
// is the exact test the SDK uses at admission (builder Path B,
// algorithm.go: dLeaf.OriginTip.Equal(ptr)) and in its delegation-tree walker
// (verifier.BuildDelegationTree, delegation_tree.go: "IsLive is true if the
// delegation leaf's OriginTip equals Position").
//
// It is deliberately NOT verifier.EvaluateOrigin. EvaluateOrigin classifies
// ROOT-ENTITY status by the tip entry's TargetRoot geometry, and a real
// BuildRevocation targets the revoked delegation ITSELF (TargetRoot == pos, Path
// A) — which EvaluateOrigin reads as Amended (entity self-modified), i.e. LIVE.
// That is a false negative for delegation liveness: the SDK's own delegation_tree
// notes "Root entity liveness not checked here (use EvaluateOrigin)" precisely
// because the two are different. A revocation advances OriginTip OFF the
// delegation's position, so OriginTip != pos is the correct revoked signal.
//
// Fail-closed: a missing leaf or read error ⇒ not live. A committed delegation
// always has a self-pointing leaf (algorithm.go:63 creates it at admission), so
// absence is unprovable liveness, not "fresh ⇒ live". A nil LeafReader is the
// explicit test-only "no SMT" affordance ⇒ live. Expiry is applied by the caller
// on top of this (a separate, domain-supplied axis).
func (r *SMTChainResolver) liveAt(ctx context.Context, pos types.LogPosition) bool {
	if r.LeafReader == nil {
		return true
	}
	leaf, err := r.LeafReader.Get(ctx, smt.DeriveKey(pos))
	if err != nil || leaf == nil {
		return false // fail-closed: unprovable liveness
	}
	return leaf.OriginTip.Equal(pos)
}

// Compile-time pin: SMTChainResolver is a canonical attestation.DelegationResolver.
var _ attestation.DelegationResolver = (*SMTChainResolver)(nil)
