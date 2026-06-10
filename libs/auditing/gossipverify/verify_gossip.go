// FILE PATH: libs/auditing/gossipverify/verify_gossip.go
//
// DESCRIPTION:
//
//	GossipVerifier is the zero-trust verification seam for INBOUND gossip
//	events pulled from peer ledgers. Every pulled event is attacker-controlled
//	bytes until it passes the two-tier check here; only then may a downstream
//	enforcer act on it or JN re-serve it.
//
//	  Tier 1 — Envelope authenticity (gossip.Verify): the originator actually
//	    signed THIS event for THIS network. A pulling client receives raw JSON,
//	    so JN performs this itself — the SDK server does it on push; the puller
//	    is its own gossip layer. This is the authority for self-attested Kinds
//	    (originator/ghost) and the transport-identity check for all others.
//
//	  Tier 2 — Finding proof (findings.Router): the embedded K-of-N /
//	    signer / merkle proof, dispatched by Kind against JN-LOCAL trust roots
//	    only — witness sets from the registry, JN's own SignerVerifier, a
//	    trusted tile mirror. A finding's self-claimed identifiers are lookup
//	    keys into local trust, never trust themselves.
//
//	Fail-closed: any failure returns an error and no event.
package gossipverify

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	tessera "github.com/transparency-dev/tessera/client"
)

// ErrGossipVerify wraps every inbound-event verification failure. Underlying
// SDK + router sentinels are reachable via errors.Is.
var ErrGossipVerify = errors.New("verification/verify_gossip")

// EnvelopeVerifier authenticates a gossip SignedEvent's originator signature
// (Tier 1). The production implementation delegates to gossip.Verify; it is an
// interface so tests can exercise JN's decode+route wiring without minting a
// full cosign envelope.
type EnvelopeVerifier interface {
	VerifyEnvelope(ctx context.Context, ev gossip.SignedEvent) error
}

// gossipEnvelopeVerifier is the production EnvelopeVerifier: gossip.Verify with
// a DID-backed OriginatorVerifier bound to the network's NetworkID.
type gossipEnvelopeVerifier struct {
	originator gossip.OriginatorVerifier
	networkID  cosign.NetworkID
}

func (g gossipEnvelopeVerifier) VerifyEnvelope(ctx context.Context, ev gossip.SignedEvent) error {
	return gossip.Verify(ctx, ev, g.originator, g.networkID)
}

// TreeHeadSource resolves the JN-trusted source tree head for a source-log DID,
// the trust anchor for ClassMerkle (cross-log inclusion) proof replay. A nil
// source ⇒ merkle findings cannot be verified and the router returns its
// missing-dependency error (fail-closed). monitoring.TrustedHeadStore satisfies
// it — JN's view of each peer log's head, advanced only by verified
// CosignedTreeHeads.
type TreeHeadSource interface {
	TrustedHead(sourceLogDID string) (types.TreeHead, bool)
}

// TileFetcherSource resolves a Static-CT tile fetcher for a source-log DID. The
// fetcher need not be trusted: a cross-log inclusion proof is RFC 6962-checked
// against the TRUSTED source head's RootHash, so wrong tiles produce a proof
// that fails the root check. The security anchor is the head (from
// TreeHeadSource), not the mirror. Unknown DID ⇒ (nil, false) ⇒ the merkle
// finding fails-closed at the router.
type TileFetcherSource interface {
	FetcherFor(sourceLogDID string) (tessera.TileFetcherFunc, bool)
}

// GossipVerifier runs the two-tier check. Construct via NewGossipVerifier;
// safe for concurrent use (the witness-set registry is concurrency-safe and
// every other field is read-only after construction).
// HeadWitnessSetResolver is the POSITION-AWARE witness-set resolution seam. It
// reconstructs, from the log, the witness set authoritative for a finding's
// head(s) so a finding is verified against the set that ACTUALLY cosigned it —
// not the live current-set snapshot (the position-blind gv.sets.Snapshot()
// path). A HISTORICAL (e.g. year-1) head therefore verifies against its era's
// set and is NOT mis-checked against the modern, rotated-away set (ZT-SCN-02).
//
// Two modes, matching findings.WitnessSetAnchor:
//
//   - SetForHead: head-anchored — the set a specific cosigned head satisfies.
//     Used for CosignedTreeHeadFinding (its own cosignatures identify the era,
//     correct across the operationally-fuzzy cosign switch).
//   - SetAt: position-anchored — the set authoritative at a log position. Used
//     for findings whose head(s) pin a TreeSize and where a head may be
//     adversarial (equivocation, SMT-replay) or span eras (history-rewrite); the
//     era is fixed by position, not by trusting a possibly-forged head.
//
// The auditor's journal-first store.JournalWitnessSetResolver satisfies it. Declared narrow at the consumer
// (Go structural typing) so gossipverify takes no dependency on the auditor's
// store package and there is no import cycle.
type HeadWitnessSetResolver interface {
	SetForHead(ctx context.Context, logDID string, head types.CosignedTreeHead) (*cosign.WitnessKeySet, error)
	SetAt(ctx context.Context, logDID string, asOf types.LogPosition) (*cosign.WitnessKeySet, error)
}

type GossipVerifier struct {
	envelope EnvelopeVerifier
	sets     *WitnessSetRegistry
	signer   findings.SignerVerifier
	heads    TreeHeadSource
	tiles    TileFetcherSource
	resolver HeadWitnessSetResolver // optional; nil ⇒ position-blind snapshot (legacy)
}

// GossipVerifierConfig configures a GossipVerifier.
type GossipVerifierConfig struct {
	// Originator + NetworkID build the default envelope verifier (gossip.Verify).
	// Required unless Envelope is supplied directly.
	Originator gossip.OriginatorVerifier
	NetworkID  cosign.NetworkID

	// Envelope overrides the default gossip.Verify-backed envelope check
	// (test injection). When nil, Originator + NetworkID are used.
	Envelope EnvelopeVerifier

	// WitnessSets is the live, monotonic witness-set registry. Required —
	// it is the trust root for every ClassWitness finding.
	WitnessSets *WitnessSetRegistry

	// SignerVerifier verifies ClassSigner findings (typically a
	// *did.VerifierRegistry). Optional; absent ⇒ signer findings fail-closed.
	SignerVerifier findings.SignerVerifier

	// Heads + Tiles enable ClassMerkle (cross-log inclusion). Both keyed by the
	// finding's own SourceLogDID. Optional; absent ⇒ merkle findings fail-closed
	// via the router's missing-dependency error.
	Heads TreeHeadSource
	Tiles TileFetcherSource

	// Resolver makes verification of EVERY head-bearing finding (the
	// findings.PositionAnchored class: cosigned-tree-head, equivocation,
	// SMT-replay, history-rewrite) POSITION-AWARE: each head is verified against
	// the set that cosigned it (reconstructed from the log), not the live
	// current-set snapshot — including the per-era path for a history-rewrite
	// that straddles a rotation. Optional; nil PRESERVES the legacy
	// position-blind behavior (verify against gv.sets.Snapshot()).
	Resolver HeadWitnessSetResolver
}

// NewGossipVerifier validates config and returns a GossipVerifier.
func NewGossipVerifier(cfg GossipVerifierConfig) (*GossipVerifier, error) {
	if cfg.WitnessSets == nil {
		return nil, fmt.Errorf("%w: nil WitnessSets registry", ErrGossipVerify)
	}
	env := cfg.Envelope
	if env == nil {
		if cfg.Originator == nil {
			return nil, fmt.Errorf("%w: nil Originator verifier (or supply Envelope)", ErrGossipVerify)
		}
		if cfg.NetworkID.IsZero() {
			return nil, fmt.Errorf("%w: zero NetworkID", ErrGossipVerify)
		}
		env = gossipEnvelopeVerifier{originator: cfg.Originator, networkID: cfg.NetworkID}
	}
	return &GossipVerifier{
		envelope: env,
		sets:     cfg.WitnessSets,
		signer:   cfg.SignerVerifier,
		heads:    cfg.Heads,
		tiles:    cfg.Tiles,
		resolver: cfg.Resolver,
	}, nil
}

// Verify runs Tier 1 (envelope) → decode → Tier 2 (finding proof) and returns
// the decoded, verified finding. A non-nil error means the event MUST be
// discarded — never acted on, never re-served.
//
// SourceLogDID is set to the envelope originator: correct for the originator-
// is-source Kinds (cosigned tree head, escrow override, witness rotation) and
// irrelevant to self-attested / signer / merkle Kinds. Equivocation findings
// whose reporter differs from the equivocating log are a documented follow-up
// (the SDK proof does not expose the target log as a DID).
func (gv *GossipVerifier) Verify(ctx context.Context, ev gossip.SignedEvent) (gossip.Event, error) {
	// Tier 1: envelope authenticity.
	if err := gv.envelope.VerifyEnvelope(ctx, ev); err != nil {
		return nil, fmt.Errorf("%w: envelope: %w", ErrGossipVerify, err)
	}
	// Decode the body into a typed finding (fail-closed on unknown/malformed).
	event, err := findings.FromWire(ev.Kind, ev.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGossipVerify, err)
	}
	// Tier 2: finding proof against LOCAL trust roots.
	vc := findings.VerificationContext{
		SourceLogDID:   ev.Originator,
		WitnessSets:    gv.sets.Snapshot(),
		SignerVerifier: gv.signer,
	}
	// ClassMerkle (cross-log inclusion) anchors on the SOURCE log named INSIDE
	// the finding — which may differ from the gossip originator that relayed
	// it. Resolve the trusted head + tile fetcher by the finding's own
	// SourceLogDID so a relayed attestation is checked against the source log
	// JN independently trusts, not against the relayer.
	if cli, ok := event.(*findings.CrossLogInclusionFinding); ok {
		if gv.heads != nil {
			if head, ok := gv.heads.TrustedHead(cli.SourceLogDID); ok {
				vc.SourceHead = head
			}
		}
		if gv.tiles != nil {
			if fetcher, ok := gv.tiles.FetcherFor(cli.SourceLogDID); ok {
				vc.TileFetcher = fetcher
			}
		}
	}
	// POSITION-AWARE witness-set resolution for ANY head-bearing finding (the
	// whole findings.PositionAnchored class — cosigned-tree-head, equivocation,
	// SMT-replay, history-rewrite), not just one Kind. Each finding declares its
	// anchor head(s)/position(s); we resolve the set that ACTUALLY cosigned each
	// from the log and verify against THOSE, not the position-blind current-set
	// snapshot — the fix for a HISTORICAL (e.g. year-1) head/equivocation being
	// mis-verified against the modern, rotated-away set (ZT-SCN-02).
	//
	//   - Single-era finding (one resolved set): override that set in the
	//     snapshot copy and let the ordinary dispatch verify it.
	//   - Multi-era finding (history-rewrite straddling a rotation): the
	//     single-set dispatch cannot carry two era sets, so verify per era via
	//     MultiEraWitnessAttested.VerifyEra directly.
	//
	// Failure to resolve is NON-FATAL: fall back to the snapshot (legacy path) so
	// a transient ledger/scan hiccup degrades to current-set verification rather
	// than dropping a finding. nil resolver ⇒ legacy behavior unchanged.
	// findings.WitnessRotationFinding deliberately does NOT implement
	// PositionAnchored (no cosigned head; historical reconstruction is the
	// scan-rebuild path's job), so it stays on the snapshot here.
	if pa, ok := event.(findings.PositionAnchored); ok && gv.resolver != nil {
		if sets, resolved := gv.resolveAnchors(ctx, ev.Originator, pa.WitnessSetAnchors()); resolved {
			if me, ok := event.(findings.MultiEraWitnessAttested); ok {
				// Multi-era: dispatch's single set can't express two eras.
				if verr := me.VerifyEra(sets); verr != nil {
					return nil, fmt.Errorf("%w: finding: %w", ErrGossipVerify, verr)
				}
				return event, nil
			}
			// Single-era: override the set the dispatch will look up (keyed by
			// SourceLogDID = originator). Copy-on-write so we never mutate the
			// shared snapshot.
			overridden := make(map[string]*cosign.WitnessKeySet, len(vc.WitnessSets)+1)
			for k, v := range vc.WitnessSets {
				overridden[k] = v
			}
			overridden[ev.Originator] = sets[0]
			vc.WitnessSets = overridden
		}
	}
	if err := findings.Verify(ctx, event, vc); err != nil {
		return nil, fmt.Errorf("%w: finding: %w", ErrGossipVerify, err)
	}
	return event, nil
}

// resolveAnchors resolves one era-correct witness set per finding anchor via the
// position-aware resolver. originator is the fallback log DID for an anchor that
// names none (originator-is-source, e.g. cosigned-tree-head). Returns
// (sets, true) only when EVERY anchor resolved to a non-nil set; any miss/error
// returns (_, false) so the caller falls back to the snapshot — non-fatal, never
// a dropped finding. A forged/wrong anchor LogDID can only land here (a resolver
// miss), never as a false accept (the cosignature check against the resolved set
// is the gate).
func (gv *GossipVerifier) resolveAnchors(ctx context.Context, originator string, anchors []findings.WitnessSetAnchor) ([]*cosign.WitnessKeySet, bool) {
	if len(anchors) == 0 {
		return nil, false
	}
	out := make([]*cosign.WitnessKeySet, len(anchors))
	for i, a := range anchors {
		logDID := a.LogDID
		if logDID == "" {
			logDID = originator
		}
		var (
			set *cosign.WitnessKeySet
			err error
		)
		switch a.Mode {
		case findings.AnchorByHead:
			set, err = gv.resolver.SetForHead(ctx, logDID, a.Head)
		case findings.AnchorByPosition:
			if a.Size == 0 {
				return nil, false // no head has TreeSize 0 → unresolvable
			}
			// A head at TreeSize T was cosigned by the set authoritative at its
			// highest included sequence (T-1); a rotation leaf at exactly T is not
			// yet in the head.
			set, err = gv.resolver.SetAt(ctx, logDID, types.LogPosition{LogDID: logDID, Sequence: a.Size - 1})
		default:
			return nil, false
		}
		if err != nil || set == nil {
			return nil, false
		}
		out[i] = set
	}
	return out, true
}
