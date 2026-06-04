/*
FILE PATH: gossipnet/equivocation_monitor.go

EquivocationMonitor compares the local view of an originator's
latest STH against each peer's view. On divergence it constructs
a *findings.EquivocationFinding, verifies it (K-of-N from
*cosign.WitnessKeySet) and hands it to the EquivocationPublisher.

# WHY THIS REPLACES witness/equivocation_monitor.go

The legacy ledger monitor fetched /v1/tree/head — an endpoint
that returns tree_size + root_hash but NO witness signatures.
Without the cosignatures, the legacy monitor could detect SUSPECT
equivocation but could not produce cryptographic evidence — a
mere finger-pointing JSON document with no quorum-witness backing.

The /v1/gossip/sth/latest endpoint mounted in W5 returns the full
SignedEvent, whose body carries the complete types.CosignedTreeHead
including K-of-N signatures. Building the monitor on the gossip
feed gives us cryptographic proofs from the wire — no manual sig
plumbing on our side.

# v0.1.1 API SHAPE

The witness keys, NetworkID, K-of-N quorum, and BLS verifier
are all encapsulated in *cosign.WitnessKeySet (constructed at
boot in cmd/ledger/main.go from LEDGER_WITNESS_QUORUM_K +
genesis witness DIDs). The previous (witnessKeys, quorumK,
networkID, blsVerifier) parameter group is collapsed into one
field. witness.DetectEquivocation, finding.Verify, and the
underlying cosign.Verify primitive all read K from set.Quorum().

# DETECTION ALGORITHM

For each (peer, originator) pair where:

  - peer is one of LEDGER_GOSSIP_PEER_ENDPOINTS
  - originator is the peer's own DID (the peer might equivocate
    by publishing different heads to different audiences)

Per tick:

 1. Fetch peer.LatestSTH(originatorDID) via gossip.Client. Decode
    the SignedEvent body to extract types.CosignedTreeHead with
    full signatures.
 2. Fetch our local Store.LatestSTH(originatorDID). Decode same
    way.
 3. If both exist, both at the same tree_size, but different
    root_hash → call witness.DetectEquivocation(headA, headB, set).
    The SDK helper verifies BOTH heads against the WitnessKeySet
    at K-of-N (read from set.Quorum()) and returns
    *witness.EquivocationProof on success.
 4. Wrap in findings.NewEquivocationFinding, call .Verify(set)
    to confirm cryptographic admissibility of the wire-shape
    finding (independent of step 3 — Verify guards the publish
    contract; DetectEquivocation guards the detection contract).
 5. Publish via EquivocationPublisher (signs as
    KindEquivocationFinding + appends + broadcasts).

# FALSE-POSITIVE GATE

DetectEquivocation returns nil for:

  - Equal root hashes (no equivocation)
  - Different tree sizes (not equivocation; out-of-sync clocks
    or just different commit progress)
  - Heads with insufficient signatures (cannot prove anything)

The verification gate also fires on:

  - Heads signed under a different NetworkID
  - Heads with signatures from non-witness-set keys
  - Heads where K-of-N is not reached for either side

This monitor only ever publishes verified evidence. The Verify-
before-Publish contract (see EquivocationPublisher.Publish doc)
is enforced by this monitor's checkPeer flow.

# CADENCE

Default 60s tick. Slower than anti-entropy because equivocation
is a rare-but-catastrophic event; rapid polling would consume
peer-side rate-limit budget without proportional value.
*/
package gossipnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	sdkwitness "github.com/baseproof/baseproof/witness"
)

// DefaultEquivocationInterval is the default poll period.
const DefaultEquivocationInterval = 60 * time.Second

// WitnessKeySetProvider yields the active witness key set. Implemented
// by *quorum.Manager; the monitor reads Current() on each poll so a
// witness rotation is observed without rebuilding the monitor.
type WitnessKeySetProvider interface {
	Current() *sdkcosign.WitnessKeySet
}

// EquivocationMonitorConfig configures the equivocation monitor.
//
// v0.1.1 SHAPE: WitnessKeys / QuorumK / NetworkID / BLSVerifier
// are collapsed into a single WitnessSet *cosign.WitnessKeySet
// field. The constructor at cmd/ledger/main.go calls
// cosign.NewWitnessKeySet(witKeys, networkID, quorumK, blsVerifier)
// once at boot and passes the result here.
type EquivocationMonitorConfig struct {
	// Store is the local gossip Store. Required. Used for
	// LatestSTH(originator) lookups against the ledger's own
	// chain history.
	Store sdkgossip.Store

	// Peers is the set of peers to compare against. Same shape
	// as the anti-entropy config; reusing the type keeps the
	// ledger's peer config consistent across the two loops.
	// Empty disables the monitor (Run returns immediately).
	Peers []AntiEntropyPeer

	// WitnessKeys yields the active *cosign.WitnessKeySet the monitor
	// verifies cosignatures against (witness public keys, NetworkID,
	// K-of-N quorum threshold, BLS aggregate verifier). Read via
	// Current() on every poll so a witness rotation is observed live;
	// the shared quorum.Manager satisfies this. Required (non-nil).
	WitnessKeys WitnessKeySetProvider

	// Publisher is the egress hook. nil disables publishing —
	// detected equivocations are logged but not broadcast (useful
	// for observe-only monitors).
	Publisher *EquivocationPublisher

	// SMTReplayPublisher is the egress hook for the SMT-replay
	// detection branch (plan §II.4 / §I.13). nil disables
	// SMT-replay publishing — the monitor still detects + logs,
	// but does not broadcast a KindSMTReplayFinding event. Same
	// observe-only semantics as Publisher above.
	//
	// SMT replay is the same-TreeSize + same-RootHash +
	// different-SMTRoot case: chronological log is honest, derived
	// state is forged. Distinct from equivocation (same size,
	// different RootHash) and history-rewrite (different sizes,
	// failing consistency proof) — the SDK ships separate Kinds
	// so audit pipelines can route each offence to the
	// appropriate dashboard.
	SMTReplayPublisher *SMTReplayPublisher

	// HistoryRewritePublisher is the egress hook for the
	// history-rewrite detection branch (post-Part-II #2 / issue
	// #152). nil disables history-rewrite publishing — the
	// monitor still detects + logs, but does not broadcast a
	// KindHistoryRewriteFinding event. Same observe-only
	// semantics as Publisher / SMTReplayPublisher above.
	//
	// History rewrite is the cross-TreeSize case: the suspect
	// ledger's CLAIMED consistency proof from OldHead → NewHead
	// FAILS RFC 6962 verification. The monitor fetches the
	// proof bytes via the peer's GET /v1/tree/consistency/{old}/
	// {new} (with consistencyClient), passes them to
	// sdkwitness.DetectHistoryRewrite, and publishes on success.
	//
	// HistoryRewritePublisher requires the peer to expose the
	// /v1/tree/consistency endpoint and to be willing to serve
	// the failing proof bytes. A peer that REFUSES to serve the
	// proof (e.g., returns 503) is not detectable via this
	// branch — but the FAILURE to serve is itself a Tier-1
	// alarm operators surface elsewhere.
	HistoryRewritePublisher *HistoryRewritePublisher

	// Interval is the tick period. 0 ⇒ DefaultEquivocationInterval.
	Interval time.Duration

	// HTTPClient is the per-peer HTTP client used for outbound
	// equivocation polls. REQUIRED — nil is rejected at construction
	// (see baseproof v1.34 CHANGELOG: the SDK no longer manufactures
	// a plaintext default). Production callers should pass
	// sdklog.DefaultClient(20*time.Second, tlsCfg).
	HTTPClient *http.Client

	Logger *slog.Logger
}

// EquivocationMonitor polls peers for STH divergence.
type EquivocationMonitor struct {
	store                   sdkgossip.Store
	peers                   []equivocationPeerInternal
	keys                    WitnessKeySetProvider
	publisher               *EquivocationPublisher
	smtReplayPublisher      *SMTReplayPublisher
	historyRewritePublisher *HistoryRewritePublisher
	httpClient              *http.Client
	interval                time.Duration
	logger                  *slog.Logger
}

type equivocationPeerInternal struct {
	did    string
	url    string
	client sdkgossip.Client
}

// NewEquivocationMonitor constructs the monitor. Returns an error
// when any required field is missing.
func NewEquivocationMonitor(cfg EquivocationMonitorConfig) (*EquivocationMonitor, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/equivocation_monitor: Store required")
	}
	if cfg.WitnessKeys == nil {
		return nil, fmt.Errorf(
			"gossipnet/equivocation_monitor: WitnessKeys required " +
				"(pass the shared quorum.Manager)")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultEquivocationInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// v1.34 contract: caller MUST supply HTTPClient. The boot wiring
	// always populates d.OutboundHTTPClient (see
	// cmd/ledger/boot/wire/wire.go); a nil here means a programming
	// error in a caller that constructed EquivocationMonitorConfig{}
	// by hand. Fail-closed.
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("gossipnet/equivocation_monitor: HTTPClient required (pass cfg.HTTPClient — the SDK no longer manufactures a plaintext default)")
	}
	httpClient := cfg.HTTPClient

	peers := make([]equivocationPeerInternal, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		if p.DID == "" || p.BaseURL == "" {
			return nil, fmt.Errorf(
				"gossipnet/equivocation_monitor: peer DID and BaseURL required (got %+v)", p)
		}
		client, err := sdkgossip.NewClient(p.BaseURL,
			sdkgossip.WithHTTPClient(httpClient))
		if err != nil {
			return nil, fmt.Errorf(
				"gossipnet/equivocation_monitor: NewClient(%s): %w", p.BaseURL, err)
		}
		peers = append(peers, equivocationPeerInternal{
			did: p.DID, url: p.BaseURL, client: client,
		})
	}

	return &EquivocationMonitor{
		store:                   cfg.Store,
		peers:                   peers,
		keys:                    cfg.WitnessKeys,
		publisher:               cfg.Publisher,
		smtReplayPublisher:      cfg.SMTReplayPublisher,
		historyRewritePublisher: cfg.HistoryRewritePublisher,
		httpClient:              httpClient,
		interval:                cfg.Interval,
		logger:                  cfg.Logger,
	}, nil
}

// Run drives the monitor until ctx is cancelled. Returns ctx.Err()
// on cancellation. No-op when no peers are configured.
func (m *EquivocationMonitor) Run(ctx context.Context) error {
	if len(m.peers) == 0 {
		m.logger.Info("equivocation monitor: no peers configured; loop disabled")
		return nil
	}
	quorumK, setSize := 0, 0
	if set := m.keys.Current(); set != nil {
		quorumK, setSize = set.Quorum(), set.Size()
	}
	m.logger.Info("equivocation monitor: started",
		"peers", len(m.peers),
		"interval", m.interval,
		"quorum_k", quorumK,
		"witness_set_size", setSize,
		"publisher_wired", m.publisher != nil,
	)

	t := time.NewTicker(m.interval)
	defer t.Stop()

	// Initial tick on startup so a fresh boot doesn't wait the
	// full interval before the first comparison.
	m.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("equivocation monitor: stopped")
			return ctx.Err()
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// tick runs one comparison pass over every peer. Per-peer errors
// are logged but never propagated; one bad peer cannot break
// detection on healthy peers.
func (m *EquivocationMonitor) tick(ctx context.Context) {
	for _, p := range m.peers {
		m.checkPeer(ctx, p)
	}
}

// checkPeer fetches one peer's view of its own STH and compares
// against our local view of the same originator. On divergence
// → run DetectEquivocation, then verify-then-publish.
func (m *EquivocationMonitor) checkPeer(ctx context.Context, p equivocationPeerInternal) {
	// Snapshot the active witness set once per check — a rotation
	// mid-loop is observed on the next tick. nil ⇒ no genesis set; we
	// cannot verify cosignatures, so skip rather than crash.
	set := m.keys.Current()
	if set == nil {
		m.logger.Warn("equivocation monitor: no active witness key set; skipping check",
			"peer", p.url)
		return
	}

	peerEvent, peerFound, err := p.client.LatestSTH(ctx, p.did)
	if err != nil {
		if errors.Is(err, sdkgossip.ErrRateLimited) {
			retryAfter, _ := sdkgossip.RetryAfterFromError(err)
			m.logger.Info("equivocation monitor: peer rate-limited",
				"peer", p.url, "retry_after", retryAfter)
			return
		}
		m.logger.Warn("equivocation monitor: peer LatestSTH failed",
			"peer", p.url, "error", err)
		return
	}
	if !peerFound {
		return // peer has no STH for that originator yet
	}
	peerHead, err := decodeSTHFromEvent(peerEvent)
	if err != nil {
		m.logger.Warn("equivocation monitor: decode peer STH failed",
			"peer", p.url, "error", err)
		return
	}

	localEvent, localFound, err := m.store.LatestSTH(ctx, p.did)
	if err != nil {
		m.logger.Warn("equivocation monitor: local LatestSTH failed",
			"peer", p.url, "error", err)
		return
	}
	if !localFound {
		// We don't have any STH for this peer yet — anti-entropy
		// will fetch the peer's chain over time. No comparison
		// possible this tick.
		return
	}
	localHead, err := decodeSTHFromEvent(localEvent)
	if err != nil {
		m.logger.Warn("equivocation monitor: decode local STH failed",
			"peer", p.url, "error", err)
		return
	}

	// Compare. DetectEquivocation handles the "same root" and
	// "different sizes" cases internally — we don't pre-filter.
	// K, networkID, blsVerifier all live in the snapshotted set.
	proof, err := sdkwitness.DetectEquivocation(localHead, peerHead, set)
	if err != nil {
		// A non-equivocation outcome is signalled by err == nil
		// + proof == nil. err != nil means a verification or
		// structural failure on at least one head.
		if errors.Is(err, sdkwitness.ErrDifferentSizes) {
			// Different sizes is NOT equivocation — but it MAY
			// be history-rewrite (cross-TreeSize append-only
			// violation). Fall through to the history-rewrite
			// branch, which fetches the peer's claimed
			// consistency proof and re-runs the SDK detector.
			m.tryHistoryRewrite(ctx, p, localHead, peerHead, set)
			return
		}
		m.logger.Warn("equivocation monitor: DetectEquivocation failed",
			"peer", p.url, "error", err)
		return
	}
	if proof != nil {
		m.handleEquivocationProof(ctx, p, localHead, peerHead, set, proof)
		return
	}

	// No equivocation (RootHashes match). Try the SMT-replay
	// branch — same TreeSize + same RootHash + different SMTRoot.
	// This is the orthogonal "log honest, state forged" offence
	// (plan §I.2 / §I.13 / §II.4). DetectSMTReplay returns
	// (nil, nil) when SMTRoots match (no offence), and routes
	// ErrSMTReplayRootHashDiffers / ErrDifferentSizes as the
	// "wrong detector" sentinels — but DetectEquivocation already
	// claimed neither case applies, so we expect a clean shape here.
	smtProof, err := sdkwitness.DetectSMTReplay(localHead, peerHead, set)
	if err != nil {
		// Skip the "wrong detector" sentinels; surface real
		// verification failures.
		if errors.Is(err, sdkwitness.ErrDifferentSizes) ||
			errors.Is(err, sdkwitness.ErrSMTReplayRootHashDiffers) {
			return
		}
		m.logger.Warn("equivocation monitor: DetectSMTReplay failed",
			"peer", p.url, "error", err)
		return
	}
	if smtProof == nil {
		return // SMTRoots match — no divergence at all
	}
	m.handleSMTReplayProof(ctx, p, localHead, peerHead, set, smtProof)
}

// handleEquivocationProof packages a witness.EquivocationProof into
// a wire-shape finding, verifies its cosignatures via
// findings.Verify(set), logs the offence, and (if the publisher is
// wired) emits a KindEquivocationFinding event. Same shape as the
// SMT-replay sibling below — both follow Verify-before-Publish.
func (m *EquivocationMonitor) handleEquivocationProof(
	ctx context.Context, p equivocationPeerInternal,
	localHead, peerHead types.CosignedTreeHead,
	set *sdkcosign.WitnessKeySet,
	proof *sdkwitness.EquivocationProof,
) {
	// Hand the proof to the wire-shape constructor + verifier.
	// Verify(set) returns nil iff cosignatures pass K-of-N on
	// both heads. The publish contract requires the caller to
	// have observed Verify == nil before invoking Publish; we
	// enforce that here.
	finding, err := findings.NewEquivocationFinding(*proof, p.url)
	if err != nil {
		m.logger.Warn("equivocation monitor: NewEquivocationFinding rejected proof",
			"peer", p.url, "error", err)
		return
	}
	// Position-aware routing hint: the equivocating log (p.did) is the slash
	// target, and it differs from the gossip originator that relays this finding.
	// It lets a position-aware consumer resolve p.did's ERA-CORRECT witness set
	// (the heads may have been cosigned by a since-rotated-away set) instead of
	// the current snapshot. UNSIGNED — not in CanonicalBytes; a wrong value only
	// costs a resolver miss, never a false accept (the cosignature check against
	// the resolved set is the gate). See SDK gossip/findings/position_anchored.go.
	finding.TargetLogDID = p.did
	if err := finding.Verify(set); err != nil {
		m.logger.Warn("equivocation monitor: Verify rejected finding",
			"peer", p.url, "error", err)
		return
	}

	// Surface SMTRoot in the equivocation alarm too: a divergence
	// between local + peer SMTRoot at the same TreeSize is an
	// equivocation in its own right — two parties cannot have
	// consistent ledger projections diverge at the same chronological
	// position. The witness K-of-N cosignature binds both roots
	// (SDK v0.8.0+), so the underlying cosign.Verify path already
	// rejects a forged pair; logging both fields helps SREs
	// distinguish RootHash drift (Tessera/log-side) from SMTRoot
	// drift (state-projection-side) during forensics.
	m.logger.Error("EQUIVOCATION DETECTED",
		"peer", p.url,
		"originator", p.did,
		"tree_size", proof.TreeSize,
		"local_root", fmt.Sprintf("%x", localHead.RootHash[:8]),
		"peer_root", fmt.Sprintf("%x", peerHead.RootHash[:8]),
		"local_smt_root", fmt.Sprintf("%x", localHead.SMTRoot[:8]),
		"peer_smt_root", fmt.Sprintf("%x", peerHead.SMTRoot[:8]),
		"valid_sigs_a", proof.ValidSigsA,
		"valid_sigs_b", proof.ValidSigsB,
	)

	if m.publisher != nil {
		m.publisher.Publish(ctx, finding)
	}
}

// handleSMTReplayProof packages a witness.SMTReplayProof into a
// wire-shape KindSMTReplayFinding, verifies its cosignatures via
// findings.Verify(set), logs the offence, and (if the SMT-replay
// publisher is wired) emits the event.
//
// Distinct from handleEquivocationProof so audit pipelines can
// route findings by Kind — SMT-replay alerts go to the
// state-derivation dashboard, equivocation to the same-size fork
// dashboard. Plan §II.4.
func (m *EquivocationMonitor) handleSMTReplayProof(
	ctx context.Context, p equivocationPeerInternal,
	localHead, peerHead types.CosignedTreeHead,
	set *sdkcosign.WitnessKeySet,
	proof *sdkwitness.SMTReplayProof,
) {
	finding, err := findings.NewSMTReplayFinding(*proof, p.url)
	if err != nil {
		m.logger.Warn("equivocation monitor: NewSMTReplayFinding rejected proof",
			"peer", p.url, "error", err)
		return
	}
	// Position-aware routing hint (see handleEquivocationProof): the SMT-replaying
	// log p.did is the slash target, distinct from the relaying originator. UNSIGNED.
	finding.TargetLogDID = p.did
	if err := finding.Verify(set); err != nil {
		m.logger.Warn("equivocation monitor: SMTReplay Verify rejected finding",
			"peer", p.url, "error", err)
		return
	}

	m.logger.Error("SMT REPLAY DETECTED",
		"peer", p.url,
		"originator", p.did,
		"tree_size", proof.TreeSize,
		"root_hash", fmt.Sprintf("%x", proof.RootHash[:8]),
		"local_smt_root", fmt.Sprintf("%x", localHead.SMTRoot[:8]),
		"peer_smt_root", fmt.Sprintf("%x", peerHead.SMTRoot[:8]),
		"valid_sigs_a", proof.ValidSigsA,
		"valid_sigs_b", proof.ValidSigsB,
	)

	if m.smtReplayPublisher != nil {
		m.smtReplayPublisher.Publish(ctx, finding)
	}
}

// tryHistoryRewrite is the history-rewrite detection branch of
// checkPeer. Reached when DetectEquivocation returned
// ErrDifferentSizes — i.e., local and peer disagree on TreeSize.
// This is NOT equivocation by itself; an append-only log can have
// different sizes at different observation points. It IS history
// rewrite IFF the suspect ledger's CLAIMED consistency proof
// from the smaller head → larger head FAILS RFC 6962 verification.
//
// Flow:
//  1. Normalize old/new ordering (smaller TreeSize → old).
//  2. Fetch the suspect's consistency proof via
//     GET /v1/tree/consistency/{old}/{new} on the peer's base URL.
//     A peer that refuses to serve the proof is NOT detectable
//     here (the failure to serve is itself an alarm operators
//     surface via different telemetry).
//  3. Call sdkwitness.DetectHistoryRewrite(old, new, proof, set).
//     On (nil, nil) the proof verifies successfully → log is
//     consistent, no offence. On (*proof, nil) the proof FAILS →
//     proven append-only violation.
//  4. Wrap, Verify(set) re-runs offline check, Publish.
//
// Plan: post-Part-II #2 (issue #152).
func (m *EquivocationMonitor) tryHistoryRewrite(
	ctx context.Context,
	p equivocationPeerInternal,
	localHead, peerHead types.CosignedTreeHead,
	set *sdkcosign.WitnessKeySet,
) {
	// Normalize: oldHead has the smaller TreeSize. The SDK's
	// DetectHistoryRewrite documents "the ledger's claim from
	// OldHead.TreeSize → NewHead.TreeSize is inconsistent" — the
	// proof is fetched between those two sizes.
	oldHead, newHead := localHead, peerHead
	if oldHead.TreeSize > newHead.TreeSize {
		oldHead, newHead = newHead, oldHead
	}
	if oldHead.TreeSize == newHead.TreeSize {
		// Defense-in-depth — the caller's DetectEquivocation
		// returned ErrDifferentSizes, so this can't happen, but
		// a future refactor flipping the caller's check would
		// surface here rather than calling DetectHistoryRewrite
		// with invalid input.
		return
	}

	proofBytes, err := FetchConsistencyProof(ctx, m.httpClient,
		p.url, oldHead.TreeSize, newHead.TreeSize)
	if err != nil {
		// A peer that won't serve a consistency proof is not
		// proof of rewrite — log + move on. Tier-1 alarming on
		// "peer refused to serve" lives in different telemetry.
		m.logger.Info("equivocation monitor: consistency proof fetch failed (peer refused or unreachable)",
			"peer", p.url, "old_size", oldHead.TreeSize, "new_size", newHead.TreeSize, "error", err)
		return
	}

	proof, err := sdkwitness.DetectHistoryRewrite(oldHead, newHead, proofBytes, set)
	if err != nil {
		// ErrSameTreeSize / cosignature-insufficient errors are
		// structural — log and move on. The peer may have a
		// transiently bad cosignature quorum.
		m.logger.Warn("equivocation monitor: DetectHistoryRewrite failed",
			"peer", p.url, "error", err)
		return
	}
	if proof == nil {
		// Consistency proof verified successfully → the log is
		// append-only consistent across the size delta. No
		// offence. This is the expected normal-sync outcome.
		return
	}

	m.handleHistoryRewriteProof(ctx, p, oldHead, newHead, set, proof)
}

// handleHistoryRewriteProof packages a witness.HistoryRewriteProof
// into a wire-shape KindHistoryRewriteFinding, verifies its
// cosignatures + the failing-proof re-check via
// findings.Verify(set), logs the offence, and (if the
// history-rewrite publisher is wired) emits the event.
//
// Distinct from handleEquivocationProof / handleSMTReplayProof so
// audit pipelines can route findings by Kind — history-rewrite
// alerts go to the append-only-violation dashboard. Plan: post-
// Part-II #2 (issue #152).
func (m *EquivocationMonitor) handleHistoryRewriteProof(
	ctx context.Context,
	p equivocationPeerInternal,
	oldHead, newHead types.CosignedTreeHead,
	set *sdkcosign.WitnessKeySet,
	proof *sdkwitness.HistoryRewriteProof,
) {
	finding, err := findings.NewHistoryRewriteFinding(*proof, p.url)
	if err != nil {
		m.logger.Warn("equivocation monitor: NewHistoryRewriteFinding rejected proof",
			"peer", p.url, "error", err)
		return
	}
	// Position-aware routing hint (see handleEquivocationProof): the history-
	// rewriting log p.did is the slash target, distinct from the relaying
	// originator. Critical for the multi-era (cross-rotation) per-era resolve,
	// where OldHead/NewHead may sit under DIFFERENT witness sets. UNSIGNED.
	finding.TargetLogDID = p.did
	if err := finding.Verify(set); err != nil {
		m.logger.Warn("equivocation monitor: HistoryRewrite Verify rejected finding",
			"peer", p.url, "error", err)
		return
	}

	m.logger.Error("HISTORY REWRITE DETECTED",
		"peer", p.url,
		"originator", p.did,
		"old_tree_size", oldHead.TreeSize,
		"new_tree_size", newHead.TreeSize,
		"old_root", fmt.Sprintf("%x", oldHead.RootHash[:8]),
		"new_root", fmt.Sprintf("%x", newHead.RootHash[:8]),
		"proof_len", len(proof.ConsistencyProof),
		"valid_sigs_old", proof.ValidSigsOld,
		"valid_sigs_new", proof.ValidSigsNew,
	)

	if m.historyRewritePublisher != nil {
		m.historyRewritePublisher.Publish(ctx, finding)
	}
}

// decodeSTHFromEvent extracts the types.CosignedTreeHead from a
// SignedEvent of Kind=KindCosignedTreeHead. The body is the
// gossip.WireCosignedTreeHeadBody shape; pass through the
// findings.CosignedTreeHeadFromWire decoder.
func decodeSTHFromEvent(ev sdkgossip.SignedEvent) (types.CosignedTreeHead, error) {
	if ev.Kind != sdkgossip.KindCosignedTreeHead {
		return types.CosignedTreeHead{}, fmt.Errorf(
			"expected KindCosignedTreeHead, got %s", ev.Kind)
	}
	var wire sdkgossip.WireCosignedTreeHeadBody
	if err := json.Unmarshal(ev.Body, &wire); err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("decode wire body: %w", err)
	}
	finding, err := findings.CosignedTreeHeadFromWire(wire)
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("CosignedTreeHeadFromWire: %w", err)
	}
	return finding.Head, nil
}
