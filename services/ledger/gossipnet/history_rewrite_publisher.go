/*
FILE PATH: gossipnet/history_rewrite_publisher.go

HistoryRewritePublisher signs + broadcasts a
KindHistoryRewriteFinding event for a detected, cryptographically-
verified history-rewrite (cross-TreeSize append-only violation —
SDK plan §I.2 / §I.13).

Sibling of gossipnet/equivocation_publisher.go and gossipnet/
smt_replay_publisher.go. Same Verify-before-Publish discipline;
same Sign / Append / Broadcast pipeline; emits a distinct Kind so
audit dashboards filter by offence class.

# DETECTION CLASS

History rewrite is the offence where TWO cosigned tree heads carry:

  - DIFFERENT TreeSize (oldHead.TreeSize < newHead.TreeSize)
  - K-of-N cosignatures on both sides
  - A consistency proof bytes supplied by the suspect ledger that
    FAILS RFC 6962 verification under (oldHead.RootHash,
    newHead.RootHash)

This is the canonical Certificate-Transparency append-only-
violation class. Distinct from equivocation (same TreeSize,
different RootHash) and SMT replay (same size + RootHash,
different SMTRoot) — the SDK ships separate Kinds so audit
pipelines can route each offence to the appropriate dashboard.

# VERIFY-BEFORE-PUBLISH DISCIPLINE

findings.HistoryRewriteFinding is the wire-shape adapter; NOT
cryptographic evidence by itself. .Verify(set) re-runs both
heads' cosignature K-of-N AND re-runs RFC 6962 consistency
verification against the failing proof bytes. Returns nil only
on full failure (i.e., the proof is genuinely failing — the
network's wire bytes prove a rewrite). Callers MUST observe
Verify == nil before invoking Publish.

The only call site is gossipnet/equivocation_monitor.go's
checkPeer flow — which always Verify-s before publishing.

Plan §II Post-Part-II #2 (issue #152).
*/
package gossipnet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
)

// HistoryRewritePublisher emits KindHistoryRewriteFinding events
// to the gossip Sink for cryptographically-verified history-rewrite
// proofs. Stateless — chain-discipline state is read from the
// Store on every publish (parallel shape to EquivocationPublisher
// and SMTReplayPublisher).
type HistoryRewritePublisher struct {
	store      sdkgossip.Store
	sink       sdkgossip.Sink
	signer     sdkcosign.WitnessSigner
	networkID  sdkcosign.NetworkID
	originator string
	logger     *slog.Logger
}

// HistoryRewritePublisherConfig configures the publisher. Fields
// parallel SMTReplayPublisherConfig exactly — the publisher is the
// same shape but emits a different Kind. Operators SHOULD supply
// the same (Originator, Signer) tuple as the equivocation +
// smt-replay publishers so the ledger's chain in the gossip Store
// covers all of its own emissions under one originator.
type HistoryRewritePublisherConfig struct {
	Store     sdkgossip.Store
	Sink      sdkgossip.Sink
	Signer    sdkcosign.WitnessSigner
	NetworkID sdkcosign.NetworkID

	// Originator is the ledger's own DID. Same DID used for the
	// other publishers; the gossip Store maintains one chain per
	// originator regardless of Kind.
	Originator string

	Logger *slog.Logger
}

// NewHistoryRewritePublisher constructs the publisher. Returns an
// error when any required field is missing.
func NewHistoryRewritePublisher(cfg HistoryRewritePublisherConfig) (*HistoryRewritePublisher, error) {
	// NetworkID FIRST — see NewSTHPublisher for the same rationale
	// (T-9 cryptographic domain separation is the security
	// invariant; everything else is correctness).
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet/history_rewrite: NetworkID required (non-zero)")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/history_rewrite: Store required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("gossipnet/history_rewrite: Sink required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("gossipnet/history_rewrite: Signer required")
	}
	if cfg.Originator == "" {
		return nil, fmt.Errorf("gossipnet/history_rewrite: Originator required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &HistoryRewritePublisher{
		store:      cfg.Store,
		sink:       cfg.Sink,
		signer:     cfg.Signer,
		networkID:  cfg.NetworkID,
		originator: cfg.Originator,
		logger:     cfg.Logger,
	}, nil
}

// Publish signs the (already-verified) history-rewrite finding as
// a KindHistoryRewriteFinding event, appends it to the local
// Store, and broadcasts it to peers via the Sink.
//
// Errors are logged + swallowed: the verification (already
// performed by the caller before calling Publish) is the
// authoritative event; gossip transport is best-effort.
//
// CONTRACT: callers MUST have called finding.Verify(set) and
// observed nil before invoking Publish. This publisher trusts the
// call site rather than the type system (parallel to
// EquivocationPublisher / SMTReplayPublisher).
func (p *HistoryRewritePublisher) Publish(ctx context.Context, finding *findings.HistoryRewriteFinding) {
	if p == nil {
		return
	}
	if finding == nil {
		panic("gossipnet/history_rewrite: nil finding (programmer error)")
	}

	prev, lamport, err := p.store.Head(ctx, p.originator)
	if err != nil {
		p.logger.Warn("history_rewrite publisher: read head failed", "error", err)
		return
	}
	nextLamport := lamport + 1
	if lamport == 0 {
		nextLamport = 1
	}

	signed, err := sdkgossip.Sign(ctx, finding,
		p.signer, p.networkID, p.originator, prev, nextLamport)
	if err != nil {
		p.logger.Warn("history_rewrite publisher: sign failed", "error", err)
		return
	}

	if err := p.store.Append(ctx, signed); err != nil {
		if errors.Is(err, sdkgossip.ErrChainBreak) || errors.Is(err, sdkgossip.ErrLamportRegression) {
			p.logger.Warn("history_rewrite publisher: local Append rejected; head moved underneath",
				"error", err)
			return
		}
		p.logger.Warn("history_rewrite publisher: local Append failed", "error", err)
		return
	}

	if err := p.sink.Broadcast(ctx, signed); err != nil {
		p.logger.Warn("history_rewrite publisher: fan-out failed (peers will catch up via /since)",
			"error", err)
		return
	}

	p.logger.Error("HISTORY REWRITE PUBLISHED",
		"valid_sigs_old", finding.Proof.ValidSigsOld,
		"valid_sigs_new", finding.Proof.ValidSigsNew,
		"old_tree_size", finding.Proof.OldHead.TreeSize,
		"new_tree_size", finding.Proof.NewHead.TreeSize,
		"old_root", fmt.Sprintf("%x", finding.Proof.OldHead.RootHash[:8]),
		"new_root", fmt.Sprintf("%x", finding.Proof.NewHead.RootHash[:8]),
		"proof_len", len(finding.Proof.ConsistencyProof),
		"ledger_endpoint", finding.LedgerEndpoint,
		"lamport", nextLamport,
	)
}
