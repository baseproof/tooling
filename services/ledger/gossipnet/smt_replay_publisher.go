/*
FILE PATH: gossipnet/smt_replay_publisher.go

SMTReplayPublisher signs + broadcasts a KindSMTReplayFinding event
for a detected, cryptographically-verified SMT-replay equivocation
(SDK plan §I.2 / §I.13).

This file is the SMT-replay sibling of equivocation_publisher.go;
the two surfaces stay in lock-step because the SDK has THREE
finding classes (equivocation, history-rewrite, smt-replay) that
share the same publish discipline: Verify first, Publish second.

# DETECTION CLASS

SMT replay is the offence where TWO cosigned tree heads carry:

  - the SAME TreeSize
  - the SAME RootHash (chronological log roots agree)
  - DIFFERENT SMTRoot (state-derivation roots disagree)

This is the narrow case where the append-only chronological log
is honest but the derived-state projection has been forged or
replayed. Surfacing it as its own Kind lets operators route
SMT-replay findings through their state-derivation audit pipeline
rather than the broader fork-detection pipeline.

# VERIFY-BEFORE-PUBLISH DISCIPLINE

The SDK's findings.SMTReplayFinding is the wire-shape adapter;
NOT cryptographic evidence by itself. A peer producing two
unsigned conflicting heads + claiming "SMT replay" is noise, not
a proof. Verify(set) runs cosign.VerifyTreeHeadCosignatures
against both heads' signatures and the network's
*cosign.WitnessKeySet (K-of-N read from set.Quorum()) and returns
nil only on success. Callers MUST observe Verify == nil before
invoking Publish.

The only call site is gossipnet/equivocation_monitor.go's
checkPeer flow — which always Verify-s before publishing.

# OPERATIONAL FLOW

	monitor (gossipnet/equivocation_monitor.go)
	  │   detects local-vs-peer SMTRoot disagreement at the
	  │   same (TreeSize, RootHash)
	  │   reconstructs witness.SMTReplayProof
	  │   constructs findings.NewSMTReplayFinding(proof, ourEndpoint)
	  │   calls finding.Verify(set)
	  │     ↓ (only on cryptographic verification success — err == nil)
	  └── SMTReplayPublisher.Publish(finding)
	        ├── reads gossip.Store.Head() for chain-discipline state
	        ├── gossip.Sign as KindSMTReplayFinding
	        ├── gossip.Store.Append (local persistence)
	        └── gossip.Sink.Broadcast (fan-out via BufferedSink)

Plan §II.4.
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

// SMTReplayPublisher emits KindSMTReplayFinding events to the
// gossip Sink for cryptographically-verified SMT-replay proofs.
// Stateless — chain-discipline state is read from the Store on
// every publish (parallel shape to EquivocationPublisher).
type SMTReplayPublisher struct {
	store      sdkgossip.Store
	sink       sdkgossip.Sink
	signer     sdkcosign.WitnessSigner
	networkID  sdkcosign.NetworkID
	originator string
	logger     *slog.Logger
}

// SMTReplayPublisherConfig configures the publisher. Fields
// parallel EquivocationPublisherConfig exactly — the publisher is
// the same shape but emits a different Kind. Operators SHOULD
// supply the same (Originator, Signer) tuple as the equivocation
// publisher so the ledger's chain in the gossip Store covers all
// of its own emissions under one originator.
type SMTReplayPublisherConfig struct {
	Store     sdkgossip.Store
	Sink      sdkgossip.Sink
	Signer    sdkcosign.WitnessSigner
	NetworkID sdkcosign.NetworkID

	// Originator is the ledger's own DID. Same DID used for
	// STHPublisher / EquivocationPublisher; the gossip Store
	// maintains one chain per originator regardless of Kind.
	Originator string

	Logger *slog.Logger
}

// NewSMTReplayPublisher constructs the publisher. Returns an
// error when any required field is missing.
func NewSMTReplayPublisher(cfg SMTReplayPublisherConfig) (*SMTReplayPublisher, error) {
	// NetworkID FIRST — see NewSTHPublisher for the same rationale
	// (T-9 cryptographic domain separation is the security
	// invariant; everything else is correctness).
	var zero sdkcosign.NetworkID
	if cfg.NetworkID == zero {
		return nil, fmt.Errorf("gossipnet/smt_replay: NetworkID required (non-zero)")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("gossipnet/smt_replay: Store required")
	}
	if cfg.Sink == nil {
		return nil, fmt.Errorf("gossipnet/smt_replay: Sink required")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("gossipnet/smt_replay: Signer required")
	}
	if cfg.Originator == "" {
		return nil, fmt.Errorf("gossipnet/smt_replay: Originator required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SMTReplayPublisher{
		store:      cfg.Store,
		sink:       cfg.Sink,
		signer:     cfg.Signer,
		networkID:  cfg.NetworkID,
		originator: cfg.Originator,
		logger:     cfg.Logger,
	}, nil
}

// Publish signs the (already-verified) SMT-replay finding as a
// KindSMTReplayFinding event, appends it to the local Store, and
// broadcasts it to peers via the Sink.
//
// Errors are logged + swallowed: the verification (already
// performed by the caller before calling Publish) is the
// authoritative event; gossip transport is best-effort.
//
// CONTRACT: callers MUST have called finding.Verify(set) and
// observed nil before invoking Publish. This publisher trusts the
// call site rather than the type system (parallel to
// EquivocationPublisher).
func (p *SMTReplayPublisher) Publish(ctx context.Context, finding *findings.SMTReplayFinding) {
	if p == nil {
		return
	}
	if finding == nil {
		panic("gossipnet/smt_replay: nil finding (programmer error)")
	}

	prev, lamport, err := p.store.Head(ctx, p.originator)
	if err != nil {
		p.logger.Warn("smt_replay publisher: read head failed", "error", err)
		return
	}
	nextLamport := lamport + 1
	if lamport == 0 {
		nextLamport = 1
	}

	signed, err := sdkgossip.Sign(ctx, finding,
		p.signer, p.networkID, p.originator, prev, nextLamport)
	if err != nil {
		p.logger.Warn("smt_replay publisher: sign failed", "error", err)
		return
	}

	if err := p.store.Append(ctx, signed); err != nil {
		if errors.Is(err, sdkgossip.ErrChainBreak) || errors.Is(err, sdkgossip.ErrLamportRegression) {
			p.logger.Warn("smt_replay publisher: local Append rejected; head moved underneath",
				"error", err)
			return
		}
		p.logger.Warn("smt_replay publisher: local Append failed", "error", err)
		return
	}

	if err := p.sink.Broadcast(ctx, signed); err != nil {
		p.logger.Warn("smt_replay publisher: fan-out failed (peers will catch up via /since)",
			"error", err)
		return
	}

	p.logger.Error("SMT REPLAY PUBLISHED",
		"valid_sigs_a", finding.Proof.ValidSigsA,
		"valid_sigs_b", finding.Proof.ValidSigsB,
		"tree_size", finding.Proof.TreeSize,
		"smt_root_a", fmt.Sprintf("%x", finding.Proof.SMTRootA[:8]),
		"smt_root_b", fmt.Sprintf("%x", finding.Proof.SMTRootB[:8]),
		"ledger_endpoint", finding.LedgerEndpoint,
		"lamport", nextLamport,
	)
}
