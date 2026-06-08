// FILE PATH: services/auditor/cmd/auditor/equivocation_wiring.go
//
// DESCRIPTION:
//
//	Activates the auditor's INDEPENDENT equivocation-detection leg — the
//	defining job of a detective control that, until now, shipped fully
//	implemented + unit-tested (internal/equivocation/scanner.go) but was never
//	constructed in the binary. main.go ran only the inbound puller + the
//	periodic scheduler (the CONSUME side: verify → reconcile → persist, plus the
//	slasher). This file wires the PRODUCE side: poll each peer's latest cosigned
//	tree head, prove any same-size / different-root split via
//	witness.DetectEquivocation against the auditor's OWN genesis witness set, and
//	PUSH the resulting self-certifying finding into the peer gossip mesh.
//
// ZERO-TRUST / DECENTRALIZED / INDEPENDENT (why pushing is safe):
//
//   - INDEPENDENT: detection runs on the auditor's own schedule and verifies
//     fetched heads against the auditor's OWN genesis-derived witness sets
//     (buildWitnessSets ← the bootstrap birth certificate), never a peer's
//     self-reported set. A lying ledger cannot induce a false finding.
//   - ZERO-TRUST: the emitted EquivocationFinding wraps a witness.EquivocationProof
//     = two CosignedTreeHeads, each carrying K-of-N witness signatures. Every
//     recipient RE-VERIFIES that proof (findings.Verify) before admitting it, so
//     the auditor's gossip signature authenticates only the SENDER (Lamport
//     ordering / anti-replay) — a compromised auditor cannot fabricate a burn
//     without forging K witness signatures.
//   - DECENTRALIZED: the push is a MultiSink fan-out (one HTTPSink per peer),
//     mirroring the ledger's own bundle.Sink — each peer ingests, verifies, and
//     decides independently; the identity is a self-certifying did:key. The leg
//     is purely additive to existing ledger-peer detection (no SPOF).
//
// Disabled unless BOTH AUDITOR_EQUIVOCATION_SCAN_INTERVAL > 0 AND a gossip
// signing key are configured — emit requires a gossip identity. A construction
// fault logs loudly and the auditor continues its (valuable) consume-side role:
// failing to start an ADDITIVE detector opens no security hole, whereas blocking
// custody on an emit-side misconfig would.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/auditor/internal/equivocation"
	"github.com/baseproof/tooling/services/auditor/internal/gossipfeed"
)

// equivScannerDeps are the already-constructed inputs the scanner reuses. The
// witnessSets + resolver are the SAME genesis-derived roots the verify/horizon
// paths use, which is what keeps detection independent and zero-trust.
type equivScannerDeps struct {
	signingKeyFile string
	scanInterval   time.Duration
	networkID      cosign.NetworkID
	peers          []resolvedPeer
	witnessSets    map[string]*cosign.WitnessKeySet
	resolver       witness.EndpointResolver
	httpClient     *http.Client
	logger         *slog.Logger
}

// startEquivocationScanner wires + launches the independent equivocation
// detection leg. Returns a done channel (closed when every per-peer scanner has
// unwound) and a cleanup that drains the gossip publisher; both are nil when the
// scanner is disabled. An error is returned only for a genuine construction
// fault (the caller logs it and continues without the scanner).
func startEquivocationScanner(ctx context.Context, d equivScannerDeps) (<-chan struct{}, func(context.Context) error, error) {
	if d.scanInterval <= 0 {
		d.logger.Info("auditor: equivocation scanner DISABLED (AUDITOR_EQUIVOCATION_SCAN_INTERVAL unset)")
		return nil, nil, nil
	}
	if d.signingKeyFile == "" {
		d.logger.Warn("auditor: equivocation scanner requested but AUDITOR_GOSSIP_SIGNING_KEY_FILE empty — " +
			"emit needs a gossip identity; scanner DISABLED")
		return nil, nil, nil
	}
	if len(d.peers) == 0 || len(d.witnessSets) == 0 {
		d.logger.Warn("auditor: equivocation scanner enabled but no peers / witness sets resolved; scanner DISABLED")
		return nil, nil, nil
	}

	// 1) Gossip originator identity — a self-certifying did:key derived from the
	//    operator-held secp256k1 PEM (no DID in config). Authenticates the sender;
	//    it is NOT a trust anchor (recipients re-verify the embedded K-of-N proof).
	key, err := gossipfeed.LoadSigningKeyPEM(d.signingKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load signing key: %w", err)
	}
	originator, err := gossipfeed.DIDKeyForSigningKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("derive originator did:key: %w", err)
	}
	signer, err := gossipfeed.NewEventSigner(cosign.NewECDSAWitnessSigner(key), d.networkID, originator)
	if err != nil {
		return nil, nil, fmt.Errorf("event signer: %w", err)
	}

	// 2) Push transport — a MultiSink fan-out of one HTTPSink per peer gossip
	//    endpoint, mirroring the ledger's bundle.Sink (gossipnet/wiring.go). A
	//    pushed finding lands in each peer's gossip store; the recipient
	//    re-verifies before admitting it (and thus before /v1/burn can see it).
	peerSinks := make([]sdkgossip.Sink, 0, len(d.peers))
	for _, p := range d.peers {
		if p.baseURL == "" {
			continue
		}
		client, cerr := sdkgossip.NewClient(p.baseURL, sdkgossip.WithHTTPClient(d.httpClient))
		if cerr != nil {
			return nil, nil, fmt.Errorf("gossip client %s: %w", p.baseURL, cerr)
		}
		sink, serr := sdkgossip.NewHTTPSink(client)
		if serr != nil {
			return nil, nil, fmt.Errorf("http sink %s: %w", p.baseURL, serr)
		}
		peerSinks = append(peerSinks, sink)
	}
	if len(peerSinks) == 0 {
		d.logger.Warn("auditor: equivocation scanner enabled but no peer base URLs to push to; scanner DISABLED")
		return nil, nil, nil
	}
	multi, err := sdkgossip.NewMultiSink(peerSinks)
	if err != nil {
		return nil, nil, fmt.Errorf("multi sink: %w", err)
	}
	publisher, err := gossipfeed.NewPublisher(gossipfeed.PublisherConfig{Underlying: multi, Logger: d.logger})
	if err != nil {
		return nil, nil, fmt.Errorf("publisher: %w", err)
	}

	// 3) Head fetcher — reuses the auditor's resolver + outbound client. The
	//    fetched head is only deemed equivocating when BOTH heads carry valid
	//    K-of-N signatures from the authoritative (genesis) set.
	headClient, err := witness.NewTreeHeadClient(d.resolver, witness.TreeHeadClientConfig{Client: d.httpClient})
	if err != nil {
		_ = publisher.Close(context.Background())
		return nil, nil, fmt.Errorf("tree-head client: %w", err)
	}

	// 4) One scanner per peer. The scanner stamps a single LedgerEndpoint into
	//    every finding it emits, so scoping each scanner to one peer keeps slash
	//    attribution correct (the equivocating ledger's own endpoint). Burn keys
	//    off the proof's TargetLogDID regardless, so a finding is never
	//    mis-targeted; this only sharpens the slasher's per-ledger bookkeeping.
	scanners := make([]*equivocation.Scanner, 0, len(d.peers))
	for _, p := range d.peers {
		logDID := p.originatorDID
		set, ok := d.witnessSets[logDID]
		if !ok || set == nil || p.baseURL == "" {
			continue
		}
		sc, scerr := equivocation.NewScanner(equivocation.ScannerConfig{
			LogDIDs:        []string{logDID},
			WitnessSets:    map[string]*cosign.WitnessKeySet{logDID: set},
			Client:         headClient,
			Emitter:        publisher,
			Signer:         signer.Sign,
			PollInterval:   d.scanInterval,
			Logger:         d.logger,
			LedgerEndpoint: p.baseURL,
		})
		if scerr != nil {
			_ = publisher.Close(context.Background())
			return nil, nil, fmt.Errorf("build scanner for %s: %w", logDID, scerr)
		}
		scanners = append(scanners, sc)
	}
	if len(scanners) == 0 {
		_ = publisher.Close(context.Background())
		d.logger.Warn("auditor: equivocation scanner enabled but no peer had a matching witness set; scanner DISABLED")
		return nil, nil, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, sc := range scanners {
			wg.Add(1)
			go func(s *equivocation.Scanner) {
				defer wg.Done()
				s.Run(ctx) // blocks until ctx is cancelled
			}(sc)
		}
		wg.Wait()
	}()
	d.logger.Info("auditor: equivocation scanner ENABLED (independent detection → gossip push)",
		"originator", originator,
		"scanned_peers", len(scanners),
		"push_sinks", len(peerSinks),
		"interval", d.scanInterval.String(),
	)
	return done, publisher.Close, nil
}
