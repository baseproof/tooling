// FILE PATH: services/auditor/internal/equivocation/scanner.go
//
// DESCRIPTION:
//
//	Phase 5 — Pull-side equivocation sentry. Periodically polls
//	multiple peer ledger logs' latest cosigned tree heads,
//	compares them pairwise via witness.DetectEquivocation, and
//	emits a verified gossip.findings.EquivocationFinding on
//	detection. This is judicial-network's defense against a
//	rogue Ledger publishing two different RootHashes at the same
//	TreeSize (Trust Alignment 7: split-brain proofs).
//
//	The sentry is read-only against the Ledger HTTP surface and
//	pure-CPU against the SDK's verifier — no SMT mutations, no
//	on-log entries authored. When equivocation is detected, the
//	finding is broadcast to the gossip publisher; the slasher
//	(membership.go) listens to that broadcast separately.
//
// KEY DEPENDENCIES:
//   - baseproof/witness: TreeHeadClient, DetectEquivocation,
//     EquivocationProof
//   - baseproof/gossip: SignedEvent, Sink (publisher.EmitEvidence)
//   - baseproof/gossip/findings: NewEquivocationFinding
//   - baseproof/crypto/cosign: WitnessKeySet
package equivocation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// ErrInvalidConfig is returned when ScannerConfig is malformed at
// construction time.
var ErrInvalidConfig = errors.New("equivocation/scanner: invalid configuration")

// EvidenceEmitter is the contract the scanner uses to publish
// verified equivocation findings. Satisfied by
// gossipfeed.Publisher; tests inject a counting fake.
type EvidenceEmitter interface {
	EmitEvidence(ctx context.Context, ev gossip.SignedEvent) error
}

// Signer is the contract used to sign the wrapped SignedEvent
// before it goes onto the wire. The judicial-network's gossip
// signing key is loaded by the binary at boot; tests inject a
// stub.
type Signer func(ctx context.Context, ev gossip.Event) (gossip.SignedEvent, error)

// ScannerConfig configures the equivocation scanner. All fields
// are required.
type ScannerConfig struct {
	// LogDIDs is the set of ledger DIDs to poll. The scanner
	// fetches each one's latest cosigned tree head, then compares
	// the head with the most recent previously-seen head for the
	// same log at the same tree size.
	LogDIDs []string

	// WitnessSets maps logDID to the source-log witness topology.
	// DetectEquivocation reads K and the keys from set.Quorum() /
	// set.Keys().
	WitnessSets map[string]*cosign.WitnessKeySet

	// Client is the SDK head-fetcher.
	Client *witness.TreeHeadClient

	// Emitter publishes verified findings to gossip.
	Emitter EvidenceEmitter

	// Signer wraps a findings.EquivocationFinding into a
	// SignedEvent before emit.
	Signer Signer

	// PollInterval is the cadence between full sweeps. Default 30s.
	PollInterval time.Duration

	// Logger is the structured logger; nil → slog.Default.
	Logger *slog.Logger

	// LedgerEndpoint is published into the EquivocationFinding so
	// the slasher knows which ledger to penalize.
	LedgerEndpoint string
}

// Scanner runs the pairwise comparison loop. One Scanner per
// process; safe to start once at boot and Run until ctx is
// cancelled.
type Scanner struct {
	cfg    ScannerConfig
	logger *slog.Logger

	// seen caches the most-recent head observed for each log at
	// each TreeSize. The cache trims to keep memory bounded
	// across long-running deployments.
	mu   sync.Mutex
	seen map[string]map[uint64]types.CosignedTreeHead
}

// NewScanner validates cfg and returns a scanner ready to Run.
func NewScanner(cfg ScannerConfig) (*Scanner, error) {
	if len(cfg.LogDIDs) == 0 {
		return nil, fmt.Errorf("%w: empty LogDIDs", ErrInvalidConfig)
	}
	if len(cfg.WitnessSets) == 0 {
		return nil, fmt.Errorf("%w: empty WitnessSets", ErrInvalidConfig)
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("%w: nil TreeHeadClient", ErrInvalidConfig)
	}
	if cfg.Emitter == nil {
		return nil, fmt.Errorf("%w: nil EvidenceEmitter", ErrInvalidConfig)
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("%w: nil Signer", ErrInvalidConfig)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Scanner{
		cfg:    cfg,
		logger: logger,
		seen:   make(map[string]map[uint64]types.CosignedTreeHead),
	}, nil
}

// Run loops until ctx is cancelled. Each tick polls every log
// once; per-log errors are logged and do not stop the loop.
func (s *Scanner) Run(ctx context.Context) {
	tick := time.NewTicker(s.cfg.PollInterval)
	defer tick.Stop()
	s.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.sweep(ctx)
		}
	}
}

// sweep walks every configured log once, fetching the latest head
// and comparing it against the cached entry for the same
// TreeSize.
func (s *Scanner) sweep(ctx context.Context) {
	for _, logDID := range s.cfg.LogDIDs {
		if err := s.checkOne(ctx, logDID); err != nil {
			s.logger.Warn("equivocation: sweep step failed",
				slog.String("log_did", logDID),
				slog.String("error", err.Error()),
			)
		}
	}
}

// checkOne fetches the head and compares against any prior head
// at the same TreeSize. On equivocation, emits a finding.
func (s *Scanner) checkOne(ctx context.Context, logDID string) error {
	set, ok := s.cfg.WitnessSets[logDID]
	if !ok || set == nil {
		return fmt.Errorf("no WitnessSet for %s", logDID)
	}
	head, _, err := s.cfg.Client.FetchLatestTreeHead(ctx, logDID)
	if err != nil {
		return fmt.Errorf("fetch head: %w", err)
	}
	prior, hadPrior := s.lookupAndStore(logDID, head)
	if !hadPrior {
		return nil
	}
	if prior.RootHash == head.RootHash {
		return nil
	}
	proof, err := witness.DetectEquivocation(prior, head, set)
	if err != nil {
		if errors.Is(err, witness.ErrDifferentSizes) {
			return nil
		}
		return fmt.Errorf("detect equivocation: %w", err)
	}
	if proof == nil {
		return nil
	}
	return s.emitFinding(ctx, *proof)
}

// lookupAndStore returns the previously-cached head for the same
// log + treeSize and atomically replaces it with the new head.
// The second return is false when this is the first head we have
// observed at that tree size.
func (s *Scanner) lookupAndStore(logDID string, head types.CosignedTreeHead) (types.CosignedTreeHead, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byLog, ok := s.seen[logDID]
	if !ok {
		byLog = make(map[uint64]types.CosignedTreeHead)
		s.seen[logDID] = byLog
	}
	prior, hadPrior := byLog[head.TreeSize]
	byLog[head.TreeSize] = head
	return prior, hadPrior
}

// emitFinding wraps the proof into a finding, signs it, and
// pushes it through the evidence-channel publisher.
func (s *Scanner) emitFinding(ctx context.Context, proof witness.EquivocationProof) error {
	finding, err := findings.NewEquivocationFinding(proof, s.cfg.LedgerEndpoint)
	if err != nil {
		return fmt.Errorf("wrap finding: %w", err)
	}
	signed, err := s.cfg.Signer(ctx, finding)
	if err != nil {
		return fmt.Errorf("sign finding: %w", err)
	}
	if err := s.cfg.Emitter.EmitEvidence(ctx, signed); err != nil {
		return fmt.Errorf("emit finding: %w", err)
	}
	s.logger.Error("equivocation: split-brain detected; finding emitted",
		slog.Uint64("tree_size", proof.TreeSize),
		slog.String("ledger_endpoint", s.cfg.LedgerEndpoint),
	)
	return nil
}
