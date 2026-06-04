package aggregator

import (
	"context"
	"log/slog"
	"time"

	"github.com/baseproof/tooling/libs/clitools"
)

// LedgerScanner reads up to count raw entries from a log starting at startPos.
// *clitools.LedgerClient satisfies it.
type LedgerScanner interface {
	ScanFrom(ctx context.Context, startPos uint64, count int) ([]clitools.RawEntry, error)
}

// WatermarkStore persists per-log scan progress. *clitools.DB satisfies it.
type WatermarkStore interface {
	GetWatermark(logDID string) (uint64, error)
	UpdateWatermark(logDID string, pos uint64) error
}

// Projector consumes a decoded entry and writes the domain projection (classify
// + index). It is the SINGLE domain injection seam: the engine owns polling,
// decoding, and watermark progress; the network owns what to extract and how to
// store it (Ledger Principle 12 — schema-aware extractor inversion).
type Projector interface {
	Project(ctx context.Context, e *DecodedEntry) error
}

// ScannerConfig is the engine's operational config — no domain.
type ScannerConfig struct {
	LogDIDs      []string
	BatchSize    int
	PollInterval time.Duration
}

// Scanner polls the ledger for new entries, decodes each, and drives them
// through the injected Projector, advancing a per-log watermark.
type Scanner struct {
	ledger       LedgerScanner
	watermarks   WatermarkStore
	projector    Projector
	logDIDs      []string
	batchSize    int
	pollInterval time.Duration
	logger       *slog.Logger
}

// NewScanner wires the engine from operational config + injected dependencies.
func NewScanner(cfg ScannerConfig, ledger LedgerScanner, watermarks WatermarkStore, projector Projector, logger *slog.Logger) *Scanner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scanner{
		ledger:       ledger,
		watermarks:   watermarks,
		projector:    projector,
		logDIDs:      cfg.LogDIDs,
		batchSize:    cfg.BatchSize,
		pollInterval: cfg.PollInterval,
		logger:       logger,
	}
}

// Run starts the polling loop and blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) error {
	s.logger.Info("aggregator: scanner starting",
		"poll", s.pollInterval, "batch", s.batchSize, "logs", len(s.logDIDs))
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("aggregator: scanner stopped")
			return nil
		case <-time.After(s.pollInterval):
			for _, logDID := range s.logDIDs {
				if err := s.scanLog(ctx, logDID); err != nil {
					s.logger.Error("aggregator: scan failed", "log", logDID, "err", err)
				}
			}
		}
	}
}

// RunOnce scans every configured log a single time (for tests and manual runs).
func (s *Scanner) RunOnce(ctx context.Context) error {
	for _, logDID := range s.logDIDs {
		if err := s.scanLog(ctx, logDID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) scanLog(ctx context.Context, logDID string) error {
	watermark, err := s.watermarks.GetWatermark(logDID)
	if err != nil {
		return err
	}

	startPos := watermark + 1
	if watermark == 0 {
		startPos = 0
	}

	entries, err := s.ledger.ScanFrom(ctx, startPos, s.batchSize)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}

	indexed := 0
	for _, raw := range entries {
		decoded, err := Decode(logDID, raw)
		if err != nil {
			s.logger.Warn("aggregator: decode failed", "seq", raw.Sequence, "err", err)
			continue
		}
		if err := s.projector.Project(ctx, decoded); err != nil {
			s.logger.Warn("aggregator: project failed", "seq", raw.Sequence, "err", err)
			continue
		}
		indexed++
	}

	lastSeq := entries[len(entries)-1].Sequence
	if err := s.watermarks.UpdateWatermark(logDID, lastSeq); err != nil {
		return err
	}

	if indexed > 0 {
		s.logger.Info("aggregator: indexed",
			"log", logDID, "count", indexed, "from", startPos, "to", lastSeq)
	}
	return nil
}
