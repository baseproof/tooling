/*
Package ledgerscan is a generic, restart-safe sequential reader for an
append-only transparency log. It owns the mechanics — batched traversal in
position order, deserialization, and cursor persistence — while *what to index*
from each entry is injected by the consumer via Indexer. The scanner therefore
carries zero domain knowledge (no docket/party/schema field names): any network
reuses it by supplying its own Indexer + Cursor.

Inspired by CT monitors: the ledger serves entries by position and does not
search; at 1B+ entries, building searchable indexes is the scanner's job, not
the log's.
*/
package ledgerscan

import (
	"context"
	"log"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"
)

// LogScanner is the narrow read surface the scanner needs from a ledger query
// API — just flat-offset traversal. baseproof/log.LedgerQueryAPI satisfies it, so
// the scanner depends on this one method rather than the whole query surface.
type LogScanner interface {
	ScanFromPosition(ctx context.Context, startPos uint64, count int) ([]types.EntryWithMetadata, error)
}

// Indexer consumes each scanned entry, in ascending position order. The network
// implements it to build whatever indexes it needs (signer DID, domain fields,
// …). The scanner never inspects the payload itself.
type Indexer interface {
	IndexEntry(logID string, pos uint64, entry *envelope.Entry)
}

// Cursor persists the scanner's progress so it resumes after a restart instead
// of re-scanning from zero.
type Cursor interface {
	LastScannedPosition(logID string) uint64
	SetLastScannedPosition(logID string, pos uint64)
}

// Scanner reads entries sequentially from a log and feeds each to its Indexer.
type Scanner struct {
	query     LogScanner
	indexer   Indexer
	cursor    Cursor
	logID     string
	batchSize uint64
	interval  time.Duration
}

// ScannerConfig configures the scanner. QueryAPI, Indexer, Cursor, and LogID
// are required; BatchSize and Interval default to 1000 and 5s.
type ScannerConfig struct {
	QueryAPI  LogScanner
	Indexer   Indexer
	Cursor    Cursor
	LogID     string
	BatchSize uint64
	Interval  time.Duration
}

// NewScanner creates a log scanner from cfg.
func NewScanner(cfg ScannerConfig) *Scanner {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1000
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Scanner{
		query:     cfg.QueryAPI,
		indexer:   cfg.Indexer,
		cursor:    cfg.Cursor,
		logID:     cfg.LogID,
		batchSize: cfg.BatchSize,
		interval:  cfg.Interval,
	}
}

// Run starts the scan loop, resuming from the cursor's last position. Blocks
// until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	lastPos := s.cursor.LastScannedPosition(s.logID)
	log.Printf("ledgerscan: starting from position %d on %s", lastPos, s.logID)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("ledgerscan: stopped at position %d", lastPos)
			return
		case <-ticker.C:
			newPos, err := s.scanBatch(ctx, lastPos)
			if err != nil {
				log.Printf("ledgerscan: scan error at %d: %v", lastPos, err)
				continue
			}
			if newPos > lastPos {
				lastPos = newPos
				s.cursor.SetLastScannedPosition(s.logID, lastPos)
			}
		}
	}
}

// scanBatch reads one batch from fromPos, hands each deserializable entry to the
// Indexer, and returns the next position to scan from.
func (s *Scanner) scanBatch(ctx context.Context, fromPos uint64) (uint64, error) {
	entries, err := s.query.ScanFromPosition(ctx, fromPos, int(s.batchSize))
	if err != nil {
		return fromPos, err
	}
	if len(entries) == 0 {
		return fromPos, nil
	}

	maxPos := fromPos
	for _, meta := range entries {
		pos := meta.Position.Sequence
		if pos > maxPos {
			maxPos = pos
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue // skip malformed bytes; never stall the scan
		}
		s.indexer.IndexEntry(s.logID, pos, entry)
	}
	return maxPos + 1, nil
}
