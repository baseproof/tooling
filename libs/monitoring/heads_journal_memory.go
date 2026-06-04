// MemoryHeadsJournal — in-memory HeadsJournal implementation.
//
// USAGE
//
//   - Tests: production-grade tests construct one of these directly.
//     The shape matches the production PostgresHeadsJournal so a test
//     can substitute either.
//
//   - Small deployments: a single-network JN whose 15-year horizon
//     fits in process memory (≈ 80M heads × 250 B ≈ 20 GB) may run
//     with this implementation alone. The 250 GB / 30 logs case
//     needs the Postgres impl in services/auditor/internal/store.
//
//   - Bootstrap & restart: this implementation FORGETS on process
//     exit. Callers that need durability MUST use the Postgres
//     implementation; this one is the contract reference, not a
//     production durability layer.
//
// CONCURRENCY
//
// Writes serialize through a single sync.Mutex (the equivocation
// detection requires read-then-write atomicity at the (LogDID,
// Sequence) row). Reads take RLock so HeadAt / LatestHead are
// concurrent with other reads. Adequate for the in-memory scale
// described above; the Postgres impl uses row-level locking for
// the production-scale case.
package monitoring

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryHeadsJournal is the in-memory HeadsJournal reference
// implementation. Constructor: NewMemoryHeadsJournal.
type MemoryHeadsJournal struct {
	mu sync.RWMutex

	// heads is the canonical store.
	// Key: composite (LogDID, Sequence, RootHash) — primary key.
	// Value: the recorded Head.
	heads map[headKey]Head

	// byLogSeq indexes the primary key by (LogDID, Sequence) →
	// RootHashes recorded at that point. Lets HeadsAtSequence
	// answer in O(forks) instead of O(rows). On a clean log
	// each (LogDID, Sequence) maps to one RootHash; on an
	// equivocated log to ≥ 2.
	byLogSeq map[logSeqKey][][32]byte

	// byLogLatest tracks the highest Sequence per LogDID. Lets
	// LatestHead answer in O(1) on a clean log. Updated on every
	// Record that advances the sequence.
	byLogLatest map[string]uint64

	// burns records the per-LogDID burn status. Empty (zero
	// value, Burned:false) means the log is clean.
	burns map[string]BurnStatus
}

// NewMemoryHeadsJournal constructs an empty in-memory HeadsJournal.
// Always returns a usable instance — no error path.
func NewMemoryHeadsJournal() *MemoryHeadsJournal {
	return &MemoryHeadsJournal{
		heads:       make(map[headKey]Head),
		byLogSeq:    make(map[logSeqKey][][32]byte),
		byLogLatest: make(map[string]uint64),
		burns:       make(map[string]BurnStatus),
	}
}

// Static interface conformance — drift in the interface surfaces at
// build time, not at first usage. Catches the case where a future
// edit adds a method to HeadsJournal but forgets the in-memory impl.
var _ HeadsJournal = (*MemoryHeadsJournal)(nil)

// Record implements HeadsJournal.
func (j *MemoryHeadsJournal) Record(ctx context.Context, head Head) (RecordVerdict, error) {
	if err := ctx.Err(); err != nil {
		return RecordVerdict{}, err
	}
	if err := ValidateForRecord(head); err != nil {
		return RecordVerdict{}, err
	}

	// Default RecordedAt to "now" if the caller did not set it.
	// We do NOT default CommittedAt — that's the cosigned head's
	// own truth and must come from the publisher.
	if head.RecordedAt.IsZero() {
		head.RecordedAt = time.Now().UTC()
	}

	pk := headKey{LogDID: head.LogDID, Sequence: head.TreeSize, RootHash: head.RootHash}
	lsk := logSeqKey{LogDID: head.LogDID, Sequence: head.TreeSize}

	j.mu.Lock()
	defer j.mu.Unlock()

	// Idempotence: same (LogDID, Sequence, RootHash) is a no-op
	// at the persistence layer. The verdict reports Persisted:false.
	if _, dup := j.heads[pk]; dup {
		burned := j.burns[head.LogDID].Burned
		return RecordVerdict{
			Persisted:    false,
			Equivocation: burned,
		}, nil
	}

	// Equivocation detection: a different RootHash already exists
	// at this (LogDID, Sequence). Write the new row AND flag the
	// equivocation; record the FIRST burn as a transition signal.
	existing := j.byLogSeq[lsk]
	equivocation := len(existing) > 0
	var conflictingRoot [32]byte
	if equivocation {
		conflictingRoot = existing[0]
	}

	// Persist the row.
	j.heads[pk] = head
	j.byLogSeq[lsk] = append(j.byLogSeq[lsk], head.RootHash)

	// Update latest-sequence index on the BURN-FREE history.
	// Burned logs do not advance LatestHead (the contract is
	// fail-closed for burned logs).
	burned := j.burns[head.LogDID].Burned
	burnTransition := false
	if equivocation && !burned {
		// First equivocation observed for this log — TRANSITION
		// to BURNED.
		burnTransition = true
		burnedRoots := append([][32]byte{conflictingRoot}, head.RootHash)
		j.burns[head.LogDID] = BurnStatus{
			Burned:            true,
			BurnedAt:          head.RecordedAt,
			FirstForkSequence: head.TreeSize,
			ConflictingRoots:  burnedRoots,
		}
		// Once burned, the latest-head index for this log is
		// FROZEN at the highest pre-burn sequence — burned logs
		// do not surface a "latest" to the verifier. We leave
		// byLogLatest as-is (the highest value before this
		// Record); HeadAt / HeadAtTime / LatestHead consult the
		// burn map first and return ErrEquivocatedLog.
	} else if equivocation {
		// Additional fork on an already-burned log — accumulate
		// the new root for forensic surface.
		bs := j.burns[head.LogDID]
		bs.ConflictingRoots = append(bs.ConflictingRoots, head.RootHash)
		j.burns[head.LogDID] = bs
	} else {
		// Clean head — advance the latest-sequence index.
		if cur := j.byLogLatest[head.LogDID]; head.TreeSize > cur {
			j.byLogLatest[head.LogDID] = head.TreeSize
		}
	}

	return RecordVerdict{
		Persisted:       true,
		Equivocation:    equivocation,
		BurnTransition:  burnTransition,
		ConflictingRoot: conflictingRoot,
	}, nil
}

// HeadAt implements HeadsJournal.
func (j *MemoryHeadsJournal) HeadAt(ctx context.Context, logDID string, asOfSequence uint64) (Head, error) {
	if err := ctx.Err(); err != nil {
		return Head{}, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()

	if j.burns[logDID].Burned {
		return Head{}, ErrEquivocatedLog
	}
	return j.lookupAtSequenceLocked(logDID, asOfSequence)
}

// HeadAtTime implements HeadsJournal.
func (j *MemoryHeadsJournal) HeadAtTime(ctx context.Context, logDID string, t time.Time) (Head, error) {
	if err := ctx.Err(); err != nil {
		return Head{}, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()

	if j.burns[logDID].Burned {
		return Head{}, ErrEquivocatedLog
	}

	// Scan all heads for the log; pick the one with the largest
	// CommittedAt ≤ t. In-memory scan is O(headcount-for-log) —
	// acceptable for the memory impl's intended scale. The
	// Postgres impl uses an index on (LogDID, CommittedAt) for
	// log(n) lookup.
	var best Head
	found := false
	for pk, h := range j.heads {
		if pk.LogDID != logDID {
			continue
		}
		if h.CommittedAt.After(t) {
			continue
		}
		if !found || h.CommittedAt.After(best.CommittedAt) {
			best = h
			found = true
		}
	}
	if !found {
		return Head{}, ErrNoHead
	}
	return best, nil
}

// HeadByRootHash implements HeadsJournal.
func (j *MemoryHeadsJournal) HeadByRootHash(ctx context.Context, logDID string, sequence uint64, rootHash [32]byte) (Head, error) {
	if err := ctx.Err(); err != nil {
		return Head{}, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()

	pk := headKey{LogDID: logDID, Sequence: sequence, RootHash: rootHash}
	h, ok := j.heads[pk]
	if !ok {
		return Head{}, ErrNoHead
	}
	return h, nil
}

// HeadsAtSequence implements HeadsJournal.
func (j *MemoryHeadsJournal) HeadsAtSequence(ctx context.Context, logDID string, sequence uint64) ([]Head, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()

	roots := j.byLogSeq[logSeqKey{LogDID: logDID, Sequence: sequence}]
	if len(roots) == 0 {
		return nil, nil
	}
	out := make([]Head, 0, len(roots))
	for _, r := range roots {
		if h, ok := j.heads[headKey{LogDID: logDID, Sequence: sequence, RootHash: r}]; ok {
			out = append(out, h)
		}
	}
	return out, nil
}

// LatestHead implements HeadsJournal.
func (j *MemoryHeadsJournal) LatestHead(ctx context.Context, logDID string) (Head, error) {
	if err := ctx.Err(); err != nil {
		return Head{}, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()

	if j.burns[logDID].Burned {
		return Head{}, ErrEquivocatedLog
	}
	seq, ok := j.byLogLatest[logDID]
	if !ok {
		return Head{}, ErrNoHead
	}
	return j.lookupAtSequenceLocked(logDID, seq)
}

// BurnStatus implements HeadsJournal.
func (j *MemoryHeadsJournal) BurnStatus(ctx context.Context, logDID string) (BurnStatus, error) {
	if err := ctx.Err(); err != nil {
		return BurnStatus{}, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.burns[logDID], nil
}

// lookupAtSequenceLocked finds the head at or before asOfSequence
// for the supplied log on the BURN-FREE history. Caller MUST hold
// at least an RLock. Implementation walks the recorded sequences
// descending to find the largest ≤ asOf — efficient at the in-
// memory scale; the Postgres impl uses an index-backed descending
// scan.
func (j *MemoryHeadsJournal) lookupAtSequenceLocked(logDID string, asOfSequence uint64) (Head, error) {
	// Collect candidate sequences for this log ≤ asOf, then pick
	// the largest. Sequences from byLogSeq's keys.
	var candidates []uint64
	for k := range j.byLogSeq {
		if k.LogDID != logDID {
			continue
		}
		if k.Sequence > asOfSequence {
			continue
		}
		candidates = append(candidates, k.Sequence)
	}
	if len(candidates) == 0 {
		return Head{}, ErrNoHead
	}
	sort.Slice(candidates, func(i, jj int) bool { return candidates[i] > candidates[jj] })
	bestSeq := candidates[0]

	// On a CLEAN log there is exactly one root at bestSeq. On a
	// burned log this code path is unreachable (caller checks
	// burn first). Return the canonical entry.
	roots := j.byLogSeq[logSeqKey{LogDID: logDID, Sequence: bestSeq}]
	if len(roots) == 0 {
		// Index drift — should not happen if Record is the only
		// mutator. Defensive: surface as ErrNoHead.
		return Head{}, ErrNoHead
	}
	return j.heads[headKey{LogDID: logDID, Sequence: bestSeq, RootHash: roots[0]}], nil
}

// ─────────────────────────────────────────────────────────────────────
// Composite keys
// ─────────────────────────────────────────────────────────────────────

type headKey struct {
	LogDID   string
	Sequence uint64
	RootHash [32]byte
}

type logSeqKey struct {
	LogDID   string
	Sequence uint64
}
