// FILE PATH: libs/monitoring/peer_consistency.go
//
// DESCRIPTION:
//
//	TrustedHeadStore is the "act" for a VERIFIED CosignedTreeHead pulled from a
//	peer's gossip feed: it maintains JN's monotonic, per-source-log view of the
//	highest tree head whose K-of-N witness quorum JN has independently verified.
//	This is cross-log mirror consistency in the gossip sense — JN's local mirror
//	of each peer log's head — distinct from delegation-mirror drift
//	(mirror_consistency.go).
//
//	The store does double duty:
//	  - It is the trust anchor for ClassMerkle (cross-log inclusion) proofs: a
//	    foreign inclusion proof is replayed against the SOURCE head JN trusts,
//	    which is exactly the highest verified head recorded here. It satisfies
//	    verification.TreeHeadSource structurally (TrustedHead method).
//	  - It surfaces drift: a head that advances (sync target), stalls
//	    (duplicate), regresses (older head re-served), or — the dangerous case —
//	    a DIFFERENT root at the SAME size, which is the fingerprint of a fork /
//	    equivocation and is never allowed to overwrite the trusted head.
//
//	ZERO-TRUST: callers MUST pass only heads that have already passed the
//	two-tier verifier. The store records trust; it does not establish it.
package monitoring

import (
	"log/slog"
	"sync"

	"github.com/baseproof/baseproof/types"
)

// HeadVerdict classifies a recorded head relative to the previously-trusted
// head for the same source log.
type HeadVerdict int

const (
	// VerdictAdvanced: first head for this log, or a strictly larger TreeSize.
	// The trusted head is updated.
	VerdictAdvanced HeadVerdict = iota
	// VerdictStale: same (TreeSize, RootHash) as already trusted. No update.
	VerdictStale
	// VerdictRegressed: smaller TreeSize than trusted. No update — a peer
	// re-serving an older head, benign on its own but worth surfacing.
	VerdictRegressed
	// VerdictForkSuspected: SAME TreeSize, DIFFERENT RootHash — two distinct
	// cosigned heads at one size. The fingerprint of equivocation. Never
	// overwrites the trusted head; the reconciler escalates.
	VerdictForkSuspected
)

func (v HeadVerdict) String() string {
	switch v {
	case VerdictAdvanced:
		return "advanced"
	case VerdictStale:
		return "stale"
	case VerdictRegressed:
		return "regressed"
	case VerdictForkSuspected:
		return "fork_suspected"
	default:
		return "unknown"
	}
}

// TrustedHeadStore holds source-log DID → highest verified TreeHead.
// Concurrency-safe. Construct via NewTrustedHeadStore.
type TrustedHeadStore struct {
	mu     sync.RWMutex
	heads  map[string]types.TreeHead
	logger *slog.Logger
}

// NewTrustedHeadStore returns an empty store. nil logger ⇒ slog.Default().
func NewTrustedHeadStore(logger *slog.Logger) *TrustedHeadStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &TrustedHeadStore{heads: make(map[string]types.TreeHead), logger: logger}
}

// RecordCosignedHead records a VERIFIED head for sourceLogDID and returns the
// drift verdict. Monotonic: the trusted head advances only on a strictly larger
// TreeSize; a same-size-different-root (fork) or smaller-size (regression) head
// never overwrites it.
func (s *TrustedHeadStore) RecordCosignedHead(sourceLogDID string, head types.TreeHead) HeadVerdict {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev, ok := s.heads[sourceLogDID]
	switch {
	case !ok || head.TreeSize > prev.TreeSize:
		s.heads[sourceLogDID] = head
		return VerdictAdvanced
	case head.TreeSize == prev.TreeSize && head.RootHash != prev.RootHash:
		// Two cosigned heads at the same size with different roots. Do NOT
		// overwrite — keep the first-trusted head; the reconciler escalates.
		s.logger.Error("monitoring/peer: FORK suspected — same TreeSize, different RootHash",
			slog.String("source_log", sourceLogDID),
			slog.Uint64("tree_size", head.TreeSize))
		return VerdictForkSuspected
	case head.TreeSize < prev.TreeSize:
		return VerdictRegressed
	default:
		return VerdictStale
	}
}

// TrustedHead returns the highest verified head for sourceLogDID. Satisfies
// verification.TreeHeadSource so the verifier can anchor cross-log inclusion
// proofs against JN's independently-verified view.
func (s *TrustedHeadStore) TrustedHead(sourceLogDID string) (types.TreeHead, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.heads[sourceLogDID]
	return h, ok
}
