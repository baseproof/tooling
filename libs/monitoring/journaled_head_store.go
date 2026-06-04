// JournaledHeadStore — write-through decorator that mirrors every
// RecordCosignedHead into a HeadsJournal.
//
// # PURPOSE
//
// TrustedHeadStore lives in-memory; it's the fast path for "what is
// the highest verified head right now?" queries (the cross-log
// inclusion proof anchor for live verification).
//
// HeadsJournal lives in durable storage; it's the slow-but-permanent
// archive that survives restarts and supports historical-asOf reads
// for forensic verification, year-15 bundles, fork forensics, and
// the equivocation responder.
//
// JournaledHeadStore wires the two together: every Record fans out
// to BOTH the in-memory store AND the journal. Reads of "latest" go
// to the in-memory store (fast); reads of "historical" go directly
// to the journal (callers that need asOf semantics call the journal
// themselves, not this decorator).
//
// # CONCURRENCY
//
// Inherits the underlying stores' concurrency posture. The
// TrustedHeadStore uses a mutex; the HeadsJournal contract requires
// the implementation to handle concurrent writes safely. No
// additional locks here.
package monitoring

import (
	"context"
	"log/slog"
	"time"

	"github.com/baseproof/baseproof/types"
)

// JournaledHeadStore wraps a *TrustedHeadStore with a HeadsJournal
// fan-out. Construct via NewJournaledHeadStore; pass the result to
// the gossipingest pipeline's TrustedHeadStore slot. Reads against
// the fast latest-head path go through the embedded
// *TrustedHeadStore; writes fan out to both.
type JournaledHeadStore struct {
	// inner is the in-memory store the existing reconciler call
	// path already targets. We delegate the fast read path to it
	// (peer-consistency endpoint, cross-log inclusion proof
	// anchor) without change.
	inner *TrustedHeadStore

	// journal is the durable archive. May be nil — when nil this
	// decorator behaves identically to *TrustedHeadStore directly
	// (the "no durable archive" mode is the default for small
	// dev / test deployments). Production wiring always passes a
	// non-nil journal.
	journal HeadsJournal

	logger *slog.Logger
}

// NewJournaledHeadStore composes the two stores. The inner store
// is REQUIRED — it is the existing trust anchor. The journal is
// OPTIONAL — nil disables durable archival (the decorator then
// behaves identically to using *TrustedHeadStore directly).
//
// V1.34 CONTRACT — the journal parameter is optional, but when
// SUPPLIED it must be a valid HeadsJournal. A nil interface
// disables journaling; a non-nil but broken implementation is the
// caller's problem.
func NewJournaledHeadStore(inner *TrustedHeadStore, journal HeadsJournal, logger *slog.Logger) *JournaledHeadStore {
	if inner == nil {
		panic("monitoring/JournaledHeadStore: inner *TrustedHeadStore is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &JournaledHeadStore{
		inner:   inner,
		journal: journal,
		logger:  logger,
	}
}

// TrustedHead delegates to the inner store. Satisfies the read
// surface the existing code path uses (verification.TreeHeadSource).
func (j *JournaledHeadStore) TrustedHead(sourceLogDID string) (types.TreeHead, bool) {
	return j.inner.TrustedHead(sourceLogDID)
}

// Inner returns the underlying *TrustedHeadStore — for callers that
// need to thread the in-memory store specifically (e.g., into a
// peer-consistency endpoint). Read-only access; this decorator
// owns the lifecycle.
func (j *JournaledHeadStore) Inner() *TrustedHeadStore {
	return j.inner
}

// Journal returns the underlying HeadsJournal — for callers that
// need to do historical-asOf reads. May be nil when journaling is
// disabled.
func (j *JournaledHeadStore) Journal() HeadsJournal {
	return j.journal
}

// RecordCosignedHead delegates the in-memory record AND fans the
// head out to the durable journal. The verdict returned is the
// in-memory store's verdict (Advanced / Stale / Regressed /
// ForkSuspected) — the journal's RecordVerdict is logged but not
// propagated through this method's return.
//
// REASONING. The existing gossip reconciler at libs/monitoring/
// gossip_reconciler.go:277 already handles the VerdictForkSuspected
// case and reacts to it. Threading a second equivocation signal
// through this method would duplicate that logic. The journal's
// equivocation detection is therefore reflected via:
//
//  1. The journal's own state (BurnStatus) — queryable
//     independently
//  2. A structured log event when the journal observes a burn
//     transition — operators see it in the same log stream as the
//     reconciler's VerdictForkSuspected error
//
// A future enhancement could surface the journal's BurnTransition
// signal through a separate callback; today the log event is the
// agreed escalation channel.
func (j *JournaledHeadStore) RecordCosignedHead(
	ctx context.Context,
	sourceLogDID string,
	cosigned types.CosignedTreeHead,
	lamportTime uint64,
	committedAt time.Time,
	canonicalBytes []byte,
) HeadVerdict {
	verdict := j.inner.RecordCosignedHead(sourceLogDID, cosigned.TreeHead)

	// Journal fan-out. Failures are logged but not propagated —
	// the in-memory path has already succeeded, and a journal
	// outage must not block live verification. The journal will
	// catch up when the next head is published or when the
	// auditor restarts and replays from gossip.
	if j.journal == nil {
		return verdict
	}
	rv, err := j.journal.Record(ctx, Head{
		LogDID:         sourceLogDID,
		TreeHead:       cosigned.TreeHead,
		Signatures:     cosigned.Signatures,
		CanonicalBytes: canonicalBytes,
		LamportTime:    lamportTime,
		CommittedAt:    committedAt,
	})
	if err != nil {
		j.logger.Error("monitoring/journaled_head_store: journal.Record failed; in-memory path succeeded",
			slog.String("source_log", sourceLogDID),
			slog.Uint64("tree_size", cosigned.TreeSize),
			slog.String("error", err.Error()))
		return verdict
	}
	if rv.BurnTransition {
		j.logger.Error("monitoring/journaled_head_store: BURN — equivocation detected, log frozen",
			slog.String("source_log", sourceLogDID),
			slog.Uint64("fork_sequence", cosigned.TreeSize),
			slog.String("existing_root", encodeRoot(rv.ConflictingRoot)),
			slog.String("new_root", encodeRoot(cosigned.RootHash)))
	}
	return verdict
}

func encodeRoot(r [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range r {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0F])
	}
	return string(out)
}
