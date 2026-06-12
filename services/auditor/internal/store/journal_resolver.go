/*
FILE PATH: services/auditor/internal/store/journal_resolver.go

STHHeadSource — the auditor-side adapter from the durable evidence store's
latest verified STH to witnessrotation.VerifiedHeadSource (the scan
reconciler's stale-anchor fallback target).

The journal-first resolution machinery this file used to define
(JournalWitnessSetResolver / LogTrustRoot / RotationRecordSource) was lifted
to libs/witnessrotation — one resolver for every chain custodian; the durable
journal lives in libs/witnessrotation/journalpg. This file keeps ONLY the
evidence-store glue, because the evidence store is the auditor's.
*/
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
)

// LatestSTHSource is the narrow evidence-store read the head adapter needs:
// the newest verified STH event PLUS when it was persisted (the observation
// clock for frozen-log freshness). *PostgresStore satisfies it.
type LatestSTHSource interface {
	LatestSTHWithTime(ctx context.Context, originator string) (gossip.SignedEvent, time.Time, bool, error)
}

// STHHeadSource adapts the durable evidence store's latest verified STH into
// witnessrotation.VerifiedHeadSource (the scan reconciler's stale-anchor
// fallback). The evidence store keys events by gossip ORIGINATOR, while the
// scan reconciler names logs canonically — originatorByLog carries the
// translation (canonical LogDID → originator DID); names absent from the map
// pass through unchanged. The event was Tier-2 verified before it was
// persisted (D7), so decoding it back to a CosignedTreeHead re-surfaces an
// already-proven fact.
type STHHeadSource struct {
	src             LatestSTHSource
	originatorByLog map[string]string
}

// NewSTHHeadSource wraps an evidence store. originatorByLog may be nil when
// the caller queries by originator already.
func NewSTHHeadSource(src LatestSTHSource, originatorByLog map[string]string) (*STHHeadSource, error) {
	if src == nil {
		return nil, fmt.Errorf("auditor/store: nil LatestSTHSource")
	}
	cp := make(map[string]string, len(originatorByLog))
	for k, v := range originatorByLog {
		cp[k] = v
	}
	return &STHHeadSource{src: src, originatorByLog: cp}, nil
}

// LatestVerifiedHead returns the newest verified cosigned head persisted for
// the log; ok=false when none is held. (The witnessrotation.VerifiedHeadSource
// seam — the scan reconciler's fallback target does not need the clock.)
func (s *STHHeadSource) LatestVerifiedHead(ctx context.Context, logDID string) (types.CosignedTreeHead, bool, error) {
	head, _, ok, err := s.LatestVerifiedHeadWithTime(ctx, logDID)
	return head, ok, err
}

// LatestVerifiedHeadWithTime additionally returns WHEN the head was persisted —
// the observation clock the witness-rotation consistency audit's frozen-log
// freshness check runs against.
func (s *STHHeadSource) LatestVerifiedHeadWithTime(ctx context.Context, logDID string) (types.CosignedTreeHead, time.Time, bool, error) {
	key := logDID
	if o, ok := s.originatorByLog[logDID]; ok {
		key = o
	}
	ev, observedAt, ok, err := s.src.LatestSTHWithTime(ctx, key)
	if err != nil {
		return types.CosignedTreeHead{}, time.Time{}, false, fmt.Errorf("auditor/store: latest STH for %q: %w", key, err)
	}
	if !ok {
		return types.CosignedTreeHead{}, time.Time{}, false, nil
	}
	event, err := findings.FromWire(ev.Kind, ev.Body)
	if err != nil {
		return types.CosignedTreeHead{}, time.Time{}, false, fmt.Errorf("auditor/store: decode latest STH for %q: %w", key, err)
	}
	f, isHead := event.(*findings.CosignedTreeHeadFinding)
	if !isHead {
		return types.CosignedTreeHead{}, time.Time{}, false, fmt.Errorf("auditor/store: latest STH for %q decoded to %T, want CosignedTreeHeadFinding", key, event)
	}
	return f.Head, observedAt, true, nil
}
