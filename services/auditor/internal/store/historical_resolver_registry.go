// FILE PATH: services/auditor/internal/store/historical_resolver_registry.go
//
// HistoricalResolverRegistry — a multi-log façade over per-log
// HistoricalWitnessSetResolvers, satisfying the gossipverify
// HeadWitnessSetResolver seam (SetForHead(ctx, logDID, head)).
//
// The inbound gossip verifier serves findings from many source logs; this maps
// a finding's source-log DID to that log's position-aware resolver so a cosigned
// head is verified against the set that COSIGNED it (reconstructed from that
// log), not the position-blind current-set snapshot.
//
// A log with no registered resolver returns ErrNoResolverForLog; the verifier
// treats a resolve failure as non-fatal and falls back to the snapshot, so an
// unregistered log degrades to legacy behavior rather than dropping findings.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
)

// ErrNoResolverForLog is returned when SetForHead is called for a log that has
// no registered per-log resolver.
var ErrNoResolverForLog = errors.New("auditor/store: no historical resolver for log")

// HistoricalResolverRegistry routes SetForHead(logDID, head) to the per-log
// HistoricalWitnessSetResolver. Immutable after construction; safe for
// concurrent reads.
type HistoricalResolverRegistry struct {
	byLog map[string]*HistoricalWitnessSetResolver
}

// NewHistoricalResolverRegistry builds a registry from a logDID→resolver map.
// A nil/empty map is valid (every SetForHead returns ErrNoResolverForLog → the
// verifier falls back to the snapshot).
func NewHistoricalResolverRegistry(byLog map[string]*HistoricalWitnessSetResolver) *HistoricalResolverRegistry {
	cp := make(map[string]*HistoricalWitnessSetResolver, len(byLog))
	for k, v := range byLog {
		cp[k] = v
	}
	return &HistoricalResolverRegistry{byLog: cp}
}

// SetForHead resolves the head-anchored set for head on logDID. Satisfies
// gossipverify.HeadWitnessSetResolver.
func (r *HistoricalResolverRegistry) SetForHead(ctx context.Context, logDID string, head types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	res, ok := r.byLog[logDID]
	if !ok || res == nil {
		return nil, fmt.Errorf("%w: %q", ErrNoResolverForLog, logDID)
	}
	return res.SetForHead(ctx, head)
}

// SetAt resolves the position-anchored set authoritative at asOf on logDID — the
// era a head at a given TreeSize was cosigned under. Used for equivocation /
// SMT-replay / history-rewrite findings (where a head may be adversarial or span
// eras, so the era is fixed by position). Satisfies
// gossipverify.HeadWitnessSetResolver.
func (r *HistoricalResolverRegistry) SetAt(ctx context.Context, logDID string, asOf types.LogPosition) (*cosign.WitnessKeySet, error) {
	res, ok := r.byLog[logDID]
	if !ok || res == nil {
		return nil, fmt.Errorf("%w: %q", ErrNoResolverForLog, logDID)
	}
	return res.SetAt(ctx, asOf)
}

// Len reports how many logs have a resolver.
func (r *HistoricalResolverRegistry) Len() int { return len(r.byLog) }
