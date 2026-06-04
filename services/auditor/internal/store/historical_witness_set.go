// FILE PATH: services/auditor/internal/store/historical_witness_set.go
//
// HistoricalWitnessSetResolver — the auditor's POSITION-AWARE witness-set
// resolution, fixing the position-blindness of the inbound gossip verify path
// (gossipverify verifies every finding against gv.sets.Snapshot(), the CURRENT
// set; that resolves a year-1 head or a from-prior-set rotation against the
// wrong set).
//
// It rebuilds the PROVEN rotation chain from the LOG (witnessrotation.Rebuilder
// over a real ledger client — never gossip), then answers:
//   - SetForHead(head): the set whose cosignatures a specific head satisfies
//     (head-anchored; correct across the operationally-fuzzy cosign switch).
//   - SetAt(asOf): the set authoritative at a historical position.
//
// Both go through witness.WitnessSetAtHorizon: every rotation's POSITION is
// proven by inclusion against the single cosigned horizon, every rotation's
// AUTHENTICITY proven inductively under the prior set. This is the year-15 /
// ZT-SCN-02 custody capability.
//
// CACHING. Rebuilding scans the whole committed prefix; results are memoized
// per (logDID, horizon.TreeSize) so repeated forensic queries are cheap. A
// horizon advance (new rotations) invalidates the entry on next access.
package store

import (
	"context"
	"fmt"
	"sync"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/tooling/libs/witnessrotation"
)

// HistoricalWitnessSetResolver resolves the proven, position-appropriate
// witness set for a single log by rebuilding its rotation chain from the ledger.
type HistoricalWitnessSetResolver struct {
	src     witnessrotation.LogSource
	logDID  string
	genesis *cosign.WitnessKeySet // year-1 chain SEED (WitnessSetAtHorizon)
	anchor  *cosign.WitnessKeySet // CURRENT set that cosigns the horizon (scan trust anchor)

	mu     sync.Mutex
	cached *rebuiltChain
}

type rebuiltChain struct {
	horizonSize uint64
	horizon     types.CosignedTreeHead
	records     []witness.HorizonRotationRecord
}

// NewHistoricalWitnessSetResolver constructs a resolver.
//
//   - genesis: the YEAR-1 witness set for logDID (the chain seed
//     WitnessSetAtHorizon replays from — from the network bootstrap's
//     genesis_witness_set).
//   - anchor: the witness set CURRENTLY authoritative for logDID — the set that
//     cosigns the latest horizon, used to authenticate the scan's trust anchor.
//     When the log has never rotated, anchor == genesis; pass the auditor's
//     live trusted set otherwise. A nil anchor defaults to genesis (correct for
//     a not-yet-rotated log).
func NewHistoricalWitnessSetResolver(src witnessrotation.LogSource, logDID string, genesis, anchor *cosign.WitnessKeySet) (*HistoricalWitnessSetResolver, error) {
	if src == nil {
		return nil, fmt.Errorf("auditor/store: nil LogSource")
	}
	if logDID == "" {
		return nil, fmt.Errorf("auditor/store: empty logDID")
	}
	if genesis == nil || genesis.Size() == 0 {
		return nil, fmt.Errorf("auditor/store: nil/empty genesis witness set for %q", logDID)
	}
	if anchor == nil {
		anchor = genesis
	}
	return &HistoricalWitnessSetResolver{src: src, logDID: logDID, genesis: genesis, anchor: anchor}, nil
}

// rebuild rebuilds (or returns the cached) proven chain. The cache is keyed on
// the current horizon size, so new rotations (a larger horizon) trigger a fresh
// scan; a stable horizon serves from cache.
func (r *HistoricalWitnessSetResolver) rebuild(ctx context.Context) (*rebuiltChain, error) {
	// Cheap horizon probe to decide cache validity.
	h, err := r.src.CosignedHorizon(ctx)
	if err != nil {
		return nil, fmt.Errorf("auditor/store: horizon: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cached != nil && r.cached.horizonSize == h.TreeSize {
		return r.cached, nil
	}

	rb, err := witnessrotation.NewRebuilder(witnessrotation.Config{
		Src:       r.src,
		LogDID:    r.logDID,
		AnchorSet: r.anchor, // CURRENT set authenticates the horizon
	})
	if err != nil {
		return nil, fmt.Errorf("auditor/store: rebuilder: %w", err)
	}
	records, horizon, err := rb.Rebuild(ctx)
	if err != nil {
		return nil, fmt.Errorf("auditor/store: rebuild %q: %w", r.logDID, err)
	}
	rc := &rebuiltChain{horizonSize: horizon.TreeSize, horizon: horizon, records: records}
	r.cached = rc
	return rc, nil
}

// SetAt returns the witness set authoritative at asOf (position-aware,
// PROVEN). asOf is mandatory (ZT-IMM-01).
func (r *HistoricalWitnessSetResolver) SetAt(ctx context.Context, asOf types.LogPosition) (*cosign.WitnessKeySet, error) {
	rc, err := r.rebuild(ctx)
	if err != nil {
		return nil, err
	}
	return witness.WitnessSetAtHorizon(r.genesis, rc.records, rc.horizon.TreeHead, asOf)
}

// SetForHead returns the set authoritative for a specific cosigned head —
// head-anchored: the most-recent reconstructed set whose K-of-N the head
// satisfies. This is the fix for verifying a historical cosigned head (e.g. a
// year-1 STH) against the set that ACTUALLY cosigned it, not the current set.
func (r *HistoricalWitnessSetResolver) SetForHead(ctx context.Context, head types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	rc, err := r.rebuild(ctx)
	if err != nil {
		return nil, err
	}
	// Build the candidate chain [genesis, S1, ...] by reconstructing at each
	// rotation boundary, then return the set the head's cosignatures satisfy.
	// WitnessSetAtHorizon at each boundary gives the proven set; the most-recent
	// satisfying one wins (head-anchored).
	candidates := []*cosign.WitnessKeySet{r.genesis}
	for i := range rc.records {
		set, err := witness.WitnessSetAtHorizon(r.genesis, rc.records[:i+1], rc.horizon.TreeHead, rc.records[i].EffectivePos)
		if err != nil {
			return nil, fmt.Errorf("auditor/store: reconstruct set after rotation %d: %w", i, err)
		}
		candidates = append(candidates, set)
	}
	for i := len(candidates) - 1; i >= 0; i-- {
		if cosign.VerifyTreeHeadCosignatures(head, candidates[i]) >= candidates[i].Quorum() {
			return candidates[i], nil
		}
	}
	return nil, fmt.Errorf("auditor/store: no reconstructed set cosigns the head at quorum (log %q)", r.logDID)
}
