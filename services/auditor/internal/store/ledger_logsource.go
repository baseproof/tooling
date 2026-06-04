// FILE PATH: services/auditor/internal/store/ledger_logsource.go
//
// LedgerLogSource adapts a *clitools.LedgerClient to the
// witnessrotation.LogSource interface so the scan-rebuild engine can rebuild a
// PROVEN witness-rotation chain from a real ledger's HTTP API (the LOG is the
// source of truth, never gossip).
//
// HORIZON-ALIGNED PROOFS. The rebuilder anchors on the witness-cosigned horizon
// and requires every rotation's inclusion proof to bind to that exact horizon
// size (proof.TreeSize == horizon.TreeSize). The ledger's /v1/tree/inclusion
// defaults to the LIVE head (which lags/leads the cosigned horizon), so this
// adapter pins every inclusion fetch to the horizon size via the v1.42.0
// ?tree_size=N parameter (clitools.InclusionProofAtSize). The horizon is fetched
// once and cached for the lifetime of one Rebuild pass.
package store

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/clitools"
	"github.com/baseproof/tooling/libs/witnessrotation"
)

// LedgerLogSource satisfies witnessrotation.LogSource over a clitools ledger
// client. Construct via NewLedgerLogSource; one instance per Rebuild pass (it
// caches the horizon so all inclusion proofs align to the same cosigned size).
type LedgerLogSource struct {
	client *clitools.LedgerClient

	mu      sync.Mutex
	horizon *types.CosignedTreeHead // cached after first CosignedHorizon
}

var _ witnessrotation.LogSource = (*LedgerLogSource)(nil)

// NewLedgerLogSource wraps a ledger client. The client MUST be constructed with
// a logDID (ScanFrom requires it).
func NewLedgerLogSource(client *clitools.LedgerClient) (*LedgerLogSource, error) {
	if client == nil {
		return nil, fmt.Errorf("auditor/store: nil ledger client for LedgerLogSource")
	}
	return &LedgerLogSource{client: client}, nil
}

// ScanRange returns entries in [start, start+count) with canonical bytes.
func (s *LedgerLogSource) ScanRange(ctx context.Context, start uint64, count int) ([]witnessrotation.ScannedEntry, error) {
	raws, err := s.client.ScanFrom(ctx, start, count)
	if err != nil {
		return nil, fmt.Errorf("auditor/store: scan from %d: %w", start, err)
	}
	out := make([]witnessrotation.ScannedEntry, 0, len(raws))
	for _, r := range raws {
		canon, derr := hex.DecodeString(r.CanonicalHex)
		if derr != nil {
			return nil, fmt.Errorf("auditor/store: decode canonical at seq %d: %w", r.Sequence, derr)
		}
		out = append(out, witnessrotation.ScannedEntry{Sequence: r.Sequence, Canonical: canon})
	}
	return out, nil
}

// InclusionProofAt returns the inclusion proof for seq bound to the cosigned
// HORIZON size (fetched once, cached), via the ledger's ?tree_size= param.
func (s *LedgerLogSource) InclusionProofAt(ctx context.Context, seq uint64) (*types.MerkleProof, error) {
	h, err := s.CosignedHorizon(ctx)
	if err != nil {
		return nil, err
	}
	proof, err := s.client.InclusionProofAtSize(seq, h.TreeSize)
	if err != nil {
		return nil, fmt.Errorf("auditor/store: inclusion seq %d @size %d: %w", seq, h.TreeSize, err)
	}
	return proof, nil
}

// CosignedHorizon fetches (and caches) the ledger's latest witness-cosigned
// tree head. Cached so all inclusion proofs in one Rebuild pass align to the
// same horizon — a mid-scan horizon advance would otherwise mismatch
// proof.TreeSize and fail-closed.
func (s *LedgerLogSource) CosignedHorizon(ctx context.Context) (types.CosignedTreeHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.horizon != nil {
		return *s.horizon, nil
	}
	h, err := s.client.Horizon()
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("auditor/store: fetch horizon: %w", err)
	}
	s.horizon = &h
	return h, nil
}
