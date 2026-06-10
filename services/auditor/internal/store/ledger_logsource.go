// FILE PATH: services/auditor/internal/store/ledger_logsource.go
//
// LedgerLogSource adapts a *clitools.LedgerClient to the
// witnessrotation.LogSource interface so the scan-rebuild engine can rebuild a
// PROVEN witness-rotation chain from a real ledger's HTTP API (the LOG is the
// source of truth, never gossip).
//
// HORIZON-ALIGNED PROOFS. The rebuilder anchors on a witness-cosigned target
// and requires every rotation's inclusion proof to bind to that exact size
// (proof.TreeSize == target.TreeSize). The ledger's /v1/tree/inclusion
// defaults to the LIVE head (which lags/leads the cosigned target), so every
// inclusion fetch is pinned to the caller-named size via the v1.42.0
// ?tree_size=N parameter (clitools.InclusionProofAtSize). The size travels
// explicitly on the interface, so one adapter instance serves any number of
// scan passes — no per-pass horizon caching, no stale-cache hazard.
package store

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/clitools"
	"github.com/baseproof/tooling/libs/witnessrotation"
)

// LedgerLogSource satisfies witnessrotation.LogSource over a clitools ledger
// client. Construct via NewLedgerLogSource; safe to reuse across scan passes.
type LedgerLogSource struct {
	client *clitools.LedgerClient
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

// InclusionProofAtSize returns the inclusion proof for seq computed at the
// caller-named tree size (the cosigned target the rebuilder verified), via the
// ledger's ?tree_size= parameter.
func (s *LedgerLogSource) InclusionProofAtSize(ctx context.Context, seq, treeSize uint64) (*types.MerkleProof, error) {
	_ = ctx // clitools' proof fetch carries its own request timeout
	proof, err := s.client.InclusionProofAtSize(seq, treeSize)
	if err != nil {
		return nil, fmt.Errorf("auditor/store: inclusion seq %d @size %d: %w", seq, treeSize, err)
	}
	return proof, nil
}

// CosignedHorizon fetches the ledger's latest witness-cosigned tree head —
// fresh on every call (the scan reconciler decides per pass which verified
// target to bind proofs to).
func (s *LedgerLogSource) CosignedHorizon(_ context.Context) (types.CosignedTreeHead, error) {
	h, err := s.client.Horizon()
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("auditor/store: fetch horizon: %w", err)
	}
	return h, nil
}
