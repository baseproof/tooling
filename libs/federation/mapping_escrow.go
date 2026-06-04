/*
FILE PATH: consortium/mapping_escrow.go

DESCRIPTION:

	Vendor-DID ↔ real-DID mapping escrow for the consortium layer.
	v7.75-aligned: uses Pedersen-VSS-backed StoreMappingV2 (and the
	paired ReconstructV2) so every issued share is bound to an
	on-log commitment entry that recipients verify before reconstruct.
	Replaces the V1 plain-Shamir path that had no substitution
	defense.

KEY ARCHITECTURAL DECISIONS:
  - StoreMappingV2 produces an EscrowSplitCommitment + signed
    Path A commentary entry atomically (ADR-005 §3.5). The
    manager surfaces both on the result so the caller can submit
    the commitment entry to the log alongside the share
    distribution. Atomicity is structural: a result with
    Stored/EncShares/Commitment populated implies CommitmentEntry
    is non-nil. The wrapper preserves the invariant.
  - ReconstructV2 verifies each share against the published
    commitment polynomial before Lagrange combination. A
    substituted share is detected at reconstruct time, not at
    application-decrypt time when symptoms surface.
  - Backwards compatibility: pre-Wave-1 callers that need the V1
    plain-Shamir path call escrow.SplitGF256 / ReconstructGF256
    directly. The consortium manager is V2-only by design — the
    vendor-DID mapping is the precise threat surface where
    substitution defense matters most (mis-mapping a sealed
    identity to the wrong vendor DID is catastrophic).

KEY DEPENDENCIES:
  - baseproof/crypto/escrow: SplitV2, ReconstructV2, Share,
    EscrowSplitCommitment.
  - baseproof/exchange/identity: MappingEscrow, StoreMappingV2,
    StoreMappingV2Config, StoreMappingV2Result, EscrowNode,
    EncryptedShare, MappingRecord, CredentialRef, StoredMappingV2.
*/
package federation

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/vss"
	"github.com/baseproof/baseproof/crypto/escrow"
	"github.com/baseproof/baseproof/exchange/identity"
	"github.com/baseproof/baseproof/storage"
)

// MappingEscrowManager handles vendor-DID ↔ real-DID mappings within
// a consortium, backed by the SDK's identity.MappingEscrow V2 path.
type MappingEscrowManager struct {
	escrow       *identity.MappingEscrow
	contentStore storage.ContentStore
	dealerDID    string
	destination  string
	nodes        []identity.EscrowNode
	threshold    int
}

// MappingEscrowConfig configures the mapping escrow manager.
type MappingEscrowConfig struct {
	ContentStore storage.ContentStore
	Nodes        []identity.EscrowNode // DID + secp256k1 PubKey per escrow node
	Threshold    int                   // M in M-of-N

	// DealerDID is the consortium dealer's DID. Required by V2;
	// bound into the deterministic SplitID per ADR-005 §2.
	DealerDID string

	// Destination is the target exchange's DID. Required by V2;
	// threaded into the commitment entry's envelope.
	Destination string
}

// MappingResult bundles every artifact StoreMappingV2 produces.
// CommitmentEntry MUST be submitted to the log alongside the share
// distribution for recipients to be able to verify shares against
// the on-log commitment.
type MappingResult struct {
	Stored          *identity.StoredMappingV2
	EncShares       []identity.EncryptedShare
	Commitment      *escrow.EscrowSplitCommitment
	CommitmentEntry *envelope.Entry
}

// NewMappingEscrowManager creates a manager for vendor-DID mappings.
func NewMappingEscrowManager(cfg MappingEscrowConfig) (*MappingEscrowManager, error) {
	if cfg.ContentStore == nil {
		return nil, fmt.Errorf("federation/mapping_escrow: nil content store")
	}
	if cfg.Threshold < 1 {
		return nil, fmt.Errorf("federation/mapping_escrow: threshold must be >= 1")
	}
	if cfg.Threshold > len(cfg.Nodes) {
		return nil, fmt.Errorf("federation/mapping_escrow: threshold (%d) > node count (%d)",
			cfg.Threshold, len(cfg.Nodes))
	}
	if cfg.DealerDID == "" {
		return nil, fmt.Errorf("federation/mapping_escrow: empty dealer DID")
	}
	if cfg.Destination == "" {
		return nil, fmt.Errorf("federation/mapping_escrow: empty destination DID")
	}

	escrowCfg := identity.DefaultMappingEscrowConfig()
	escrowCfg.ShareThreshold = cfg.Threshold
	escrowCfg.TotalShares = len(cfg.Nodes)
	me := identity.NewMappingEscrow(cfg.ContentStore, escrowCfg)

	return &MappingEscrowManager{
		escrow:       me,
		contentStore: cfg.ContentStore,
		dealerDID:    cfg.DealerDID,
		destination:  cfg.Destination,
		nodes:        cfg.Nodes,
		threshold:    cfg.Threshold,
	}, nil
}

// CreateMapping creates a new identity→credential mapping using V2
// Pedersen VSS. Returns Stored/EncShares plus the EscrowSplitCommitment
// and its signed log entry. Atomic emission per ADR-005 §3.5: every
// success returns all four; the caller submits CommitmentEntry to
// the log alongside the per-node share distribution. ctx bounds the
// SDK's StoreMappingV2 RPC chain.
func (m *MappingEscrowManager) CreateMapping(
	ctx context.Context,
	identityHash [32]byte,
	credRef identity.CredentialRef,
	eventTime int64,
) (*MappingResult, error) {
	record := identity.MappingRecord{
		IdentityHash:  identityHash,
		CredentialRef: credRef,
	}
	cfg := identity.StoreMappingV2Config{
		DealerDID:   m.dealerDID,
		Destination: m.destination,
		EventTime:   eventTime,
	}

	res, err := m.escrow.StoreMappingV2(ctx, record, m.nodes, cfg)
	if err != nil {
		return nil, fmt.Errorf("federation/mapping_escrow: store v2: %w", err)
	}
	// The SDK's atomic-emission invariant (ADR-005 §3.5) guarantees
	// res.CommitmentEntry and res.Commitment are non-nil on success.
	// That contract is pinned by the SDK's own provision_escrow_test.go;
	// no defensive re-check here.

	return &MappingResult{
		Stored:          res.Stored,
		EncShares:       res.EncShares,
		Commitment:      res.Commitment,
		CommitmentEntry: res.CommitmentEntry,
	}, nil
}

// RecoverMapping reconstructs the mapping master secret from M-of-N
// V2 shares. Verifies each share against the published commitment
// polynomial before Lagrange combination — a substituted share is
// rejected at reconstruct time. Caller supplies the commitments
// fetched via FetchEscrowSplitCommitment(splitID).
func (m *MappingEscrowManager) RecoverMapping(
	shares []escrow.Share,
	commitments vss.Commitments,
) ([]byte, error) {
	if len(shares) < m.threshold {
		return nil, fmt.Errorf("federation/mapping_escrow: need %d shares, got %d",
			m.threshold, len(shares))
	}
	secret, err := escrow.ReconstructV2(shares, commitments)
	if err != nil {
		return nil, fmt.Errorf("federation/mapping_escrow: reconstruct v2: %w", err)
	}
	return secret, nil
}

// TransferMapping re-creates a mapping for a new escrow set, with a
// fresh dealer/destination if the new set is operated by a different
// consortium member. The new mapping carries its own SplitID,
// commitment, and on-log commitment entry — the old material is NOT
// rotated in place; rotation is observable on-log via the new
// commitment-entry emission.
func (m *MappingEscrowManager) TransferMapping(
	ctx context.Context,
	identityHash [32]byte,
	credRef identity.CredentialRef,
	newCfg MappingEscrowConfig,
	eventTime int64,
) (*MappingResult, error) {
	destMgr, err := NewMappingEscrowManager(newCfg)
	if err != nil {
		return nil, fmt.Errorf("federation/mapping_escrow: transfer init: %w", err)
	}
	return destMgr.CreateMapping(ctx, identityHash, credRef, eventTime)
}
