// Package networkbundle builds the SDK's protocol.NetworkBundle — the "name the
// network, gather the proof" handle — from a genesis bootstrap document. It is
// purely agnostic platform logic (only SDK types), so it lives in the tooling
// platform where the unified CLI and the platform e2e both consume it, rather
// than in any one domain network.
//
// The NetworkBundle carries the network's trust root (network id, genesis witness
// DIDs, quorum, bootstrap hash), the derived witness key set, the read endpoint,
// and the per-network governance vocabulary. The genesis bootstrap itself is NOT
// embedded — it is fetched + hash-verified at use — so the bundle stays small and
// static.
package networkbundle

import (
	"crypto/sha256"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// Vocabulary is the per-network governance vocabulary + the citation key for a
// nested (federation) proof. All fields are optional: a genesis-only network has
// no governance evolution and is not citable.
type Vocabulary struct {
	GovernanceSchemas    map[string]types.LogPosition // section name → schema position
	SignerRotationSchema *types.LogPosition           // signer-rotation schema position
	CitedMemberKey       [32]byte                     // representative member when this network is CITED
}

// Build assembles a validated protocol.NetworkBundle from a genesis bootstrap
// document, the network's read endpoint, and its vocabulary. The witness quorum K
// is doc.GenesisQuorumK — the constitutional, NetworkID-bound value (REQUIRED
// since SDK rc4) is the single source of K; a caller-supplied K could disagree
// with it, so Build takes none. doc.IDs() validates the document (including the
// quorum invariants 1<=K<=N and 2K>N) before K is read. The witness key set is
// derived from the bootstrap's genesis witness DIDs (witness.KeysFromDIDs); the
// trust root's BootstrapDocumentHash is the SHA-256 of the JCS-canonical
// bootstrap bytes (== the NetworkID).
func Build(doc *network.BootstrapDocument, endpoint string, v Vocabulary) (*protocol.NetworkBundle, error) {
	if doc == nil {
		return nil, fmt.Errorf("networkbundle: nil bootstrap document")
	}
	ids, err := doc.IDs()
	if err != nil {
		return nil, fmt.Errorf("networkbundle: bootstrap IDs: %w", err)
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("networkbundle: canonical bytes: %w", err)
	}
	keys, err := witness.KeysFromDIDs(doc.GenesisWitnessSet)
	if err != nil {
		return nil, fmt.Errorf("networkbundle: witness keys from genesis DIDs: %w", err)
	}
	set, err := cosign.NewWitnessKeySet(keys, cosign.NetworkID(ids.NetworkID), doc.GenesisQuorumK, nil)
	if err != nil {
		return nil, fmt.Errorf("networkbundle: witness key set: %w", err)
	}
	b := &protocol.NetworkBundle{
		TrustRoot: protocol.GenesisTrustRoot{
			NetworkID:             cosign.NetworkID(ids.NetworkID),
			GenesisWitnessDIDs:    append([]string(nil), doc.GenesisWitnessSet...),
			QuorumK:               doc.GenesisQuorumK,
			BootstrapDocumentHash: sha256.Sum256(canonical),
		},
		Witnesses:            set,
		Endpoint:             endpoint,
		GovernanceSchemas:    v.GovernanceSchemas,
		SignerRotationSchema: v.SignerRotationSchema,
		CitedMemberKey:       v.CitedMemberKey,
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("networkbundle: %w", err)
	}
	return b, nil
}
