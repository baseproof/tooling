/*
FILE PATH: libs/bundle/standalone_witness.go

The witness_rotation_chain gather. A v2 proof must carry the network's proven
witness-set rotation history so the offline verifier can derive the witness set
authoritative at the checkpoint (rc9+ does this horizon-anchored:
witness.WitnessSetAtHorizon).

# TWO PATHS

  - COMMON CASE (never rotated): if the GENESIS witness set still cosigns the
    checkpoint, the network has not rotated — return an empty chain in O(1), with
    NO log scan. This is the path the genesis-only e2e and the overwhelming
    majority of proofs take.
  - ROTATED CASE: rebuild the chain with libs/witnessrotation.Rebuilder, anchored
    on the proof checkpoint — each rotation's position proven by inclusion against
    that ONE checkpoint (the horizon model the rc9 verifier consumes), authenticity
    proven inductively from genesis. The Rebuilder's trust anchor is the ledger's
    CURRENT witness set (GET /v1/network/witnesses/current).

# SCALING (honest)

The Rebuilder scans the committed prefix (O(N)) for tail-omission-resistant
completeness — its auditor-grade design. Only ROTATED networks pay it; the genesis
short-circuit keeps every never-rotated proof O(1). An omitted rotation cannot
forge a proof regardless: the derived set would be stale and the checkpoint's K-of-N
under it would fail closed. A future O(rotations) source is the gossip
KindWitnessRotation feed (BP-GOSSIP-WITNESS-ROTATION-V1).
*/
package bundle

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/witnessrotation"
)

// FetchWitnessRotationChain returns the network's proven witness-set rotation chain
// up to the checkpoint (see the file header for the two paths + the scaling note).
func (g *StandaloneLedgerGather) FetchWitnessRotationChain(ctx context.Context, _ uint64) ([]sdkbundle.RotationElement, error) {
	head, err := g.getHorizon()
	if err != nil {
		return nil, err
	}
	genesisSet, err := g.genesisWitnessSet()
	if err != nil {
		return nil, err
	}
	// Common case: the genesis set still cosigns the checkpoint ⇒ never rotated ⇒
	// empty chain, no scan.
	if cosign.VerifyTreeHeadCosignatures(head, genesisSet) >= genesisSet.Quorum() {
		return nil, nil
	}

	// Rotated: rebuild against the checkpoint, anchored on the ledger's current set.
	anchor, err := g.currentWitnessSet(ctx)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: rotated network — fetch current witness set: %w", err)
	}
	rb, err := witnessrotation.NewRebuilder(witnessrotation.Config{
		Src:       &ledgerLogSource{g: g, horizon: head},
		LogDID:    g.networkLogDID(),
		AnchorSet: anchor,
	})
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: build witness-rotation rebuilder: %w", err)
	}
	records, horizon, err := rb.Rebuild(ctx)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: rebuild witness rotation chain: %w", err)
	}
	out := make([]sdkbundle.RotationElement, len(records))
	for i, rec := range records {
		var inc types.MerkleProof
		if rec.InclusionProof != nil {
			inc = *rec.InclusionProof
		}
		// CommittingHead = the shared horizon (the checkpoint); the rc9 verifier
		// proves the position against it and ignores SMTProof for rotations.
		out[i] = sdkbundle.RotationElement{Record: rec.EntryCanonical, InclusionProof: inc, CommittingHead: horizon}
	}
	return out, nil
}

// genesisWitnessSet rebuilds the genesis witness set OFFLINE from the configured
// bootstrap (the same set the verifier rebuilds from the hash-pinned document).
func (g *StandaloneLedgerGather) genesisWitnessSet() (*cosign.WitnessKeySet, error) {
	ids, err := g.bootstrap.IDs()
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: bootstrap IDs: %w", err)
	}
	keys, err := witness.KeysFromDIDs(g.bootstrap.GenesisWitnessSet)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: KeysFromDIDs: %w", err)
	}
	return cosign.NewWitnessKeySet(keys, cosign.NetworkID(ids.NetworkID), g.bootstrap.GenesisQuorumK, nil)
}

// networkLogDID is the network's own log DID (the walk's ordering key).
func (g *StandaloneLedgerGather) networkLogDID() string {
	if ids, err := g.bootstrap.IDs(); err == nil {
		return ids.DID
	}
	return ""
}

// currentWitnessSet fetches the ledger's currently-active witness set from
// GET /v1/network/witnesses/current — the Rebuilder's trust anchor for a rotated
// network (K preserved from genesis).
func (g *StandaloneLedgerGather) currentWitnessSet(ctx context.Context) (*cosign.WitnessKeySet, error) {
	var view struct {
		Keys []struct {
			ID        string `json:"id"`
			PublicKey string `json:"public_key"`
			SchemeTag uint8  `json:"scheme_tag"`
		} `json:"keys"`
	}
	if err := g.getJSON(ctx, g.baseURL+"/v1/network/witnesses/current", &view); err != nil {
		return nil, err
	}
	if len(view.Keys) == 0 {
		return nil, fmt.Errorf("bundle/standalone: current witness set is empty")
	}
	keys := make([]types.WitnessPublicKey, len(view.Keys))
	for i, k := range view.Keys {
		idb, err := hex.DecodeString(k.ID)
		if err != nil || len(idb) != 32 {
			return nil, fmt.Errorf("bundle/standalone: witness key id[%d]: %v", i, err)
		}
		pub, err := hex.DecodeString(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: witness key public_key[%d]: %v", i, err)
		}
		var id [32]byte
		copy(id[:], idb)
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pub, SchemeTag: k.SchemeTag}
	}
	ids, err := g.bootstrap.IDs()
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: bootstrap IDs: %w", err)
	}
	return cosign.NewWitnessKeySet(keys, cosign.NetworkID(ids.NetworkID), g.bootstrap.GenesisQuorumK, nil)
}

// ledgerLogSource adapts the ledger read API to the Rebuilder's LogSource: the scan
// is the ledger's entry scan; inclusion proofs are taken against the proof
// checkpoint (the shared horizon); the cosigned horizon IS that checkpoint, so the
// rebuilt records bind to the same head the rest of the proof anchors on.
type ledgerLogSource struct {
	g       *StandaloneLedgerGather
	horizon types.CosignedTreeHead
}

func (s *ledgerLogSource) ScanRange(ctx context.Context, start uint64, count int) ([]witnessrotation.ScannedEntry, error) {
	raws, err := s.g.client.ScanFrom(ctx, start, count)
	if err != nil {
		return nil, err
	}
	out := make([]witnessrotation.ScannedEntry, 0, len(raws))
	for _, r := range raws {
		b, err := hex.DecodeString(r.CanonicalHex)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: scan entry %d canonical: %w", r.Sequence, err)
		}
		out = append(out, witnessrotation.ScannedEntry{Sequence: r.Sequence, Canonical: b})
	}
	return out, nil
}

func (s *ledgerLogSource) InclusionProofAtSize(_ context.Context, seq, treeSize uint64) (*types.MerkleProof, error) {
	return s.g.client.InclusionProofAtSize(seq, treeSize)
}

func (s *ledgerLogSource) CosignedHorizon(context.Context) (types.CosignedTreeHead, error) {
	return s.horizon, nil
}
