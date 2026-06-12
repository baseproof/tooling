/*
FILE PATH: anchor/confirm.go

The parent-anchor READ-BACK — the half that closes publishParentAnchor's
202-and-forget: after a successful submit, find OUR anchor on the parent via
its by-source discovery page, read the entry back through the parent log
handle, and record a durable AnchorConfirmation whose verified_at is the
FIRST observation (the store's insert-only law keeps it immutable).

Composition only, through the same seams the auditors use:
  - discovery: the parent's /v1/network/anchors/by-source/{ourLogDID} page
    (anchorfeed.FetchBySourceSeqs) — positions, never authority;
  - provenance: anchorfeed.CollectEvidence over an anchor.MultiLog holding
    the parent's read backend (the SDK MultiLog/EntryProof path);
  - identity: the anchor whose tree_head_ref equals the network-bound digest
    of the head we submitted (cosign.TreeHeadDigest under OUR NetworkID).

"Not found yet" is an error, not a silent skip: the publisher logs it as
published-but-unconfirmed (the alarm direction) and the next tick retries —
RecordFirstSeen is idempotent, so a late confirmation lands exactly once.
*/
package anchor

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	sdkanchor "github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/anchorfeed"
	"github.com/baseproof/tooling/services/ledger/store"
)

// ConfirmationRecorder is the narrow store seam (satisfied by
// *store.AnchorConfirmationStore). RecordFirstSeen returns the DURABLE
// verified_at — unchanged on re-observation.
type ConfirmationRecorder interface {
	RecordFirstSeen(ctx context.Context, c store.AnchorConfirmation) (time.Time, error)
}

// ParentReadBackConfig wires NewParentAnchorConfirmer.
type ParentReadBackConfig struct {
	// ParentLogDID is the parent log the anchors were submitted to.
	ParentLogDID string
	// OwnLogDID is THIS log's DID — the by-source key our anchors carry.
	OwnLogDID string
	// OwnNetworkID binds tree_head_ref digests (cosign.TreeHeadDigest).
	OwnNetworkID cosign.NetworkID
	// FetchSeqs pages the parent's by-source discovery endpoint for
	// OwnLogDID (anchorfeed.FetchBySourceSeqs composed by the wiring).
	FetchSeqs func(ctx context.Context) ([]uint64, error)
	// ParentFetcher reads entries from the parent log (the SDK HTTP entry
	// fetcher in production; a fake in tests).
	ParentFetcher types.EntryFetcher
	// Recorder persists confirmations.
	Recorder ConfirmationRecorder
	// Now is the observation clock (defaults to time.Now).
	Now func() time.Time
}

// NewParentAnchorConfirmer returns the read-back: given the head we just
// submitted, confirm it landed on the parent and record the confirmation.
// Returns an error when the anchor is not (yet) discoverable — the caller
// treats that as published-but-unconfirmed and retries next tick.
func NewParentAnchorConfirmer(cfg ParentReadBackConfig) (func(ctx context.Context, head types.CosignedTreeHead) error, error) {
	if cfg.ParentLogDID == "" || cfg.OwnLogDID == "" {
		return nil, fmt.Errorf("anchor/confirm: ParentLogDID and OwnLogDID required")
	}
	if cfg.FetchSeqs == nil || cfg.ParentFetcher == nil || cfg.Recorder == nil {
		return nil, fmt.Errorf("anchor/confirm: FetchSeqs, ParentFetcher and Recorder required (no silent no-op confirmer)")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ml := sdkanchor.NewMultiLog(map[string]sdkanchor.LogConfig{
		cfg.ParentLogDID: {Fetcher: cfg.ParentFetcher},
	})
	return func(ctx context.Context, head types.CosignedTreeHead) error {
		digest, err := cosign.TreeHeadDigest(head.TreeHead, cfg.OwnNetworkID)
		if err != nil {
			return fmt.Errorf("anchor/confirm: tree head digest: %w", err)
		}
		wantRef := hex.EncodeToString(digest[:])

		seqs, err := cfg.FetchSeqs(ctx)
		if err != nil {
			return fmt.Errorf("anchor/confirm: by-source discovery: %w", err)
		}
		// Zero parent pin: the read-back consumes the decoded ANCHOR (its
		// tree_head_ref + position), not the evidence attribution — evidence
		// assembly for monitors is the auditors' path with the real pin.
		items, errs := anchorfeed.CollectEvidence(ctx, ml, cfg.ParentLogDID, [32]byte{}, seqs, nil, cfg.Now)
		for _, it := range items {
			if it.Anchor.TreeHeadRef != wantRef {
				continue
			}
			stored, rerr := cfg.Recorder.RecordFirstSeen(ctx, store.AnchorConfirmation{
				ParentLogDID:     cfg.ParentLogDID,
				TreeHeadRef:      wantRef,
				ParentSeq:        it.ParentSeq,
				AnchoredTreeSize: head.TreeSize,
				AnchoredAt:       it.Evidence.AnchoredAt,
				VerifiedAt:       cfg.Now().UTC(),
			})
			if rerr != nil {
				return fmt.Errorf("anchor/confirm: record: %w", rerr)
			}
			_ = stored // durable first-seen; re-observation returns the original
			return nil
		}
		return fmt.Errorf("anchor/confirm: anchor %s not discoverable on %s yet (%d anchors paged, %d read errors) — will retry",
			wantRef[:16], cfg.ParentLogDID, len(items), len(errs))
	}, nil
}
