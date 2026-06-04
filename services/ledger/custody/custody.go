/*
Package custody projects the on-log artifact-custody chain and resolves the
(owner, custodian) authoritative at a log position by WALKING it via the SDK's
storage.ArtifactCustodyAt.

The chain is: a genesis ArtifactCustodyRecord (derived from the artifact's
ArtifactGenesis entry) + an EffectivePos-ordered slice of
ArtifactCustodyTransfer links + an optional ArtifactDestruction. ResolveAt sorts
the transfers and hands them to storage.ArtifactCustodyAt, which walks the chain
with per-hop FromOwner == current-owner verification (a forged/orphan transfer
fails the walk closed) and returns the owner/custodian at the requested as-of
position. A destruction whose EffectivePos <= asOf marks the artifact destroyed.

This is the ledger half of artifact-store Phase 6: the SDK ships the data model +
the walk; the ledger projects the on-log entries (baseproof#104 carriage) and feeds
the walk. The custody-aware AuthorizationHook (artifactstore.CustodyHook) calls
ResolveCustodyAt at the request's asOf and admits only the resolved owner or
custodian.
*/
package custody

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"
)

var (
	// ErrSourceFailed wraps a chain-source (query) failure — infrastructure, not
	// a custody decision. Callers fail closed.
	ErrSourceFailed = errors.New("custody: chain source failed")
)

// Chain is the on-log custody chain for one artifact: the genesis custody record
// (from its ArtifactGenesis entry), the EffectivePos-stamped transfer links, and
// an optional destruction record. Found is false when no genesis exists for the
// requested CID.
type Chain struct {
	Genesis     storage.ArtifactCustodyRecord
	Transfers   []storage.ArtifactCustodyTransfer
	Destruction *storage.ArtifactDestruction
	Found       bool
}

// ChainSource returns the custody chain for the served artifact CID. EffectivePos
// on each transfer/destruction MUST be the entry's on-log position (the SDK walk
// orders + bounds by it). Wired from the QueryAPI — see QuerySource.
type ChainSource interface {
	Chain(ctx context.Context, servedCID storage.CID) (Chain, error)
}

// Resolver walks the chain via storage.ArtifactCustodyAt. Pure over its source.
type Resolver struct{ src ChainSource }

// NewResolver builds a Resolver over a ChainSource.
func NewResolver(src ChainSource) *Resolver { return &Resolver{src: src} }

// ResolveCustodyAt resolves the custody state of servedCID at asOf. It projects
// the chain, sorts transfers by EffectivePos, and walks them (per-hop
// FromOwner == current-owner; a forged hop returns an error and the caller fails
// closed). found is false when there is no genesis for the CID. destroyed is
// true when a destruction record is in effect at asOf.
//
// The signature matches artifactstore.CustodyResolver, so a *Resolver satisfies
// that interface structurally (no import in either direction).
func (r *Resolver) ResolveCustodyAt(
	ctx context.Context,
	servedCID storage.CID,
	asOf types.LogPosition,
) (owner, custodian string, destroyed, found bool, err error) {
	ch, sErr := r.src.Chain(ctx, servedCID)
	if sErr != nil {
		return "", "", false, false, fmt.Errorf("%w: %v", ErrSourceFailed, sErr)
	}
	if !ch.Found {
		return "", "", false, false, nil
	}
	// Defensive copy before the in-place sort so a cached source slice is never
	// mutated under a concurrent reader.
	transfers := append([]storage.ArtifactCustodyTransfer(nil), ch.Transfers...)
	storage.SortCustodyTransfers(transfers)

	owner, custodian, err = storage.ArtifactCustodyAt(ch.Genesis, transfers, asOf)
	if err != nil {
		return "", "", false, false, fmt.Errorf("custody: ArtifactCustodyAt: %w", err)
	}
	destroyed = ch.Destruction != nil && !asOf.Less(ch.Destruction.EffectivePos)
	return owner, custodian, destroyed, true, nil
}
