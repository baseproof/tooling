/*
FILE PATH: libs/monitoring/delegation_health.go
DESCRIPTION: Detects expired/revoked officers still signing entries, and

	orphan delegations (delegations whose grantor is no longer authorized).

KEY ARCHITECTURAL DECISIONS:
  - Uses verifier.WalkDelegationTree to enumerate the current delegation forest.
  - Uses builder.ClassifyEntry to bucket recent signatures by path —
    any Path A/B/C entry signed by a non-live officer is an incident.
  - Orphan check: a delegation is live (OriginTip==self) but its grantor's
    own delegation is dead → chain of trust is broken.

OVERVIEW: CheckDelegationHealth returns alerts for expired signers + orphans.
KEY DEPENDENCIES: baseproof/builder, baseproof/verifier, baseproof/log
*/
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/libs/clitools"
)

const MonitorDelegationHealth monitoring.MonitorID = "judicial.delegation_health"

// DelegationHealthConfig configures the delegation health monitor.
type DelegationHealthConfig struct {
	LocalLogDID    string
	RootEntityPos  types.LogPosition // Court profile scope entity
	ScanLookback   int               // Entries to scan from tip backward
	ScanStartSeq   uint64            // Starting position for the scan
	OfficersLogDID string            // Officers log DID (may equal LocalLogDID)
}

// CheckDelegationHealth walks the delegation tree and the recent entry log,
// flagging entries signed by officers whose delegation is not live and
// delegations whose grantor chain is broken. ctx threads into every
// LedgerQueryAPI / fetcher / verifier RPC.
func CheckDelegationHealth(
	ctx context.Context,
	cfg DelegationHealthConfig,
	queryAPI sdklog.LedgerQueryAPI,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	now time.Time,
) ([]monitoring.Alert, error) {
	if queryAPI == nil {
		return nil, fmt.Errorf("monitoring/delegation: nil query API")
	}

	// 1. Walk the delegation tree. The DelegationQuerier interface
	// is ctx-free; the adapter binds the request ctx into each
	// underlying QueryBySignerDID RPC.
	tree, err := verifier.WalkDelegationTree(ctx, verifier.WalkDelegationTreeParams{
		RootEntityPos: cfg.RootEntityPos,
		Fetcher:       fetcher,
		LeafReader:    leafReader,
		Querier:       clitools.NewDelegationQuerier(ctx, queryAPI),
	})

	if err != nil {
		return nil, fmt.Errorf("monitoring/delegation: walk tree: %w", err)
	}

	// Build liveness lookup: DID → IsLive.
	allNodes := verifier.FlattenTree(tree)
	liveDIDs := make(map[string]bool, len(allNodes))
	for _, node := range allNodes {
		if node.Depth == 0 {
			liveDIDs[node.SignerDID] = true // root entity signer is always authoritative
			continue
		}
		if node.IsLive {
			liveDIDs[node.DelegateDID] = true
		}
	}

	// 2. Check for orphan delegations — live delegations whose grantor chain is broken.
	var alerts []monitoring.Alert
	for _, node := range allNodes {
		if node.Depth == 0 || !node.IsLive {
			continue
		}
		if node.SignerDID == tree.Root.SignerDID {
			continue // direct court-level delegation, always valid
		}
		if !liveDIDs[node.SignerDID] {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorDelegationHealth,
				Severity:    monitoring.Warning,
				Destination: monitoring.Both,
				Message: fmt.Sprintf(
					"orphan delegation: %s → %s (grantor delegation not live)",
					node.SignerDID, node.DelegateDID,
				),
				Details: map[string]any{
					"delegation_pos": node.Position.String(),
					"signer":         node.SignerDID,
					"delegate":       node.DelegateDID,
					"depth":          node.Depth,
				},
				EmittedAt: now,
			})
		}
	}

	// 3. Scan recent entries for non-live signers.
	lookback := cfg.ScanLookback
	if lookback <= 0 {
		lookback = 500
	}
	recentEntries, err := queryAPI.ScanFromPosition(ctx, cfg.ScanStartSeq, lookback)
	if err != nil {
		return alerts, fmt.Errorf("monitoring/delegation: scan recent: %w", err)
	}

	nonLiveSignings := make(map[string]int)
	for _, meta := range recentEntries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil {
			continue
		}
		// Only flag entries that would have been Path A / B / C (state-changing).
		classification, cErr := builder.ClassifyEntry(ctx, builder.ClassifyParams{
			Entry:       entry,
			Position:    meta.Position,
			LeafReader:  leafReader,
			Fetcher:     fetcher,
			LocalLogDID: cfg.LocalLogDID,
		})

		if cErr != nil || classification == nil {
			continue
		}
		switch classification.Path {
		case builder.PathResultPathA, builder.PathResultPathB, builder.PathResultPathC:
			// state-changing — check signer
		default:
			continue
		}

		if !liveDIDs[entry.Header.SignerDID] {
			// The root entity signer is always valid even if not in the delegation tree.
			if entry.Header.SignerDID == tree.Root.SignerDID {
				continue
			}
			nonLiveSignings[entry.Header.SignerDID]++
		}
	}

	for signer, count := range nonLiveSignings {
		alerts = append(alerts, monitoring.Alert{
			Monitor:     MonitorDelegationHealth,
			Severity:    monitoring.Critical,
			Destination: monitoring.Both,
			Message: fmt.Sprintf(
				"non-live signer active: %s published %d state-changing entries",
				signer, count,
			),
			Details: map[string]any{
				"signer_did": signer,
				"count":      count,
				"log_did":    cfg.LocalLogDID,
			},
			EmittedAt: now,
		})
	}

	return alerts, nil
}
