/*
FILE PATH: libs/accounting/settlement.go

DESCRIPTION:

	Publishes settlement period boundaries as commentary entries on
	the consortium governance log. Tracks deficit/surplus per member.
	Triggers scope removal for persistent free-riders via
	ExecuteRemoval (guide §20.2) with objective triggers enabling
	the 7-day reduced time-lock.

KEY DEPENDENCIES:
  - baseproof/builder: BuildCommentary (guide §11.3)
  - baseproof/lifecycle: ExecuteRemoval, ActivateRemoval (guide §20.2)
*/
package accounting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/lifecycle"
	"github.com/baseproof/baseproof/types"
)

// SettlementManager handles periodic settlement computation and
// publication.
type SettlementManager struct {
	destination string
	signerDID   string
	aggregator  *Aggregator
	params      LoadAccountingParams
}

// NewSettlementManager creates a settlement manager.
func NewSettlementManager(signerDID string, aggregator *Aggregator, params LoadAccountingParams) *SettlementManager {
	return &SettlementManager{
		signerDID:  signerDID,
		aggregator: aggregator,
		params:     params,
	}
}

// SettlementBoundary records a settlement period boundary on-log.
type SettlementBoundary struct {
	PeriodStart    time.Time         `json:"period_start"`
	PeriodEnd      time.Time         `json:"period_end"`
	StartPos       uint64            `json:"start_pos"`
	EndPos         uint64            `json:"end_pos"`
	Ledger         *SettlementLedger `json:"ledger"`
	DeficitMembers []string          `json:"deficit_members,omitempty"`
}

// ComputeAndPublishSettlement computes the settlement ledger for a
// period and publishes it as a commentary entry.
func (sm *SettlementManager) ComputeAndPublishSettlement(
	ctx context.Context,
	periodStart, periodEnd time.Time,
	startPos, endPos uint64,
) (*envelope.Entry, error) {
	ledger, err := sm.aggregator.ComputeSettlement(ctx, startPos, endPos)
	if err != nil {
		return nil, fmt.Errorf("accounting/settlement: compute: %w", err)
	}

	boundary := SettlementBoundary{
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
		StartPos:    startPos,
		EndPos:      endPos,
		Ledger:      ledger,
	}

	payload, err := json.Marshal(map[string]any{
		"attestation_type":    "settlement_boundary",
		"settlement_boundary": boundary,
		"settlement_unit":     sm.params.SettlementUnit,
	})
	if err != nil {
		return nil, fmt.Errorf("accounting/settlement: marshal: %w", err)
	}

	return builder.BuildCommentary(builder.CommentaryParams{
		Destination: sm.destination,
		SignerDID:   sm.signerDID,
		Payload:     payload,
	})
}

// EvaluateDeficit checks whether any member has persistent deficit
// (e.g., failed to pin structural blobs, missed SLA attestations)
// across multiple settlement periods.
func EvaluateDeficit(
	boundaries []SettlementBoundary,
	memberDID string,
	maxConsecutiveDeficits int,
) bool {
	consecutive := 0
	for _, b := range boundaries {
		for _, d := range b.DeficitMembers {
			if d == memberDID {
				consecutive++
				break
			}
		}
		if consecutive >= maxConsecutiveDeficits {
			return true
		}
	}
	return false
}

// InitiateFreeloacherRemoval begins the scope removal process for a
// persistent free-rider. Uses ExecuteRemoval (guide §20.2) with N-1
// consent. The default time-lock is 90 days. If objective triggers
// are provided (failed SLA, missing blobs), the time-lock reduces
// to 7 days.
func InitiateFreeloacherRemoval(
	executorDID string,
	scopePos types.LogPosition,
	targetDID string,
	triggerType lifecycle.ObjectiveTrigger,
	triggerPositions []types.LogPosition,
) (*lifecycle.RemovalExecution, error) {
	return lifecycle.ExecuteRemoval(lifecycle.RemovalParams{
		ExecutorDID:       executorDID,
		ScopePos:          scopePos,
		TargetDID:         targetDID,
		ObjectiveTriggers: triggerPositions,
		TriggerType:       triggerType,
	})
}
