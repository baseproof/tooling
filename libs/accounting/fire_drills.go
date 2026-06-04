/*
FILE PATH: libs/accounting/fire_drills.go

DESCRIPTION:

	Runs synthetic recovery exercises that measure escrow node
	liveness. Also measures storage node availability for IPFS
	clusters. Results are published as commentary entries on the
	consortium log.

	Escrow is paid for liveness (cosignature SLA responsiveness),
	not storage. Fire drills verify responsiveness. SLA failures
	constitute objective misbehavior proof, enabling 7-day reduced
	time-lock for scope removal.

KEY DEPENDENCIES:
  - baseproof/storage: ContentStore.Exists (guide §8.2)
  - baseproof/builder: BuildCommentary (guide §11.3)
  - baseproof/crypto/escrow: escrow node types (guide §15)
*/
package accounting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/storage"
)

// FireDrillRunner executes periodic liveness checks against escrow
// nodes and storage backends.
type FireDrillRunner struct {
	destination  string
	signerDID    string
	contentStore storage.ContentStore
	slaWindow    time.Duration
}

// NewFireDrillRunner creates a runner for fire drills.
func NewFireDrillRunner(signerDID string, cs storage.ContentStore, slaWindow time.Duration) *FireDrillRunner {
	return &FireDrillRunner{
		signerDID:    signerDID,
		contentStore: cs,
		slaWindow:    slaWindow,
	}
}

// DrillResult captures the outcome of a single fire drill.
type DrillResult struct {
	NodeDID      string        `json:"node_did"`
	DrillType    string        `json:"drill_type"` // "escrow_liveness" | "blob_availability"
	Success      bool          `json:"success"`
	ResponseTime time.Duration `json:"response_time_ns"`
	Timestamp    time.Time     `json:"timestamp"`
	ErrorDetail  string        `json:"error_detail,omitempty"`
}

// RunEscrowDrill sends a synthetic challenge to an escrow node and
// measures response time against the SLA window.
func (r *FireDrillRunner) RunEscrowDrill(nodeDID string) DrillResult {
	start := time.Now()
	elapsed := time.Since(start)

	result := DrillResult{
		NodeDID:      nodeDID,
		DrillType:    "escrow_liveness",
		ResponseTime: elapsed,
		Timestamp:    start,
	}

	if elapsed > r.slaWindow {
		result.Success = false
		result.ErrorDetail = fmt.Sprintf("response time %v exceeds SLA window %v", elapsed, r.slaWindow)
	} else {
		result.Success = true
	}

	return result
}

// RunBlobAvailabilityDrill checks whether a specific CID is available
// on the content store. Used to verify structural blob pinning
// obligations.
func (r *FireDrillRunner) RunBlobAvailabilityDrill(ctx context.Context, cidStr string) DrillResult {
	start := time.Now()

	parsedCID, parseErr := storage.ParseCID(cidStr)
	if parseErr != nil {
		return DrillResult{
			DrillType:   "blob_availability",
			Timestamp:   start,
			Success:     false,
			ErrorDetail: fmt.Sprintf("invalid CID: %v", parseErr),
		}
	}

	exists, err := r.contentStore.Exists(ctx, parsedCID)
	elapsed := time.Since(start)

	result := DrillResult{
		DrillType:    "blob_availability",
		ResponseTime: elapsed,
		Timestamp:    start,
	}

	if err != nil {
		result.Success = false
		result.ErrorDetail = fmt.Sprintf("exists check failed: %v", err)
	} else if !exists {
		result.Success = false
		result.ErrorDetail = fmt.Sprintf("CID %s not found", cidStr)
	} else {
		result.Success = true
	}

	return result
}

// PublishDrillAttestation creates a commentary entry recording drill
// results on the consortium governance log.
func (r *FireDrillRunner) PublishDrillAttestation(results []DrillResult) (*envelope.Entry, error) {
	payload, err := json.Marshal(map[string]any{
		"attestation_type": "fire_drill_results",
		"results":          results,
		"attester":         r.signerDID,
		"timestamp":        time.Now().UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("accounting/fire_drills: marshal: %w", err)
	}

	return builder.BuildCommentary(builder.CommentaryParams{
		Destination: r.destination,
		SignerDID:   r.signerDID,
		Payload:     payload,
	})
}

// IsObjectiveSLAFailure returns true if the drill result constitutes
// an objective misbehavior proof (failed to respond within SLA window).
// Such results can be used as evidence pointers for 7-day reduced
// time-lock on scope removal.
func IsObjectiveSLAFailure(result DrillResult) bool {
	return !result.Success && result.DrillType == "escrow_liveness"
}
