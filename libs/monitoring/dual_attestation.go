/*
FILE PATH: libs/monitoring/dual_attestation.go
DESCRIPTION: Verifies that each active officer has at least two independent

	identity attestations on the log (typically AOC + bar association, or
	court + identity witness). Mitigates single-authority compromise.

KEY ARCHITECTURAL DECISIONS:
  - Queries entries by each officer's DID, filters for attestation-shaped
    Domain Payloads (attestation_type field).
  - Counts distinct ATTESTER DIDs, not entry count — one attester publishing
    multiple attestations is still one attester.
  - Configurable minimum count (default 2).

OVERVIEW: CheckDualAttestation walks the officer roster and reports shortfalls.
KEY DEPENDENCIES: baseproof/log, baseproof/verifier
*/
package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/libs/clitools"
)

const MonitorDualAttestation monitoring.MonitorID = "judicial.dual_attestation"

// DualAttestationConfig configures the dual-attestation monitor.
type DualAttestationConfig struct {
	// RootEntityPos is the court scope entity.
	RootEntityPos types.LogPosition

	// MinimumAttesters is the required distinct attester count. Default 2.
	MinimumAttesters int
}

// CheckDualAttestation walks live delegations and verifies attestation coverage.
// ctx threads into every LedgerQueryAPI / fetcher RPC.
func CheckDualAttestation(
	ctx context.Context,
	cfg DualAttestationConfig,
	queryAPI sdklog.LedgerQueryAPI,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	now time.Time,
) ([]monitoring.Alert, error) {
	minAttesters := cfg.MinimumAttesters
	if minAttesters < 2 {
		minAttesters = 2
	}

	tree, err := verifier.WalkDelegationTree(ctx, verifier.WalkDelegationTreeParams{
		RootEntityPos: cfg.RootEntityPos,
		Fetcher:       fetcher,
		LeafReader:    leafReader,
		Querier:       clitools.NewDelegationQuerier(ctx, queryAPI),
	})

	if err != nil {
		return nil, fmt.Errorf("monitoring/dual_attestation: walk tree: %w", err)
	}

	var alerts []monitoring.Alert

	for _, node := range verifier.LiveDelegations(tree) {
		attesters, err := countAttestersFor(ctx, node.DelegateDID, queryAPI)
		if err != nil {
			continue // query error is not an attestation failure
		}
		if len(attesters) < minAttesters {
			attesterList := make([]string, 0, len(attesters))
			for a := range attesters {
				attesterList = append(attesterList, a)
			}
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorDualAttestation,
				Severity:    monitoring.Warning,
				Destination: monitoring.Both,
				Message: fmt.Sprintf(
					"officer %s has %d distinct attesters, need %d",
					node.DelegateDID, len(attesters), minAttesters,
				),
				Details: map[string]any{
					"officer":          node.DelegateDID,
					"attester_count":   len(attesters),
					"minimum_required": minAttesters,
					"attesters":        attesterList,
					"delegation_depth": node.Depth,
				},
				EmittedAt: now,
			})
		}
	}

	return alerts, nil
}

// countAttestersFor returns the set of distinct DIDs that have published
// attestation commentary entries about the target officer.
//
// Attestation convention (domain-specific, not SDK): commentary entries
// with Domain Payload containing {"attestation_type": "...", "subject_did": "<target>"}.
func countAttestersFor(
	ctx context.Context,
	targetDID string,
	queryAPI sdklog.LedgerQueryAPI,
) (map[string]bool, error) {
	// We query by subject-referencing commentary. The ledger's
	// QueryBySignerDID index isn't keyed on subject_did, so we scan
	// broadly and filter. In production, an ledger-side index on
	// attestation subject would replace this.
	//
	// For the monitor's purposes, we use the pragmatic pattern: scan
	// a reasonable window (caller-provided via ScanStartSeq would be
	// a future enhancement; for now scan 2000 recent entries).
	entries, err := queryAPI.ScanFromPosition(ctx, 0, 2000)
	if err != nil {
		return nil, err
	}

	attesters := make(map[string]bool)
	for _, meta := range entries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil || len(entry.DomainPayload) == 0 {
			continue
		}
		// Commentary only — no TargetRoot, no AuthorityPath.
		if entry.Header.TargetRoot != nil || entry.Header.AuthorityPath != nil {
			continue
		}
		var payload struct {
			AttestationType string `json:"attestation_type"`
			SubjectDID      string `json:"subject_did"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}
		if payload.AttestationType == "" || payload.SubjectDID != targetDID {
			continue
		}
		attesters[entry.Header.SignerDID] = true
	}
	return attesters, nil
}
