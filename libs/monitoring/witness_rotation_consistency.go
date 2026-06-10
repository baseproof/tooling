// FILE PATH: libs/monitoring/witness_rotation_consistency.go
//
// CheckWitnessRotationConsistency — the proactive "did the rotation actually
// take effect?" audit, split into the only two properties an ASYNCHRONOUS
// federation can honestly assert:
//
//	SAFETY (provable at any instant, Critical):
//	  - the journaled rotation chain walks clean from genesis (every step
//	    verifies under the prior set — a broken chain is a corrupt trust
//	    root, never extend it);
//	  - the latest verified head is cosigned by a set ON that proven chain.
//	    A head satisfying NO chain set is cosigned by an unexplainable
//	    authority — forged keys or a rotation history we cannot account for.
//
//	LIVENESS (only boundable by a grace window, Warning — never slash):
//	  - a rotation was journaled at time T, yet past T+grace the log's
//	    latest verified head is still cosigned by a PRE-rotation set (the
//	    ledger logged the rotation but keeps cosigning under the old keys),
//	    or no head covering the rotation has been observed at all (stalled
//	    cosigning or stalled gossip);
//	  - FROZEN LOG: the newest verified head was observed more than
//	    MaxHeadAge ago — the log stopped publishing (or gossip stopped
//	    delivering), rotation or not. Freshness semantics come from the
//	    SDK's witness/staleness.go (witness.CheckFreshness), so "stale"
//	    has exactly one definition across the ecosystem.
//
// The grace window is the async-correctness load-bearing piece: the cosign
// switch after a rotation is operationally fuzzy (the SDK documents that
// post-rotation heads are legitimately still old-set-cosigned while the
// builder/endpoint-resolver adopts the new set — see
// baseproof/witness/witness_set_verified.go), and gossip delivers heads and
// rotations on independent schedules. Inside the grace window, divergence is
// expected and silent; only divergence that OUTLIVES the window is a signal.
// Liveness alerts are Warnings by design: a slow adoption is an operational
// fact to chase, not cryptographic proof of fraud.
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// MonitorWitnessRotationConsistency identifies this audit's alerts.
const MonitorWitnessRotationConsistency monitoring.MonitorID = "witness_rotation_consistency"

// DefaultRotationAdoptionGrace bounds how long after a journaled rotation the
// audit tolerates old-set-cosigned heads before warning. Generous by intent:
// adoption requires the ledger's builder to pick up the new set AND a fresh
// head to traverse gossip — both asynchronous.
const DefaultRotationAdoptionGrace = time.Hour

// RotationLogState is one log's inputs, assembled by the caller (the auditor
// reads these from its rotation journal + durable evidence store).
type RotationLogState struct {
	LogDID string
	// Genesis is the log's year-1 witness set from the network bootstrap.
	Genesis *cosign.WitnessKeySet
	// Records is the journaled verified rotation chain, sorted ascending by
	// EffectivePos. Empty means the log has never rotated.
	Records []types.WitnessRotationRecord
	// LatestRotationRecordedAt is when the NEWEST record was journaled — the
	// clock the adoption grace window runs against. Zero when Records is empty.
	LatestRotationRecordedAt time.Time
	// LatestHead is the most recent INDEPENDENTLY VERIFIED cosigned head held
	// for this log (e.g. the auditor's durable evidence store). nil when no
	// verified head is held yet — the audit then has nothing to assert.
	LatestHead *types.CosignedTreeHead
	// LatestHeadAt is when LatestHead was observed/persisted — the clock the
	// frozen-log freshness check runs against (TreeHead carries no timestamp,
	// so observation time is the only honest clock). Zero ⇒ freshness is not
	// assessable for this log and the frozen check is skipped.
	LatestHeadAt time.Time
}

// WitnessRotationConsistencyConfig configures one audit pass.
type WitnessRotationConsistencyConfig struct {
	Logs []RotationLogState
	// Grace is the adoption window for the liveness half. <=0 ⇒
	// DefaultRotationAdoptionGrace.
	Grace time.Duration
	// MaxHeadAge bounds how old the newest verified head may be before the
	// log is flagged FROZEN (Warning). 0 disables the frozen check — the same
	// "no staleness check" semantics as witness.StalenessConfig.MaxAge == 0.
	MaxHeadAge time.Duration
}

// RotationConsistencySource returns the current audit inputs; the scheduler
// job calls it once per pass.
type RotationConsistencySource func(ctx context.Context) (WitnessRotationConsistencyConfig, error)

// CheckWitnessRotationConsistency runs the safety + liveness audit over every
// supplied log. A per-log input problem (nil genesis) is itself an alert, not
// an error — one misconfigured log must not mute the audit for the others.
func CheckWitnessRotationConsistency(
	_ context.Context,
	cfg WitnessRotationConsistencyConfig,
	now time.Time,
) ([]monitoring.Alert, error) {
	grace := cfg.Grace
	if grace <= 0 {
		grace = DefaultRotationAdoptionGrace
	}

	var alerts []monitoring.Alert
	for _, lg := range cfg.Logs {
		alerts = append(alerts, checkOneLog(lg, grace, cfg.MaxHeadAge, now)...)
	}
	return alerts, nil
}

func checkOneLog(lg RotationLogState, grace, maxHeadAge time.Duration, now time.Time) []monitoring.Alert {
	if lg.Genesis == nil || lg.Genesis.Size() == 0 {
		return []monitoring.Alert{{
			Monitor:     MonitorWitnessRotationConsistency,
			Severity:    monitoring.Critical,
			Destination: monitoring.Ops,
			Message:     fmt.Sprintf("witness rotation audit for %s: nil/empty genesis witness set (input bug)", lg.LogDID),
			Details:     map[string]any{"log_did": lg.LogDID},
			EmittedAt:   now,
		}}
	}

	// SAFETY 1 — the chain itself. Walk genesis → end, verifying every step.
	candidates := []*cosign.WitnessKeySet{lg.Genesis}
	cur := lg.Genesis
	for i := range lg.Records {
		newKeys, err := witness.VerifyRotation(lg.Records[i].Rotation, cur)
		if err != nil {
			return []monitoring.Alert{{
				Monitor:     MonitorWitnessRotationConsistency,
				Severity:    monitoring.Critical,
				Destination: monitoring.Both,
				Message: fmt.Sprintf("witness rotation chain BROKEN for %s at record %d (seq %d): %v",
					lg.LogDID, i, lg.Records[i].EffectivePos.Sequence, err),
				Details: map[string]any{
					"log_did":       lg.LogDID,
					"record_index":  i,
					"effective_seq": lg.Records[i].EffectivePos.Sequence,
				},
				EmittedAt: now,
			}}
		}
		next, err := cosign.NewWitnessKeySet(newKeys, cur.NetworkID(), cur.Quorum(), cur.BLSVerifier())
		if err != nil {
			return []monitoring.Alert{{
				Monitor:     MonitorWitnessRotationConsistency,
				Severity:    monitoring.Critical,
				Destination: monitoring.Ops,
				Message:     fmt.Sprintf("witness rotation audit for %s: rebuild set after record %d: %v", lg.LogDID, i, err),
				Details:     map[string]any{"log_did": lg.LogDID, "record_index": i},
				EmittedAt:   now,
			}}
		}
		cur = next
		candidates = append(candidates, cur)
	}

	if lg.LatestHead == nil {
		return nil // nothing verified yet to assert against
	}
	head := *lg.LatestHead

	// SAFETY 2 — the head's cosigner set must be ON the proven chain. Newest
	// candidate first: the era a head satisfies identifies adoption state.
	matched := -1
	for i := len(candidates) - 1; i >= 0; i-- {
		if cosign.VerifyTreeHeadCosignatures(head, candidates[i]) >= candidates[i].Quorum() {
			matched = i
			break
		}
	}
	if matched == -1 {
		return []monitoring.Alert{{
			Monitor:     MonitorWitnessRotationConsistency,
			Severity:    monitoring.Critical,
			Destination: monitoring.Both,
			Message: fmt.Sprintf("latest verified head for %s (TreeSize=%d) is cosigned by NO set on the proven rotation chain — unexplainable cosigner set",
				lg.LogDID, head.TreeSize),
			Details: map[string]any{
				"log_did":   lg.LogDID,
				"tree_size": head.TreeSize,
				"chain_len": len(candidates),
			},
			EmittedAt: now,
		}}
	}

	// LIVENESS, part 1 — FROZEN LOG. The newest verified head (already proven
	// on-chain above) is too old: the log stopped publishing, or gossip
	// stopped delivering — rotation or not. Freshness semantics are the SDK's
	// (witness.CheckFreshness; MaxAge 0 ⇒ check disabled). Independent of the
	// adoption check below: frozen says "nothing new observed", non-adoption
	// says "the rotation never took effect" — different clocks, different
	// remediations, both honest.
	var alerts []monitoring.Alert
	if maxHeadAge > 0 && !lg.LatestHeadAt.IsZero() {
		if fr, ferr := witness.CheckFreshness(lg.LatestHeadAt, now, witness.StalenessConfig{MaxAge: maxHeadAge}); ferr != nil && fr != nil && !fr.IsFresh {
			alerts = append(alerts, monitoring.Alert{
				Monitor:     MonitorWitnessRotationConsistency,
				Severity:    monitoring.Warning,
				Destination: monitoring.Ops,
				Message: fmt.Sprintf("log %s appears FROZEN: newest verified head (TreeSize=%d) observed %s ago (max %s)",
					lg.LogDID, head.TreeSize, fr.Age.Round(time.Second), maxHeadAge),
				Details: map[string]any{
					"log_did":          lg.LogDID,
					"head_tree_size":   head.TreeSize,
					"head_observed_at": lg.LatestHeadAt,
					"age_seconds":      fr.Age.Seconds(),
					"max_age_seconds":  maxHeadAge.Seconds(),
				},
				EmittedAt: now,
			})
		}
	}

	// LIVENESS, part 2 — ADOPTION. Only meaningful when a rotation exists and
	// the grace window has elapsed since it was journaled.
	if len(lg.Records) == 0 || matched == len(candidates)-1 {
		return alerts // never rotated, or the newest set is adopted: healthy
	}
	if lg.LatestRotationRecordedAt.IsZero() || now.Sub(lg.LatestRotationRecordedAt) <= grace {
		return alerts // inside the async adoption window: divergence is expected
	}

	lastRotSeq := lg.Records[len(lg.Records)-1].EffectivePos.Sequence
	reason := "latest verified head still cosigned by a pre-rotation set"
	if head.TreeSize <= lastRotSeq {
		reason = "no verified head covering the rotation observed yet (stalled cosigning or stalled gossip)"
	}
	return append(alerts, monitoring.Alert{
		Monitor:     MonitorWitnessRotationConsistency,
		Severity:    monitoring.Warning,
		Destination: monitoring.Ops,
		Message: fmt.Sprintf("witness rotation for %s not adopted %s after journaling: %s (head TreeSize=%d cosigned by chain set #%d of %d; rotation at seq %d)",
			lg.LogDID, now.Sub(lg.LatestRotationRecordedAt).Round(time.Second), reason,
			head.TreeSize, matched, len(candidates)-1, lastRotSeq),
		Details: map[string]any{
			"log_did":            lg.LogDID,
			"head_tree_size":     head.TreeSize,
			"matched_set_index":  matched,
			"chain_len":          len(candidates),
			"last_rotation_seq":  lastRotSeq,
			"rotation_journaled": lg.LatestRotationRecordedAt,
			"grace_seconds":      grace.Seconds(),
		},
		EmittedAt: now,
	})
}
