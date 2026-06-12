/*
FILE PATH: libs/monitoring/derivation_commitment_compliance.go — platform.derivation_commitment_compliance.

Independent re-verification of the ledger's on-log SMT-derivation commitments
(#190). The ledger moves each commitment's mutation set OFF-log behind a
content-addressed MutationsCID and publishes only the fixed-size
storage.SMTDerivationCommitmentRef on the log. The SDK ships the COMPLETE
read-side verifier (verifier.VerifyDerivationCommitmentRef → fetch-by-CID +
verify-on-read + bounded decode + entry replay + post-root compare); this
monitor is the caller the SDK intended — the auditor that performs that
read-side verification.

# THE CHAINED PRIOR-STATE

VerifyDerivationCommitment puts priorState on the CALLER ("Callers are
responsible for ensuring priorState matches PriorSMTRoot; mismatches surface as
a post-root divergence"). The SDK has no "give me the SMT at root R" oracle, so
the monitor CHAINS: it seeds one empty smt.InMemoryLeafStore at genesis, verifies
the refs in ascending LogRangeStart order, and after each Valid result applies
that commitment's mutations to the running store — so the next ref's PriorSMTRoot
holds by construction. A PriorSMTRoot that does NOT chain surfaces as a post-root
divergence (Valid:false) on that ref. The prior is rebuilt from genesis each run
(the only correct way without persisting the SMT).

# CLASSIFICATION
  - verify returns storage.ErrIntegrityViolation → Critical (the off-log blob
    fails its MutationsCID — tampered or wrong bytes).
  - verify returns *FraudProofResult{Valid:false} → Critical (the committed
    mutations do not replay to the claimed PostSMTRoot, or the PriorSMTRoot does
    not chain).
  - any other verify error → Warning (infrastructure: missing entries for the
    replay, content store unreachable — not proof of fraud).

A Valid commitment that then fails to advance the prior (re-fetch/decode error)
is a Warning (the chain may not continue cleanly), never a false fraud Critical.

KEY DEPENDENCIES: baseproof/verifier (the SDK verifier), baseproof/core/smt (the
chained leaf store), baseproof/storage, baseproof/monitoring.
*/
package monitoring

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

const MonitorDerivationCommitmentCompliance monitoring.MonitorID = "platform.derivation_commitment_compliance"

// CommitmentVerifyFunc is the per-ref verification primitive. It matches
// verifier.VerifyDerivationCommitmentRef; production wires that, tests inject a
// fake so the monitor's chaining/classification is exercised without standing up
// the full SMT replay machinery.
type CommitmentVerifyFunc func(
	ctx context.Context,
	ref storage.SMTDerivationCommitmentRef,
	bulk verifier.CommitmentBulkFetcher,
	prior smt.LeafStore,
	fetcher types.EntryFetcher,
	schemaRes builder.SchemaResolver,
	logDID string,
) (*verifier.FraudProofResult, error)

// DerivationCommitmentComplianceConfig configures the monitor. Refs are the
// discovered on-log commitment refs (see crosslog.DiscoverCommitmentRefs);
// BulkStore / Fetcher / SchemaRes are the SDK verifier's inputs. Empty Refs ⇒
// the monitor is unwired and no-ops.
type DerivationCommitmentComplianceConfig struct {
	Refs      []storage.SMTDerivationCommitmentRef
	BulkStore verifier.CommitmentBulkFetcher
	Fetcher   types.EntryFetcher
	SchemaRes builder.SchemaResolver
	LogDID    string

	// Verify is the per-ref primitive; nil ⇒ verifier.VerifyDerivationCommitmentRef.
	Verify CommitmentVerifyFunc
}

// DerivationCommitmentSource returns the latest commitment-audit config (the
// discovered refs + the verifier's inputs). Typically a closure over a
// freshly-walked (or cached) log scan + the content store. A non-nil error
// aborts the cycle. Empty Refs is valid — the monitor then no-ops.
type DerivationCommitmentSource func(ctx context.Context) (DerivationCommitmentComplianceConfig, error)

// CheckDerivationCommitmentCompliance replays every published commitment ref
// against a chained, genesis-seeded prior SMT state and flags any off-log
// integrity failure or post-root divergence. Empty Refs returns no alerts.
func CheckDerivationCommitmentCompliance(
	ctx context.Context,
	cfg DerivationCommitmentComplianceConfig,
	now time.Time,
) ([]monitoring.Alert, error) {
	if len(cfg.Refs) == 0 {
		return nil, nil
	}
	if cfg.BulkStore == nil {
		return []monitoring.Alert{commitmentAlert(monitoring.Warning,
			"derivation-commitment audit has refs but no content store wired (cannot fetch mutation blobs)",
			map[string]any{"refs": len(cfg.Refs)}, now)}, nil
	}
	verify := cfg.Verify
	if verify == nil {
		verify = verifier.VerifyDerivationCommitmentRef
	}

	// Replay in ascending range order so the chained prior is built correctly.
	refs := append([]storage.SMTDerivationCommitmentRef(nil), cfg.Refs...)
	sort.SliceStable(refs, func(i, j int) bool {
		return refs[i].LogRangeStart.Less(refs[j].LogRangeStart)
	})

	prior := smt.NewInMemoryLeafStore()
	var alerts []monitoring.Alert
	for _, ref := range refs {
		res, err := verify(ctx, ref, cfg.BulkStore, prior, cfg.Fetcher, cfg.SchemaRes, cfg.LogDID)
		if err != nil {
			if errors.Is(err, storage.ErrIntegrityViolation) {
				alerts = append(alerts, commitmentAlert(monitoring.Critical,
					"commitment mutations blob fails its MutationsCID (tampered or wrong bytes)",
					refDetails(ref, err), now))
			} else {
				alerts = append(alerts, commitmentAlert(monitoring.Warning,
					"commitment verification could not complete (infrastructure, not proof of fraud)",
					refDetails(ref, err), now))
			}
			continue // cannot advance the chain past an unverified ref
		}
		if res == nil || !res.Valid {
			alerts = append(alerts, commitmentAlert(monitoring.Critical,
				"commitment does not replay to its claimed PostSMTRoot (or PriorSMTRoot does not chain)",
				fraudDetails(ref, res), now))
			continue // do not advance on a divergent commitment
		}
		// Valid → advance the running prior so the next ref's PriorSMTRoot chains.
		if aerr := applyCommittedMutations(ctx, prior, cfg.BulkStore, ref); aerr != nil {
			alerts = append(alerts, commitmentAlert(monitoring.Warning,
				"cannot advance chained prior-state after a valid commitment (subsequent refs may not chain)",
				refDetails(ref, aerr), now))
		}
	}
	return alerts, nil
}

// applyCommittedMutations advances store to a commitment's post-state by applying
// its mutations. It re-fetches + re-verifies the blob (defense in depth over the
// verifier's own verify-on-read) and bounds it, then SetBatches each leaf to its
// NEW (OriginTip, AuthorityTip) — making the running root equal PostSMTRoot for
// the next ref's prior.
func applyCommittedMutations(
	ctx context.Context,
	store smt.LeafStore,
	bulk verifier.CommitmentBulkFetcher,
	ref storage.SMTDerivationCommitmentRef,
) error {
	data, err := bulk.Fetch(ctx, ref.MutationsCID)
	if err != nil {
		return fmt.Errorf("fetch mutations %s: %w", ref.MutationsCID, err)
	}
	if int64(len(data)) > storage.MaxCommitmentMutationsBytes(ref.MutationCount) {
		return fmt.Errorf("mutations blob %d bytes exceeds bound for %d mutations", len(data), ref.MutationCount)
	}
	if !ref.MutationsCID.Verify(data) {
		return fmt.Errorf("%w: mutations blob does not match %s", storage.ErrIntegrityViolation, ref.MutationsCID)
	}
	muts, err := storage.UnmarshalCommitmentMutations(data)
	if err != nil {
		return fmt.Errorf("decode mutations %s: %w", ref.MutationsCID, err)
	}
	leaves := make([]types.SMTLeaf, len(muts))
	for i, m := range muts {
		leaves[i] = types.SMTLeaf{Key: m.LeafKey, OriginTip: m.NewOriginTip, AuthorityTip: m.NewAuthorityTip}
	}
	return store.SetBatch(ctx, leaves)
}

func refDetails(ref storage.SMTDerivationCommitmentRef, err error) map[string]any {
	return map[string]any{
		"range_start":   ref.LogRangeStart.String(),
		"range_end":     ref.LogRangeEnd.String(),
		"mutations_cid": ref.MutationsCID.String(),
		"error":         err.Error(),
	}
}

func fraudDetails(ref storage.SMTDerivationCommitmentRef, res *verifier.FraudProofResult) map[string]any {
	d := map[string]any{
		"range_start":   ref.LogRangeStart.String(),
		"range_end":     ref.LogRangeEnd.String(),
		"mutations_cid": ref.MutationsCID.String(),
	}
	if res != nil {
		d["divergent_leaves"] = len(res.Proofs)
		keys := make([]string, 0, len(res.Proofs))
		for i, p := range res.Proofs {
			if i == 4 { // cap the detail size
				break
			}
			keys = append(keys, fmt.Sprintf("%x", p.LeafKey[:8]))
		}
		d["leaf_key_prefixes"] = keys
	}
	return d
}

func commitmentAlert(sev monitoring.Severity, msg string, details map[string]any, now time.Time) monitoring.Alert {
	return monitoring.Alert{
		Monitor:     MonitorDerivationCommitmentCompliance,
		Severity:    sev,
		Destination: monitoring.Both,
		Message:     msg,
		Details:     details,
		EmittedAt:   now,
	}
}
