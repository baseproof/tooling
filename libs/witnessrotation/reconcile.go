// FILE PATH: libs/witnessrotation/reconcile.go
//
// ScanReconciler — the periodic, INCREMENTAL log-scan that keeps a durable
// rotation journal reconciled with the on-log truth (AT-2; the CQRS write side
// of journal-first witness-set resolution).
//
// # THE CQRS SPLIT THIS COMPLETES
//
// The fast read path is the JOURNAL: position-bearing, gossip-fed verified
// rotations that witness.WitnessSetAt replays in O(chain) per resolution. But a
// gossip-fed journal alone is omittable — a ledger that withholds its rotation
// finding leaves every downstream verifier on a stale set with no signal
// (tail-omission). The Rebuilder's full log scan closes that, but a full
// re-scan per pass is O(history) — untenable at year-15 scale.
//
// ScanReconciler is the bounded middle: each RunOnce covers ONLY
// [cursor, target.TreeSize) — the suffix not yet scanned — and advances a
// durable cursor on success. Coverage is cumulative and complete: the first
// pass (cursor 0) scans the whole committed prefix once; every later pass costs
// O(new entries). A withheld rotation is therefore found within one scan
// interval of being committed, or it is not in the cosigned tree at all (in
// which case it never took effect for anyone — fail-static, not a forgery).
//
// # ASYNC TRUST MODEL (the stale-anchor crux)
//
// The scan target must be a cosigned head the reconciler can authenticate. The
// anchor is the journal-reconstructed CURRENT set (genesis + verified chain).
// Asynchrony creates one hard case: the ledger rotated, the rotation finding
// has not arrived via gossip, and the live horizon is already cosigned by
// S_new — the anchor (still S_old) cannot verify it. Scanning is exactly what
// would discover the missing rotation, so failing permanently would deadlock.
//
// The structural escape is the FALLBACK TARGET: the latest cosigned head this
// process already verified and durably stored (the auditor's evidence store).
// That head is S_old-cosigned — the anchor CAN verify it — and its committed
// prefix contains the rotation entry (the ledger commits the rotation BEFORE
// cosigning under S_new). One degraded pass against the fallback discovers and
// journals the rotation; the next pass's anchor includes S_new and the live
// horizon verifies again. Self-healing, never trust-expanding: every target is
// verified under the reconstructed chain before a single entry is trusted.
//
// If NEITHER target verifies, RunOnce fails loudly (ErrNoVerifiableTarget) —
// that is a genuine safety signal (an unexplainable cosigner set), not a
// condition to paper over.
//
// # WHAT GETS JOURNALED
//
// Only rotations that pass the full inductive authenticity walk (genesis →
// chain → candidate, witness.VerifyRotation per step) are recorded — the
// journal stores VERIFIED rotations only, so journal-first readers
// (witness.WitnessSetAt) can fail-closed on corruption rather than resolve
// through a poisoned record. An on-log rotation-kind entry that FAILS the walk
// is reported as ErrOnLogRotationInvalid and NOT journaled: a committed-but-
// unauthorized rotation entry is evidence of ledger misbehavior, and the
// cursor does not advance past it (every subsequent pass re-flags it).
package witnessrotation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

var (
	// ErrJournalChainBroken is returned when the journal's existing rotation
	// chain fails the inductive authenticity walk from genesis — the durable
	// read-model is corrupt (or seeded with the wrong genesis) and MUST NOT be
	// extended. Recovery: purge the journal for this log and let the next pass
	// rebuild it from the log (the journal is a rebuildable projection).
	ErrJournalChainBroken = errors.New("witnessrotation: journal rotation chain broken")

	// ErrOnLogRotationInvalid is returned when a rotation-kind entry committed
	// in the cosigned tree fails authenticity under the set authoritative at
	// its position. This is EVIDENCE (the ledger admitted an unauthorized
	// rotation), not noise: the record is not journaled and the cursor is not
	// advanced past it.
	ErrOnLogRotationInvalid = errors.New("witnessrotation: on-log rotation entry fails authenticity under the prior set")

	// ErrNoVerifiableTarget is returned when neither the live horizon nor the
	// fallback verified head authenticates under the journal-reconstructed
	// current set — the log's cosigner set cannot be explained by the proven
	// rotation chain. Loud by design; see the async trust model above.
	ErrNoVerifiableTarget = errors.New("witnessrotation: no scan target verifies under the reconstructed current set")
)

// RotationJournal is the durable verified-rotation chain the reconciler reads
// (to reconstruct the anchor) and appends (newly discovered rotations). The
// auditor's PostgresWitnessRotationJournal satisfies it. RecordRotation MUST be
// idempotent on (LogDID, EffectivePos) — the scan re-discovers gossip-fed rows.
type RotationJournal interface {
	RecordsFor(ctx context.Context, logDID string) ([]types.WitnessRotationRecord, error)
	RecordRotation(ctx context.Context, record types.WitnessRotationRecord) error
}

// CursorStore persists the per-log scan watermark: every position below the
// cursor has been scanned by some past pass. Implementations return 0 (and no
// error) for a log never scanned.
type CursorStore interface {
	ScanCursor(ctx context.Context, logDID string) (uint64, error)
	SetScanCursor(ctx context.Context, logDID string, scannedUntil uint64) error
}

// VerifiedHeadSource supplies the latest cosigned head this process has
// ALREADY verified and durably stored (e.g. the auditor's evidence store) —
// the fallback scan target for the stale-anchor case. Optional; ok=false when
// no verified head is held for the log.
type VerifiedHeadSource interface {
	LatestVerifiedHead(ctx context.Context, logDID string) (types.CosignedTreeHead, bool, error)
}

// ScanReconciler reconciles one log's rotation journal against the log itself.
// Construct via NewScanReconciler; drive RunOnce on a scheduler.
type ScanReconciler struct {
	src      LogSource
	journal  RotationJournal
	cursor   CursorStore
	fallback VerifiedHeadSource // optional; nil ⇒ no degraded path
	genesis  *cosign.WitnessKeySet
	logDID   string
	batch    int
	logger   *slog.Logger
}

// ScanReconcilerConfig configures a ScanReconciler. Src, Journal, Cursor,
// Genesis, and LogDID are required; Fallback is optional; Batch defaults to
// 1000.
type ScanReconcilerConfig struct {
	Src      LogSource
	Journal  RotationJournal
	Cursor   CursorStore
	Fallback VerifiedHeadSource
	// Genesis is the log's year-1 witness set from the network bootstrap — the
	// chain SEED every reconstruction replays from. Required.
	Genesis *cosign.WitnessKeySet
	LogDID  string
	Batch   int
	Logger  *slog.Logger
}

// NewScanReconciler validates cfg and returns a ScanReconciler.
func NewScanReconciler(cfg ScanReconcilerConfig) (*ScanReconciler, error) {
	if cfg.Src == nil {
		return nil, errors.New("witnessrotation: nil LogSource")
	}
	if cfg.Journal == nil {
		return nil, errors.New("witnessrotation: nil RotationJournal")
	}
	if cfg.Cursor == nil {
		return nil, errors.New("witnessrotation: nil CursorStore")
	}
	if cfg.Genesis == nil || cfg.Genesis.Size() == 0 {
		return nil, errors.New("witnessrotation: nil/empty genesis witness set")
	}
	if cfg.LogDID == "" {
		return nil, errors.New("witnessrotation: empty LogDID")
	}
	b := cfg.Batch
	if b <= 0 {
		b = 1000
	}
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}
	return &ScanReconciler{
		src: cfg.Src, journal: cfg.Journal, cursor: cfg.Cursor,
		fallback: cfg.Fallback, genesis: cfg.Genesis, logDID: cfg.LogDID,
		batch: b, logger: lg,
	}, nil
}

// ScanReport summarizes one RunOnce pass.
type ScanReport struct {
	LogDID string
	// From/Until bound the window covered this pass: [From, Until). Until ==
	// From means a no-op pass (no new committed prefix to scan).
	From, Until uint64
	// Discovered counts rotation entries found in the window (including ones
	// the journal already held via gossip).
	Discovered int
	// NewlyJournaled counts rotations recorded for the first time this pass —
	// each one is a rotation gossip MISSED (tail-omission caught) or a fresh
	// boot backfilling history.
	NewlyJournaled int
	// DegradedTarget is true when the live horizon did not verify under the
	// reconstructed current set and the pass scanned against the fallback
	// verified head instead (the stale-anchor escape).
	DegradedTarget bool
}

// RunOnce performs one bounded reconciliation pass. It never advances the
// cursor unless every discovered rotation in the window was verified and
// durably journaled — a failed pass is re-covered in full by the next one.
func (s *ScanReconciler) RunOnce(ctx context.Context) (ScanReport, error) {
	report := ScanReport{LogDID: s.logDID}

	// 1. Reconstruct the anchor (the journal-proven CURRENT set). A broken
	//    chain is journal corruption — never extend it.
	existing, err := s.journal.RecordsFor(ctx, s.logDID)
	if err != nil {
		return report, fmt.Errorf("witnessrotation: read journal for %q: %w", s.logDID, err)
	}
	anchor, _, err := walkChain(s.genesis, existing)
	if err != nil {
		return report, fmt.Errorf("%w: %s: %v", ErrJournalChainBroken, s.logDID, err)
	}

	from, err := s.cursor.ScanCursor(ctx, s.logDID)
	if err != nil {
		return report, fmt.Errorf("witnessrotation: read scan cursor for %q: %w", s.logDID, err)
	}
	report.From, report.Until = from, from

	// 2. Pick a verifiable target: the live horizon, else the fallback head.
	target, degraded, err := s.pickTarget(ctx, anchor, from)
	if err != nil {
		return report, err
	}
	report.DegradedTarget = degraded
	if target.TreeSize <= from {
		return report, nil // nothing new committed since the last pass
	}

	// 3. Scan the window; every record is position-proven against the target.
	rb, err := NewRebuilder(Config{Src: s.src, LogDID: s.logDID, AnchorSet: anchor, Batch: s.batch})
	if err != nil {
		return report, fmt.Errorf("witnessrotation: rebuilder: %w", err)
	}
	scanned, err := rb.RebuildWindow(ctx, from, target)
	if err != nil {
		return report, err
	}
	report.Discovered = len(scanned)

	// 4. Verify authenticity inductively across the MERGED chain (journal ∪
	//    window) and journal only what verifies. The merged walk matters: a
	//    fresh window can contain several chained rotations, and gossip may
	//    have journaled some of them already.
	newly, err := s.verifyAndJournal(ctx, existing, scanned)
	report.NewlyJournaled = newly
	if err != nil {
		return report, err
	}

	// 5. Coverage is durable only now.
	if err := s.cursor.SetScanCursor(ctx, s.logDID, target.TreeSize); err != nil {
		return report, fmt.Errorf("witnessrotation: persist scan cursor for %q: %w", s.logDID, err)
	}
	report.Until = target.TreeSize
	return report, nil
}

// pickTarget returns a cosigned head verified under anchor: the live horizon
// when possible, else the fallback verified head (degraded=true) when it both
// verifies and extends the cursor. Fail-closed otherwise.
func (s *ScanReconciler) pickTarget(ctx context.Context, anchor *cosign.WitnessKeySet, from uint64) (types.CosignedTreeHead, bool, error) {
	horizon, err := s.src.CosignedHorizon(ctx)
	if err != nil {
		return types.CosignedTreeHead{}, false, fmt.Errorf("witnessrotation: fetch horizon for %q: %w", s.logDID, err)
	}
	if cosign.VerifyTreeHeadCosignatures(horizon, anchor) >= anchor.Quorum() {
		return horizon, false, nil
	}
	if s.fallback != nil {
		h, ok, ferr := s.fallback.LatestVerifiedHead(ctx, s.logDID)
		if ferr != nil {
			return types.CosignedTreeHead{}, false, fmt.Errorf("witnessrotation: fallback head for %q: %w", s.logDID, ferr)
		}
		if ok && h.TreeSize > from && cosign.VerifyTreeHeadCosignatures(h, anchor) >= anchor.Quorum() {
			s.logger.Warn("witnessrotation: live horizon not cosigned by reconstructed current set; scanning against the last verified head (stale-anchor escape)",
				slog.String("log_did", s.logDID),
				slog.Uint64("horizon_size", horizon.TreeSize),
				slog.Uint64("fallback_size", h.TreeSize))
			return h, true, nil
		}
	}
	return types.CosignedTreeHead{}, false, fmt.Errorf("%w: %s (horizon TreeSize=%d)",
		ErrNoVerifiableTarget, s.logDID, horizon.TreeSize)
}

// verifyAndJournal merges the scanned window into the existing chain, walks the
// whole merged chain from genesis verifying each step, and journals every
// newly-discovered record. Returns how many records were newly journaled.
func (s *ScanReconciler) verifyAndJournal(ctx context.Context, existing []types.WitnessRotationRecord, scanned []witness.HorizonRotationRecord) (int, error) {
	known := make(map[uint64]struct{}, len(existing))
	for _, r := range existing {
		known[r.EffectivePos.Sequence] = struct{}{}
	}

	type mergedRec struct {
		rec types.WitnessRotationRecord
		new bool
	}
	merged := make([]mergedRec, 0, len(existing)+len(scanned))
	for _, r := range existing {
		merged = append(merged, mergedRec{rec: r})
	}
	for _, hr := range scanned {
		if _, dup := known[hr.EffectivePos.Sequence]; dup {
			continue
		}
		rot, derr := witness.DecodeWitnessRotationEntry(hr.EntryCanonical)
		if derr != nil {
			// RebuildWindow already decoded this payload; a failure here is a
			// programming error, surfaced loudly rather than skipped.
			return 0, fmt.Errorf("witnessrotation: re-decode rotation at %s: %w", hr.EffectivePos, derr)
		}
		merged = append(merged, mergedRec{
			rec: types.WitnessRotationRecord{Rotation: rot, EffectivePos: hr.EffectivePos},
			new: true,
		})
	}
	// Positions are intrinsic and unique; sort the merged chain by sequence.
	for i := 1; i < len(merged); i++ {
		for j := i; j > 0 && merged[j].rec.EffectivePos.Sequence < merged[j-1].rec.EffectivePos.Sequence; j-- {
			merged[j], merged[j-1] = merged[j-1], merged[j]
		}
	}

	newly := 0
	cur := s.genesis
	for i := range merged {
		newKeys, verr := witness.VerifyRotation(merged[i].rec.Rotation, cur)
		if verr != nil {
			if merged[i].new {
				return newly, fmt.Errorf("%w: %s at %s: %v",
					ErrOnLogRotationInvalid, s.logDID, merged[i].rec.EffectivePos, verr)
			}
			return newly, fmt.Errorf("%w: %s at %s: %v",
				ErrJournalChainBroken, s.logDID, merged[i].rec.EffectivePos, verr)
		}
		next, berr := cosign.NewWitnessKeySet(newKeys, cur.NetworkID(), cur.Quorum(), cur.BLSVerifier())
		if berr != nil {
			return newly, fmt.Errorf("witnessrotation: rebuild set after %s: %w", merged[i].rec.EffectivePos, berr)
		}
		cur = next
		if merged[i].new {
			if jerr := s.journal.RecordRotation(ctx, merged[i].rec); jerr != nil {
				return newly, fmt.Errorf("witnessrotation: journal rotation at %s: %w", merged[i].rec.EffectivePos, jerr)
			}
			newly++
			s.logger.Info("witnessrotation: journaled on-log rotation discovered by scan",
				slog.String("log_did", s.logDID),
				slog.Uint64("effective_seq", merged[i].rec.EffectivePos.Sequence))
		}
	}
	return newly, nil
}

// walkChain replays records from genesis, verifying each step, and returns the
// final (current) set plus the number of applied rotations.
func walkChain(genesis *cosign.WitnessKeySet, records []types.WitnessRotationRecord) (*cosign.WitnessKeySet, int, error) {
	cur := genesis
	for i := range records {
		newKeys, err := witness.VerifyRotation(records[i].Rotation, cur)
		if err != nil {
			return nil, i, fmt.Errorf("record %d (%s): %w", i, records[i].EffectivePos, err)
		}
		next, err := cosign.NewWitnessKeySet(newKeys, cur.NetworkID(), cur.Quorum(), cur.BLSVerifier())
		if err != nil {
			return nil, i, fmt.Errorf("record %d: rebuild set: %w", i, err)
		}
		cur = next
	}
	return cur, len(records), nil
}
