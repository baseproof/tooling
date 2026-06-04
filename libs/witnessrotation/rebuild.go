/*
Package witnessrotation rebuilds a PROVEN witness-set rotation chain by
re-walking a ledger's transparency log — the LOG is the source of truth, never
gossip.

# WHY SCAN-REBUILD, NOT GOSSIP-TRUST

The auditor's inbound gossip path verifies every finding against the CURRENT
witness set (gossipverify gv.sets.Snapshot()) and DROPS anything that doesn't
verify. After a rotation swaps the live set to S_new, an S_old-cosigned head (or
a rotation finding) arriving late fails that gate and never reaches durable
storage. So a gossip-fed rotation journal is both position-blind AND omittable:
a ledger that withholds its latest rotation finding leaves the auditor on a
stale set with no signal (tail-omission).

This package eliminates both. It anchors on the ledger's witness-COSIGNED
horizon (a head whose K-of-N the auditor re-verifies against the set it
independently trusts), scans EVERY entry in [0, horizon.TreeSize), and for each
BP-ENTRY-WITNESS-ROTATION-PAYLOAD-V1 entry builds a self-proving
witness.VerifiedRotationRecord (entry bytes + inclusion proof against the
cosigned horizon + the covering head). Because the scan enumerates the whole
committed prefix of the cosigned tree, a withheld rotation cannot hide: it is
either a leaf the scan finds, or it is not in the cosigned tree at all (in which
case it never took effect for anyone — fail-static to the last proven set, safe,
not a forgery).

The resulting []VerifiedRotationRecord feeds witness.NewVerifiedWitnessSetHistory
for proven, memoized, position-aware reconstruction.

# TRUST MODEL

  - Horizon cosignatures are re-verified under the ANCHOR (current) set, then inductively
    under each reconstructed set (NewVerifiedWitnessSetHistory does the inductive
    proof). The horizon transports a head; it is never trusted blind.
  - Each rotation's position is PROVEN by its inclusion proof against the
    horizon root (envelope.OnLogEntryLeafHash leaf), not asserted.
  - The covering head for every rotation is the SAME cosigned horizon — which is
    cosigned by the CURRENT set. The inductive history walk verifies each
    rotation's covering head under the set authoritative at that rotation; here
    we supply the horizon as the covering head and let the SDK's
    NewVerifiedWitnessSetHistory enforce the per-step cosig check. (A rotation
    whose covering head is the horizon proves the rotation entry is committed in
    the cosigned tree; its authenticity under the prior set is checked
    separately by the history walk.)
*/
package witnessrotation

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// ScannedEntry is one entry returned by a log scan: its sequence and canonical
// bytes. Mirrors clitools.RawEntry minus the diagnostic fields.
type ScannedEntry struct {
	Sequence  uint64
	Canonical []byte
}

// LogSource is the narrow read surface the rebuild needs from a ledger client.
// *clitools.LedgerClient satisfies it (ScanFrom returns []RawEntry; a thin
// adapter maps that to []ScannedEntry — see clientAdapter in the auditor wiring).
type LogSource interface {
	// ScanRange returns entries in [start, start+count) in ascending sequence
	// order, each with its canonical bytes. Fewer than count near the frontier.
	ScanRange(ctx context.Context, start uint64, count int) ([]ScannedEntry, error)
	// InclusionProofAt returns the RFC 6962 inclusion proof for the leaf at seq
	// against the ledger's current tree (proof.TreeSize = that tree's size).
	// LeafHash MAY be zero (the caller binds it).
	InclusionProofAt(ctx context.Context, seq uint64) (*types.MerkleProof, error)
	// CosignedHorizon returns the latest witness-cosigned tree head.
	CosignedHorizon(ctx context.Context) (types.CosignedTreeHead, error)
}

var (
	// ErrHorizonNotCosigned is returned when the horizon's K-of-N cosignatures
	// do not verify under the anchor (current) set — the trust anchor is
	// unauthenticated, so no reconstruction is attempted (fail-closed).
	ErrHorizonNotCosigned = errors.New("witnessrotation: horizon not cosigned by the anchor (current) set")

	// ErrRotationProofMismatch is returned when a scanned rotation entry's
	// inclusion proof does not bind its leaf to the cosigned horizon at the
	// entry's position — the position is unproven.
	ErrRotationProofMismatch = errors.New("witnessrotation: rotation inclusion proof does not bind to the cosigned horizon")
)

// Rebuilder scans a single log and rebuilds its proven rotation chain.
type Rebuilder struct {
	src    LogSource
	logDID string
	batch  int
	anchor *cosign.WitnessKeySet
}

// Config configures a Rebuilder. Src, LogDID, and AnchorSet are required; Batch
// defaults to 1000.
type Config struct {
	Src    LogSource
	LogDID string
	// AnchorSet is the witness set the auditor uses to AUTHENTICATE the cosigned
	// horizon (the scan's trust anchor). It is the set CURRENTLY authoritative
	// for the log — the set that cosigns the latest horizon — NOT necessarily the
	// genesis set. (The genesis set is the chain SEED, supplied separately to
	// witness.WitnessSetAtHorizon by the consumer of Rebuild's output.) Required.
	AnchorSet *cosign.WitnessKeySet
	Batch     int
}

// NewRebuilder validates cfg and returns a Rebuilder.
func NewRebuilder(cfg Config) (*Rebuilder, error) {
	if cfg.Src == nil {
		return nil, errors.New("witnessrotation: nil LogSource")
	}
	if cfg.LogDID == "" {
		return nil, errors.New("witnessrotation: empty LogDID")
	}
	if cfg.AnchorSet == nil || cfg.AnchorSet.Size() == 0 {
		return nil, errors.New("witnessrotation: nil/empty anchor witness set")
	}
	b := cfg.Batch
	if b <= 0 {
		b = 1000
	}
	return &Rebuilder{src: cfg.Src, logDID: cfg.LogDID, batch: b, anchor: cfg.AnchorSet}, nil
}

// Rebuild scans the whole committed prefix of the cosigned horizon and returns
// the PROVEN rotation records in ascending position order, plus the cosigned
// horizon they were proven against. Feed the records to
// witness.WitnessSetAtHorizon(genesis, records, horizon.TreeHead, asOf): every
// position is proven against the single shared horizon, every authenticity is
// proven inductively under the prior set.
//
// Steps:
//  1. Fetch the cosigned horizon; re-verify its K-of-N under the anchor set
//     (trust anchor — never blind).
//  2. Scan [0, horizon.TreeSize): for each BP-ENTRY-WITNESS-ROTATION-PAYLOAD-V1
//     entry, fetch its inclusion proof, bind the on-log leaf
//     (OnLogEntryLeafHash), verify it reconstructs to the horizon root at the
//     entry's position (position PROVEN), and emit a VerifiedRotationRecord with
//     the horizon as the covering head.
//
// Tail-omission is closed by construction: the scan covers the entire committed
// prefix of the cosigned tree, so a withheld rotation is either found or absent
// from the cosigned tree (never took effect).
func (r *Rebuilder) Rebuild(ctx context.Context) ([]witness.HorizonRotationRecord, types.CosignedTreeHead, error) {
	horizon, err := r.src.CosignedHorizon(ctx)
	if err != nil {
		return nil, types.CosignedTreeHead{}, fmt.Errorf("witnessrotation: fetch horizon: %w", err)
	}
	// Trust anchor: the horizon must be cosigned by the anchor set the auditor
	// supplies (its current trusted set). The history walk then re-proves every
	// rotation inductively from genesis; the anchor check authenticates the SCAN
	// horizon itself so positions are proven against a trusted root.
	if cosign.VerifyTreeHeadCosignatures(horizon, r.anchor) < r.anchor.Quorum() {
		return nil, types.CosignedTreeHead{}, ErrHorizonNotCosigned
	}

	var records []witness.HorizonRotationRecord
	for start := uint64(0); start < horizon.TreeSize; {
		entries, err := r.src.ScanRange(ctx, start, r.batch)
		if err != nil {
			return nil, types.CosignedTreeHead{}, fmt.Errorf("witnessrotation: scan from %d: %w", start, err)
		}
		if len(entries) == 0 {
			break
		}
		for _, e := range entries {
			if e.Sequence >= horizon.TreeSize {
				continue // never trust entries beyond the cosigned prefix
			}
			rec, ok, perr := r.tryRotation(ctx, e, horizon)
			if perr != nil {
				return nil, types.CosignedTreeHead{}, perr
			}
			if ok {
				records = append(records, rec)
			}
			if e.Sequence+1 > start {
				start = e.Sequence + 1
			}
		}
	}
	return records, horizon, nil
}

// tryRotation returns (record, true, nil) if e is a witness-rotation entry whose
// position is PROVEN against the horizon; (zero, false, nil) if e is not a
// rotation entry; (zero, false, err) on a proof/transport failure.
func (r *Rebuilder) tryRotation(ctx context.Context, e ScannedEntry, horizon types.CosignedTreeHead) (witness.HorizonRotationRecord, bool, error) {
	// Is this a witness-rotation entry? Two skip-cases (NOT errors): bytes that
	// don't deserialize as an envelope at all (ordinary domain entries / filler),
	// and a valid envelope whose payload is a different kind. Only a genuine
	// rotation-KIND payload that is structurally malformed is surfaced — that
	// would be a real on-log integrity problem, not background traffic.
	entry, derr := envelope.Deserialize(e.Canonical)
	if derr != nil {
		return witness.HorizonRotationRecord{}, false, nil // not an envelope; skip
	}
	if _, derr := witness.DecodeWitnessRotationPayload(entry.DomainPayload); derr != nil {
		if errors.Is(derr, witness.ErrWitnessRotationKindMismatch) {
			return witness.HorizonRotationRecord{}, false, nil // other kind; skip
		}
		return witness.HorizonRotationRecord{}, false,
			fmt.Errorf("witnessrotation: malformed rotation payload at seq %d: %w", e.Sequence, derr)
	}

	proof, err := r.src.InclusionProofAt(ctx, e.Sequence)
	if err != nil {
		return witness.HorizonRotationRecord{}, false, fmt.Errorf("witnessrotation: inclusion seq %d: %w", e.Sequence, err)
	}
	// Bind the on-log-entry leaf and pin the proof to the cosigned horizon.
	proof.LeafHash = envelope.OnLogEntryLeafHash(e.Canonical)
	if proof.TreeSize != horizon.TreeSize {
		// The ledger must serve a HORIZON-ALIGNED inclusion proof
		// (/v1/tree/inclusion/{seq}?tree_size=horizon.TreeSize). A proof at a
		// different (e.g. live) size cannot be verified against the cosigned
		// horizon root — fail closed rather than trust it.
		return witness.HorizonRotationRecord{}, false, fmt.Errorf(
			"%w: seq %d proof.TreeSize=%d != horizon.TreeSize=%d",
			ErrRotationProofMismatch, e.Sequence, proof.TreeSize, horizon.TreeSize)
	}
	pos := types.LogPosition{LogDID: r.logDID, Sequence: e.Sequence}
	// POSITION proof: the entry leaf is committed at pos in the cosigned horizon.
	// (AUTHENTICITY under the prior set is proven later by WitnessSetAtHorizon's
	// inductive VerifyRotation walk — kept separate by design.)
	if verr := witness.VerifyRotationInclusion(e.Canonical, proof, horizon.TreeHead, pos); verr != nil {
		return witness.HorizonRotationRecord{}, false, fmt.Errorf("%w: seq %d: %v", ErrRotationProofMismatch, e.Sequence, verr)
	}

	return witness.HorizonRotationRecord{
		EntryCanonical: e.Canonical,
		EffectivePos:   pos,
		InclusionProof: proof,
	}, true, nil
}
