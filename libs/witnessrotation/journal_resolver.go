// FILE PATH: libs/witnessrotation/journal_resolver.go
//
// JournalWitnessSetResolver — journal-first, position-aware witness-set
// resolution: genesis trust root + the journaled verified-rotation chain,
// replayed through the SDK (witness.WitnessSetAt / witness.VerifyRotation per
// step), yields the set authoritative at any position, for any head, or
// currently — for ANY tracked log, domestic or foreign.
//
// # WHY JOURNAL-FIRST
//
// A live current-set snapshot is position-blind: at a rotation boundary the
// log legitimately keeps emitting heads cosigned by the OUTGOING set for a
// while (the operationally-fuzzy cosign switch), and a snapshot check rejects
// those transitional heads as false fork alarms. Head-anchored resolution
// (SetForHead) lets every head identify its own era; position-anchored
// resolution (SetAt) serves historical asOf queries (ZT-SCN-02, the Year-15
// scenario); CurrentSet is the boot-time anchor reconstruction.
//
// # TRUST MODEL
//
// The ONLY trust inputs are the per-log genesis seeds (LogTrustRoot — the
// year-1 set each network's bootstrap declares, TOFU-pinned by its consumer).
// Every journaled rotation is re-verified under its predecessor on every
// resolution (chain()): a record that does not chain from genesis fails
// loudly, so a poisoned journal row can never resolve. The journal itself is
// a rebuildable cache of each log's on-log rotation entries, never an
// authority.
package witnessrotation

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// RotationRecordSource is the narrow journal read surface the resolver needs.
// Both journal implementations (journalpg.PostgresWitnessRotationJournal and
// MemoryRotationJournal) satisfy it.
type RotationRecordSource interface {
	RecordsFor(ctx context.Context, logDID string) ([]types.WitnessRotationRecord, error)
}

// LogTrustRoot declares one tracked log: its canonical journal key, the other
// names it is queried by, and its year-1 chain seed.
type LogTrustRoot struct {
	// LogDID is the canonical key — the log's own DID, the value rotation
	// findings stamp into EffectivePos.LogDID and the journal keys rows by.
	LogDID string

	// Aliases are additional names this log is queried by (e.g. the gossip
	// originator DID the verify path sees). An alias resolves to the same
	// chain; an alias collision across roots is a configuration fault.
	Aliases []string

	// Genesis is the log's year-1 witness set — the chain seed every
	// reconstruction replays from. Required, non-empty.
	Genesis *cosign.WitnessKeySet
}

// JournalWitnessSetResolver resolves witness sets journal-first. Construct via
// NewJournalWitnessSetResolver; safe for concurrent use (the maps are
// write-once at construction; the journal owns its own concurrency).
type JournalWitnessSetResolver struct {
	records   RotationRecordSource
	canonical map[string]string // any accepted name → canonical LogDID
	genesis   map[string]*cosign.WitnessKeySet
}

// NewJournalWitnessSetResolver validates the trust roots (non-empty genesis
// per log; no alias collisions) and returns the resolver.
func NewJournalWitnessSetResolver(records RotationRecordSource, roots []LogTrustRoot) (*JournalWitnessSetResolver, error) {
	if records == nil {
		return nil, fmt.Errorf("witnessrotation: nil RotationRecordSource")
	}
	canonical := make(map[string]string, len(roots)*2)
	genesis := make(map[string]*cosign.WitnessKeySet, len(roots))
	for _, root := range roots {
		if root.LogDID == "" {
			return nil, fmt.Errorf("witnessrotation: LogTrustRoot with empty LogDID")
		}
		if root.Genesis == nil || root.Genesis.Size() == 0 {
			return nil, fmt.Errorf("witnessrotation: nil/empty genesis witness set for %q", root.LogDID)
		}
		if prev, dup := canonical[root.LogDID]; dup && prev != root.LogDID {
			return nil, fmt.Errorf("witnessrotation: %q already aliased to %q", root.LogDID, prev)
		}
		canonical[root.LogDID] = root.LogDID
		genesis[root.LogDID] = root.Genesis
		for _, a := range root.Aliases {
			if a == "" || a == root.LogDID {
				continue
			}
			if prev, dup := canonical[a]; dup && prev != root.LogDID {
				return nil, fmt.Errorf("witnessrotation: alias %q maps to both %q and %q", a, prev, root.LogDID)
			}
			canonical[a] = root.LogDID
		}
	}
	return &JournalWitnessSetResolver{records: records, canonical: canonical, genesis: genesis}, nil
}

// SetAt returns the witness set authoritative on logDID at asOf, replaying the
// journaled chain from genesis via the SDK's witness.WitnessSetAt (authenticity
// re-verified every step; asOf mandatory per ZT-IMM-01). asOf.LogDID is
// rewritten to the log's canonical DID — an alias names the SAME log, and the
// sequence is the position; the SDK's cross-log guard would otherwise reject
// the alias-named query against canonical-keyed records.
func (r *JournalWitnessSetResolver) SetAt(ctx context.Context, logDID string, asOf types.LogPosition) (*cosign.WitnessKeySet, error) {
	canon, gen, err := r.root(logDID)
	if err != nil {
		return nil, err
	}
	records, err := r.records.RecordsFor(ctx, canon)
	if err != nil {
		return nil, fmt.Errorf("witnessrotation: journal records for %q: %w", canon, err)
	}
	return witness.WitnessSetAt(gen, records, types.LogPosition{LogDID: canon, Sequence: asOf.Sequence})
}

// SetForHead returns the set authoritative for a SPECIFIC cosigned head —
// head-anchored: the most-recent chain set whose K-of-N the head's
// cosignatures satisfy. Head-anchoring is what makes a transitional head
// (cosigned by the outgoing set during the operationally-fuzzy adoption
// window) resolve to ITS era's set instead of false-failing against the
// just-installed one. Fail-closed when no chain set explains the head.
func (r *JournalWitnessSetResolver) SetForHead(ctx context.Context, logDID string, head types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	candidates, canon, err := r.chain(ctx, logDID)
	if err != nil {
		return nil, err
	}
	for i := len(candidates) - 1; i >= 0; i-- {
		if cosign.VerifyTreeHeadCosignatures(head, candidates[i]) >= candidates[i].Quorum() {
			return candidates[i], nil
		}
	}
	return nil, fmt.Errorf("witnessrotation: no journaled chain set cosigns the head at quorum (log %q, TreeSize=%d)", canon, head.TreeSize)
}

// CurrentSet replays the FULL journaled chain and returns the newest set —
// the boot-time anchor reconstruction (a restart after rotations must seed the
// live registry with the reconstructed current set, not the genesis: the
// genesis cannot verify a post-rotation horizon and would silently re-open the
// stale-trust gap).
func (r *JournalWitnessSetResolver) CurrentSet(ctx context.Context, logDID string) (*cosign.WitnessKeySet, error) {
	candidates, _, err := r.chain(ctx, logDID)
	if err != nil {
		return nil, err
	}
	return candidates[len(candidates)-1], nil
}

// root resolves any accepted name to (canonical LogDID, genesis seed).
func (r *JournalWitnessSetResolver) root(logDID string) (string, *cosign.WitnessKeySet, error) {
	canon, ok := r.canonical[logDID]
	if !ok {
		return "", nil, fmt.Errorf("witnessrotation: unknown log %q (no trust root configured)", logDID)
	}
	return canon, r.genesis[canon], nil
}

// chain walks genesis → every journaled rotation, verifying each step, and
// returns the full candidate chain [genesis, S1, ..., Sn] plus the canonical
// log DID.
func (r *JournalWitnessSetResolver) chain(ctx context.Context, logDID string) ([]*cosign.WitnessKeySet, string, error) {
	canon, gen, err := r.root(logDID)
	if err != nil {
		return nil, "", err
	}
	records, err := r.records.RecordsFor(ctx, canon)
	if err != nil {
		return nil, "", fmt.Errorf("witnessrotation: journal records for %q: %w", canon, err)
	}
	candidates := make([]*cosign.WitnessKeySet, 0, len(records)+1)
	candidates = append(candidates, gen)
	cur := gen
	for i := range records {
		newKeys, verr := witness.VerifyRotation(records[i].Rotation, cur)
		if verr != nil {
			return nil, "", fmt.Errorf("witnessrotation: journaled chain broken for %q at record %d (seq %d): %w",
				canon, i, records[i].EffectivePos.Sequence, verr)
		}
		next, berr := cosign.NewWitnessKeySet(newKeys, cur.NetworkID(), cur.Quorum(), cur.BLSVerifier())
		if berr != nil {
			return nil, "", fmt.Errorf("witnessrotation: rebuild set for %q after record %d: %w", canon, i, berr)
		}
		cur = next
		candidates = append(candidates, cur)
	}
	return candidates, canon, nil
}
