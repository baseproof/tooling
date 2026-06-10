// FILE PATH: services/auditor/internal/store/journal_resolver.go
//
// JournalWitnessSetResolver — JOURNAL-FIRST position-aware witness-set
// resolution (the CQRS read side; AT-2).
//
// # WHY JOURNAL-FIRST, NOT SCAN-PER-RESOLUTION
//
// HistoricalWitnessSetResolver proves its chain by re-walking the ledger over
// HTTP — authoritative, but O(committed prefix) per horizon advance: the wrong
// cost model for the per-event verify hot path at year-15 scale. This resolver
// reads the DURABLE journal instead (indexed by (log_did, effective_seq); the
// chain is tiny — rotations are rare) and re-verifies AUTHENTICITY inductively
// from genesis on every resolution via the SDK walkers, so a corrupt journal
// fails closed rather than resolving through a poisoned record.
//
// Positions in the journal are trusted-at-ingest (each carried a proven
// inclusion proof when verified: gossip Tier-2 for reconciler-fed records, a
// cosigned-target inclusion proof for scan-fed ones) and re-PROVEN over time by
// the witnessrotation.ScanReconciler, which re-walks every committed position
// exactly once against a cosigned target (tail-omission closure). Fast live
// reads + bounded authoritative reconciliation = the journal is a rebuildable
// projection of the on-log truth, never bedrock.
//
// # ONE LOG, TWO NAMES (the alias map)
//
// The same log is named by TWO DIDs in this process, and conflating them
// silently breaks resolution:
//
//   - its LOG DID (ControlHeader.Destination) — what the ledger stamps into
//     every rotation finding's EffectivePos.LogDID, hence the key the journal
//     rows carry (see services/ledger/witnessclient/rotation_appender.go);
//   - its gossip-ORIGINATOR did:key — what the verify path keys trust by
//     (WitnessSets[ev.Originator]) and what position-anchored findings fall
//     back to when their anchor names no log.
//
// The resolver therefore canonicalizes every query: each LogTrustRoot declares
// the canonical journal key (the LOG DID) plus its aliases (the originator),
// and SetAt rewrites asOf.LogDID to the canonical before the SDK walk — the
// SDK's own cross-log guard (witness.ErrAsOfLogMismatch) would otherwise
// reject an alias-named query against canonical-keyed records.
//
// # FEDERATION
//
// Resolution is strictly PER LOG: each log carries its own genesis seed, and
// every chain rebuild inherits the genesis set's own NetworkID/Quorum/BLS
// topology (the SDK walkers' rule), so logs spanning networks never
// cross-bind a trust root. Cross-NETWORK peers resolved via crosslog
// federation never enter this resolver.
//
// Satisfies gossipverify.HeadWitnessSetResolver (the inbound verify seam) and
// equivocation.EraWitnessSetResolver (the slasher seam) — conformance pinned
// in journal_resolver_test.go.
package store

import (
	"context"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// RotationRecordSource is the narrow journal read surface the resolver needs.
// *PostgresWitnessRotationJournal satisfies it; tests inject an in-memory fake.
type RotationRecordSource interface {
	RecordsFor(ctx context.Context, logDID string) ([]types.WitnessRotationRecord, error)
}

// LogTrustRoot declares one tracked log: its canonical journal key, the other
// names it is queried by, and its year-1 chain seed.
type LogTrustRoot struct {
	// LogDID is the canonical key — the log's own DID, the value rotation
	// findings stamp into EffectivePos.LogDID and the journal keys rows by.
	LogDID string
	// Aliases are additional names resolving to this log (typically the
	// gossip-originator did:key the verify path uses).
	Aliases []string
	// Genesis is the log's year-1 witness set from the network bootstrap —
	// the chain SEED, never the live current set.
	Genesis *cosign.WitnessKeySet
}

// JournalWitnessSetResolver resolves the era-correct witness set for any log
// the auditor tracks, from the durable rotation journal.
type JournalWitnessSetResolver struct {
	records   RotationRecordSource
	canonical map[string]string                // every accepted name → canonical LogDID
	genesis   map[string]*cosign.WitnessKeySet // canonical LogDID → year-1 seed
}

// NewJournalWitnessSetResolver constructs a resolver over the journal and the
// per-log trust roots.
func NewJournalWitnessSetResolver(records RotationRecordSource, roots []LogTrustRoot) (*JournalWitnessSetResolver, error) {
	if records == nil {
		return nil, fmt.Errorf("auditor/store: nil RotationRecordSource")
	}
	canonical := make(map[string]string, len(roots)*2)
	genesis := make(map[string]*cosign.WitnessKeySet, len(roots))
	for _, root := range roots {
		if root.LogDID == "" {
			return nil, fmt.Errorf("auditor/store: LogTrustRoot with empty LogDID")
		}
		if root.Genesis == nil || root.Genesis.Size() == 0 {
			return nil, fmt.Errorf("auditor/store: nil/empty genesis witness set for %q", root.LogDID)
		}
		if prev, dup := canonical[root.LogDID]; dup && prev != root.LogDID {
			return nil, fmt.Errorf("auditor/store: %q already aliased to %q", root.LogDID, prev)
		}
		canonical[root.LogDID] = root.LogDID
		genesis[root.LogDID] = root.Genesis
		for _, a := range root.Aliases {
			if a == "" || a == root.LogDID {
				continue
			}
			if prev, dup := canonical[a]; dup && prev != root.LogDID {
				return nil, fmt.Errorf("auditor/store: alias %q maps to both %q and %q", a, prev, root.LogDID)
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
		return nil, fmt.Errorf("auditor/store: journal records for %q: %w", canon, err)
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
	return nil, fmt.Errorf("auditor/store: no journaled chain set cosigns the head at quorum (log %q, TreeSize=%d)", canon, head.TreeSize)
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
		return "", nil, fmt.Errorf("auditor/store: unknown log %q (no trust root configured)", logDID)
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
		return nil, "", fmt.Errorf("auditor/store: journal records for %q: %w", canon, err)
	}
	candidates := make([]*cosign.WitnessKeySet, 0, len(records)+1)
	candidates = append(candidates, gen)
	cur := gen
	for i := range records {
		newKeys, verr := witness.VerifyRotation(records[i].Rotation, cur)
		if verr != nil {
			return nil, "", fmt.Errorf("auditor/store: journaled chain broken for %q at record %d (seq %d): %w",
				canon, i, records[i].EffectivePos.Sequence, verr)
		}
		next, berr := cosign.NewWitnessKeySet(newKeys, cur.NetworkID(), cur.Quorum(), cur.BLSVerifier())
		if berr != nil {
			return nil, "", fmt.Errorf("auditor/store: rebuild set for %q after record %d: %w", canon, i, berr)
		}
		cur = next
		candidates = append(candidates, cur)
	}
	return candidates, canon, nil
}

// LatestSTHSource is the narrow evidence-store read the head adapter needs.
// *PostgresStore satisfies it.
type LatestSTHSource interface {
	LatestSTH(ctx context.Context, originator string) (gossip.SignedEvent, bool, error)
}

// STHHeadSource adapts the durable evidence store's latest verified STH into
// witnessrotation.VerifiedHeadSource (the scan reconciler's stale-anchor
// fallback). The evidence store keys events by gossip ORIGINATOR, while the
// scan reconciler names logs canonically — originatorByLog carries the
// translation (canonical LogDID → originator DID); names absent from the map
// pass through unchanged. The event was Tier-2 verified before it was
// persisted (D7), so decoding it back to a CosignedTreeHead re-surfaces an
// already-proven fact.
type STHHeadSource struct {
	src             LatestSTHSource
	originatorByLog map[string]string
}

// NewSTHHeadSource wraps an evidence store. originatorByLog may be nil when
// the caller queries by originator already.
func NewSTHHeadSource(src LatestSTHSource, originatorByLog map[string]string) (*STHHeadSource, error) {
	if src == nil {
		return nil, fmt.Errorf("auditor/store: nil LatestSTHSource")
	}
	cp := make(map[string]string, len(originatorByLog))
	for k, v := range originatorByLog {
		cp[k] = v
	}
	return &STHHeadSource{src: src, originatorByLog: cp}, nil
}

// LatestVerifiedHead returns the newest verified cosigned head persisted for
// the log; ok=false when none is held.
func (s *STHHeadSource) LatestVerifiedHead(ctx context.Context, logDID string) (types.CosignedTreeHead, bool, error) {
	key := logDID
	if o, ok := s.originatorByLog[logDID]; ok {
		key = o
	}
	ev, ok, err := s.src.LatestSTH(ctx, key)
	if err != nil {
		return types.CosignedTreeHead{}, false, fmt.Errorf("auditor/store: latest STH for %q: %w", key, err)
	}
	if !ok {
		return types.CosignedTreeHead{}, false, nil
	}
	event, err := findings.FromWire(ev.Kind, ev.Body)
	if err != nil {
		return types.CosignedTreeHead{}, false, fmt.Errorf("auditor/store: decode latest STH for %q: %w", key, err)
	}
	f, isHead := event.(*findings.CosignedTreeHeadFinding)
	if !isHead {
		return types.CosignedTreeHead{}, false, fmt.Errorf("auditor/store: latest STH for %q decoded to %T, want CosignedTreeHeadFinding", key, event)
	}
	return f.Head, true, nil
}
