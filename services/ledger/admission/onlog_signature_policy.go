/*
FILE PATH: admission/onlog_signature_policy.go

Part II.6 part 2 — the AMENDMENT-AWARE SignaturePolicy resolver.

# WHAT THIS IS

OnLogSignaturePolicyResolver implements SignaturePolicyResolver by
walking on-log BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1 entries (SDK plan §I.18
walker — network/signature_policy_walker.go) on top of the network's
bootstrap-document GenesisSignaturePolicy. The resolved policy reflects
the most recent governance decision at or before the current tree
position — the production-correct posture, not the genesis-only
approximation shipped in II.6 part 1.

# DESIGN — MIRRORS THE EXISTING ONLOG PATTERN

The shape is identical to OnLogAdmissionPolicy and OnLogAdmissionKeyset:

  - SignaturePolicyAmendmentSource is an injected closure returning
    the on-log records (unsorted is fine — the resolver sorts). Wired
    from the QueryAPI in cmd/ledger/boot/wire.
  - TreeSizeProvider supplies the latest tree size — the asOf the
    walker uses. Wired from store.TreeHeadStore.
  - The bootstrap document supplies the genesis baseline; the resolver
    materializes records[0] via network.GenesisRecordFromBootstrap so
    the SDK walker sees one unified records[] slice (no separate
    genesis parameter — the "genesis is just an entry on the log"
    principle).
  - Short TTL cache (typically 30s, matching OnLogAdmissionPolicy).
    Submission gates do NOT pay for a walker pass per submission.

# RequireHybridAfter — TIMESTAMP-DRIVEN HYBRID-AFTER ENFORCEMENT

A SignaturePolicy that sets RequireHybridAfter (a Unix-seconds wall
timestamp) declares the moment after which every entry MUST carry at
least one signature from a post-quantum scheme group (plan §I.7).
The amendment-aware resolver translates this into
MinSigsFromSchemeGroup["pq"]=1 whenever wall-clock now is at or after
the RequireHybridAfter epoch. The genesis-only resolver
(GenesisSignaturePolicyResolver in signature_policy_verifier.go) does
NOT enforce this — its docstring is explicit on the trade-off.

# ERRORS

  - source(ctx) error → wraps ErrSignaturePolicyResolverFailed
  - sizes.LatestTreeSize(ctx) error → wraps ErrSignaturePolicyResolverFailed
  - SDK walker sentinel (ErrSignaturePolicyNoneInEffect, etc.) → wraps
    BOTH ErrSignaturePolicyResolverFailed and the SDK sentinel, so the
    admission pipeline routes via the 500-default (resolver failure)
    AND callers can inspect via errors.Is for diagnostic dispatch.
  - Translated policy fails verifier.EntrySignaturePolicy.Validate (e.g.
    RequireHybridAfter elapsed but no PQ algos admitted) → wraps
    ErrSignaturePolicyResolverFailed. Misconfiguration surfaces as
    infrastructure failure, not a per-entry policy reject — the
    operator must fix the on-log policy.

Plan §II.6 part 2 / §I.7 / §I.18.
*/
package admission

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// SignaturePolicyAmendmentSource returns the on-log BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1
// records (unsorted is fine — the resolver sorts). Wired from the QueryAPI.
// An empty/nil slice is a valid response — the resolver serves the genesis
// alone in that case.
type SignaturePolicyAmendmentSource func(ctx context.Context) ([]network.SignaturePolicyRecord, error)

// TreeSizeProvider returns the current tree size — the leaf COUNT
// committed on the log. Wired from store.TreeHeadStore via the
// treeSizeProviderFunc adapter in wire.go.
//
// A nil-but-no-error head (zero entries committed) MUST be reported as
// tree_size = 0 (not an error); the resolver treats that as "no entries
// admitted yet, the genesis baseline is in effect."
type TreeSizeProvider interface {
	LatestTreeSize(ctx context.Context) (uint64, error)
}

// OnLogSignaturePolicyResolver is the amendment-aware
// SignaturePolicyResolver. Walks on-log amendments on top of the
// bootstrap document's GenesisSignaturePolicy and caches the
// resolved policy behind a TTL.
type OnLogSignaturePolicyResolver struct {
	source    SignaturePolicyAmendmentSource
	sizes     TreeSizeProvider
	bootstrap network.BootstrapDocument
	logDID    string
	networkID [32]byte
	ttl       time.Duration
	now       func() time.Time

	mu                 sync.RWMutex
	cachedPolicy       verifier.EntrySignaturePolicy
	cachedAllowedAlgos map[uint16]struct{}
	cachedAt           time.Time
	loaded             bool
}

// NewOnLogSignaturePolicyResolver constructs the amendment-aware resolver.
//
// The bootstrap document MUST carry a valid GenesisSignaturePolicy — used
// as the records[0] baseline via network.GenesisRecordFromBootstrap.
// Validation runs at construction (defense-in-depth re-check on top of
// BootstrapDocument.IDs / network.validateSignaturePolicyShape) so a
// malformed genesis fails boot, NOT the first admission cycle.
//
// source may return nil/empty records — the resolver then serves the
// genesis only (no amendments yet). The "genesis is just an entry on
// the log" invariant is preserved by the synthetic genesis record at
// LogPosition{LogDID, Sequence: 0}.
//
// sizes is REQUIRED — the resolver cannot determine the active policy
// without the current tree size. A nil sizes is a programmer bug at
// the composition root.
//
// logDID is the ledger's own log DID — used to materialize both the
// genesis LogPosition and the asOf LogPosition (per-DID ordering).
//
// networkID is the genesis record's Checkpoint identity (typically
// doc.IDs().NetworkID, so the genesis record's checkpoint pin-locks
// it to the network identity that hashed the bootstrap).
//
// ttl > 0 caches the resolved policy for the duration. ttl == 0
// disables caching (every Current re-walks).
func NewOnLogSignaturePolicyResolver(
	source SignaturePolicyAmendmentSource,
	sizes TreeSizeProvider,
	bootstrap network.BootstrapDocument,
	logDID string,
	networkID [32]byte,
	ttl time.Duration,
) (*OnLogSignaturePolicyResolver, error) {
	if source == nil {
		return nil, fmt.Errorf("admission: OnLogSignaturePolicyResolver: source required")
	}
	if sizes == nil {
		return nil, fmt.Errorf("admission: OnLogSignaturePolicyResolver: sizes required")
	}
	if logDID == "" {
		return nil, fmt.Errorf("admission: OnLogSignaturePolicyResolver: logDID required")
	}
	// Defense-in-depth: validate the bootstrap's GenesisSignaturePolicy at
	// construction. The bootstrap loader already validates this, but a
	// malformed doc must fail boot rather than every admission cycle.
	if _, err := NewGenesisSignaturePolicyResolver(bootstrap); err != nil {
		return nil, fmt.Errorf("admission: OnLogSignaturePolicyResolver: bootstrap invalid: %w", err)
	}
	return &OnLogSignaturePolicyResolver{
		source:    source,
		sizes:     sizes,
		bootstrap: bootstrap,
		logDID:    logDID,
		networkID: networkID,
		ttl:       ttl,
		now:       time.Now,
	}, nil
}

// Current resolves the network signature policy in effect at the current
// log tree size. Returns the translated verifier.EntrySignaturePolicy +
// the allowed-algo set used by the SignaturePolicy gate's allow-list step.
func (r *OnLogSignaturePolicyResolver) Current(
	ctx context.Context,
) (verifier.EntrySignaturePolicy, map[uint16]struct{}, error) {
	if r.ttl > 0 {
		r.mu.RLock()
		fresh := r.loaded && time.Since(r.cachedAt) < r.ttl
		policy, allowed := r.cachedPolicy, r.cachedAllowedAlgos
		r.mu.RUnlock()
		if fresh {
			return policy, allowed, nil
		}
	}

	treeSize, err := r.sizes.LatestTreeSize(ctx)
	if err != nil {
		return verifier.EntrySignaturePolicy{}, nil,
			fmt.Errorf("%w: tree-size fetch: %v", ErrSignaturePolicyResolverFailed, err)
	}

	amendments, err := r.source(ctx)
	if err != nil {
		return verifier.EntrySignaturePolicy{}, nil,
			fmt.Errorf("%w: amendment source: %v", ErrSignaturePolicyResolverFailed, err)
	}

	// Materialize the genesis as records[0]. The bridge case: a network
	// whose bootstrap carries the genesis policy AND whose log does not
	// yet have a genesis-policy entry. The walker has no idea whether
	// records[0] was synthesized here or decoded from a real on-log
	// entry — the SDK design is intentional.
	originPos := types.LogPosition{LogDID: r.logDID, Sequence: 0}
	genesisRec := network.GenesisRecordFromBootstrap(r.bootstrap, originPos, r.networkID)
	records := make([]network.SignaturePolicyRecord, 0, 1+len(amendments))
	records = append(records, genesisRec)
	records = append(records, amendments...)
	sort.Sort(network.SignaturePolicyByPosition(records))

	// asOf = the position the next entry WILL HAVE. tree_size is the
	// leaf count; the next entry is at sequence == tree_size (0-indexed
	// per store.TreeSizeForCommittedSeq's "+1 convention"). The SDK
	// walker uses INCLUSIVE boundary, so an amendment that landed at
	// EffectivePos == tree_size IS in effect for the next entry.
	asOf := types.LogPosition{LogDID: r.logDID, Sequence: treeSize}
	policy, err := network.ResolveSignaturePolicyAt(records, asOf)
	if err != nil {
		// Join with the resolver-failure sentinel so the admission
		// pipeline routes as 500 (infrastructure), AND preserve the
		// underlying SDK sentinel so callers can inspect via errors.Is
		// (e.g., ErrSignaturePolicyNoneInEffect for diagnostics).
		return verifier.EntrySignaturePolicy{}, nil,
			errors.Join(ErrSignaturePolicyResolverFailed, err)
	}

	sigPolicy, allowed, err := translateSignaturePolicy(policy, r.now())
	if err != nil {
		return verifier.EntrySignaturePolicy{}, nil,
			fmt.Errorf("%w: translated policy invalid: %v", ErrSignaturePolicyResolverFailed, err)
	}

	if r.ttl > 0 {
		r.mu.Lock()
		r.cachedPolicy = sigPolicy
		r.cachedAllowedAlgos = allowed
		r.cachedAt = time.Now()
		r.loaded = true
		r.mu.Unlock()
	}
	return sigPolicy, allowed, nil
}

// translateSignaturePolicy converts a network.SignaturePolicy into the
// verifier.EntrySignaturePolicy + allowedAlgos shape the
// VerifyEntrySignaturePolicy gate consumes.
//
// Honors plan §I.7 RequireHybridAfter — when set and now is at or after
// the timestamp, the translation adds MinSigsFromSchemeGroup["pq"]=1.
// The translated policy is then validated; a hybrid-after requirement
// against a policy that admits no PQ algorithms is unsatisfiable and
// surfaces as a Validate error (which the caller wraps as
// ErrSignaturePolicyResolverFailed — operator must fix on-log policy).
func translateSignaturePolicy(
	p network.SignaturePolicy,
	now time.Time,
) (verifier.EntrySignaturePolicy, map[uint16]struct{}, error) {
	allowed := make(map[uint16]struct{}, len(p.AllowedEntrySigSchemes))
	for _, algo := range p.AllowedEntrySigSchemes {
		allowed[algo] = struct{}{}
	}
	schemeGroups := make(map[uint16]string, len(p.AllowedEntrySigSchemes))
	for _, algo := range p.AllowedEntrySigSchemes {
		if group := conventionalGroupForAlgo(algo); group != "" {
			schemeGroups[algo] = group
		}
	}
	var minSigsFromGroup map[string]uint8
	if p.RequireHybridAfter != nil && now.Unix() >= *p.RequireHybridAfter {
		minSigsFromGroup = map[string]uint8{"pq": 1}
	}
	sigPolicy := verifier.EntrySignaturePolicy{
		MinValidSigs:           p.MinSignaturesPerEntry,
		MinSigsFromSchemeGroup: minSigsFromGroup,
		SchemeGroups:           schemeGroups,
	}
	if err := sigPolicy.Validate(); err != nil {
		return verifier.EntrySignaturePolicy{}, nil, err
	}
	return sigPolicy, allowed, nil
}

// Compile-time guard: OnLogSignaturePolicyResolver satisfies
// SignaturePolicyResolver. Drift surfaces at build time.
var _ SignaturePolicyResolver = (*OnLogSignaturePolicyResolver)(nil)
