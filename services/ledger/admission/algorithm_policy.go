/*
FILE PATH: admission/algorithm_policy.go

On-log ALGORITHM-POLICY admission gate (crypto-agility).

# WHAT THIS ENFORCES

After per-signature cryptographic verification, this gate rejects an entry
whose ANY signature uses an algorithm the network's CURRENT algorithm policy
does not permit. The policy is the SDK's authz.AlgorithmPolicy — a per-algoID
lifecycle:

	active     → admitted for new writes (PermitsVerification == true)
	deprecated → still admitted (existing + new), flagged for migration
	             (PermitsVerification == true)
	forbidden  → REJECTED for new writes (PermitsVerification == false)

An algoID absent from the policy is also rejected (PermitsVerification == false).
The lifecycle is MONOTONIC (active → deprecated → forbidden, never back) —
enforced by the SDK walker (authz.ResolveAlgorithmPolicyAt) across amendments.

# WHY A SEPARATE GATE FROM SignaturePolicy

network.SignaturePolicy.AllowedEntrySigSchemes is the GENESIS allow-list,
fixed at NetworkID-hash time. The algorithm policy is the POST-GENESIS,
on-log-amendable lifecycle layer: a network deprecates then forbids an
algorithm (e.g. after a published break, or to schedule a classical→PQ
migration) by appending BP-ENTRY-NETWORK-ALGORITHM-POLICY-V1 entries — no
ledger redeploy, no NetworkID change. The two compose: the allow-list bounds
what was ever admissible; the algorithm policy evolves it over time.

# GENESIS BASELINE

There is no GenesisAlgorithmPolicy field on the BootstrapDocument, so the
genesis baseline is SYNTHESIZED from GenesisSignaturePolicy.AllowedEntrySigSchemes
— every genesis-allowed entry algorithm starts ACTIVE. On-log amendments then
deprecate/forbid from that baseline. This keeps the two policies coherent: the
algorithm-policy lifecycle begins exactly at the genesis allow-list.

# FEATURE FLAG

Gated by Gates.AlgorithmPolicy (default OFF). The genesis-only resolver
applies the synthesized baseline (everything active = no-op unless the
allow-list itself rejects); the amendment-aware OnLog resolver (wired when
LEDGER_ALGORITHM_POLICY_SCHEMA is set) applies on-log deprecate/forbid
decisions.

Closes the crypto-agility half of ledger issue #201.
*/
package admission

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// ErrAlgorithmForbidden is returned when an entry signature uses an algoID the
// network's current algorithm policy does not permit (lifecycle "forbidden", or
// absent from the policy). Routes to 403 via admission/error_mapping.go.
var ErrAlgorithmForbidden = errors.New(
	"admission: entry signature algorithm forbidden by network algorithm policy")

// ErrAlgorithmPolicyResolverFailed is returned when the resolver cannot supply a
// current policy (I/O failure, or an unresolvable on-log policy). Distinct from
// ErrAlgorithmForbidden so the pipeline routes it as 500 (infrastructure), not
// 403 (policy reject).
var ErrAlgorithmPolicyResolverFailed = errors.New(
	"admission: algorithm policy resolver failed")

// AlgorithmPolicyResolver returns the network algorithm policy in force right
// now. The static GenesisAlgorithmPolicyResolver ignores ctx; the amendment-
// aware OnLogAlgorithmPolicyResolver honors caller cancellation while its
// underlying walker fetches entries.
type AlgorithmPolicyResolver interface {
	Current(ctx context.Context) (authz.AlgorithmPolicy, error)
}

// VerifyEntryAlgorithmPolicy enforces the network algorithm policy on an entry.
// Returns nil iff every signature's algoID is permitted (active or deprecated).
//
//   - nil resolver → gate disabled (caller opted out via Gates.AlgorithmPolicy).
//   - nil entry → programmer error.
//   - resolver.Current error → ErrAlgorithmPolicyResolverFailed (500).
//   - any signature algoID not permitted → ErrAlgorithmForbidden (403), reported
//     on the first offending signature.
func VerifyEntryAlgorithmPolicy(
	ctx context.Context,
	resolver AlgorithmPolicyResolver,
	entry *envelope.Entry,
) error {
	if resolver == nil {
		return nil
	}
	if entry == nil {
		return fmt.Errorf("admission: VerifyEntryAlgorithmPolicy called with nil entry")
	}
	policy, err := resolver.Current(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAlgorithmPolicyResolverFailed, err)
	}
	for i, sig := range entry.Signatures {
		if !policy.PermitsVerification(sig.AlgoID) {
			state := "absent"
			if rec, ok := policy.Lookup(sig.AlgoID); ok {
				state = string(rec.LifecycleState)
			}
			return fmt.Errorf("%w: signatures[%d] algoID 0x%04x (lifecycle=%s)",
				ErrAlgorithmForbidden, i, sig.AlgoID, state)
		}
	}
	return nil
}

// GenesisAlgorithmPolicyFromBootstrap synthesizes the genesis algorithm policy
// from the bootstrap document's GenesisSignaturePolicy.AllowedEntrySigSchemes:
// every genesis-allowed entry algorithm starts ACTIVE. This is the records[0]
// baseline the walker amends.
func GenesisAlgorithmPolicyFromBootstrap(doc network.BootstrapDocument) authz.AlgorithmPolicy {
	allowed := doc.GenesisSignaturePolicy.AllowedEntrySigSchemes
	recs := make([]authz.AlgorithmRecord, 0, len(allowed))
	for _, algo := range allowed {
		recs = append(recs, authz.AlgorithmRecord{
			AlgoID:         algo,
			LifecycleState: authz.AlgorithmActive,
		})
	}
	return authz.AlgorithmPolicy{Algorithms: recs}
}

// ─────────────────────────────────────────────────────────────────────
// GenesisAlgorithmPolicyResolver — static (genesis baseline only)
// ─────────────────────────────────────────────────────────────────────

// GenesisAlgorithmPolicyResolver always returns the synthesized genesis
// algorithm policy. The default resolver when no on-log algorithm-policy schema
// is configured.
type GenesisAlgorithmPolicyResolver struct {
	policy authz.AlgorithmPolicy
}

// NewGenesisAlgorithmPolicyResolver builds the static resolver from the
// bootstrap document, failing boot (not the first admission) on a malformed
// synthesized policy.
func NewGenesisAlgorithmPolicyResolver(doc network.BootstrapDocument) (*GenesisAlgorithmPolicyResolver, error) {
	p := GenesisAlgorithmPolicyFromBootstrap(doc)
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("admission: genesis algorithm policy invalid: %w", err)
	}
	return &GenesisAlgorithmPolicyResolver{policy: p}, nil
}

// Current implements AlgorithmPolicyResolver. Ignores ctx — no I/O.
func (r *GenesisAlgorithmPolicyResolver) Current(_ context.Context) (authz.AlgorithmPolicy, error) {
	return r.policy, nil
}

// ─────────────────────────────────────────────────────────────────────
// OnLogAlgorithmPolicyResolver — amendment-aware
// ─────────────────────────────────────────────────────────────────────

// AlgorithmPolicyAmendmentSource returns the on-log
// BP-ENTRY-NETWORK-ALGORITHM-POLICY-V1 records (unsorted is fine — the resolver
// sorts). Wired from the QueryAPI. An empty slice is valid: the resolver then
// serves the genesis baseline alone.
type AlgorithmPolicyAmendmentSource func(ctx context.Context) ([]authz.AlgorithmPolicyRecord, error)

// OnLogAlgorithmPolicyResolver walks on-log amendments on top of the synthesized
// genesis baseline and caches the resolved policy behind a TTL — mirrors
// OnLogSignaturePolicyResolver so admission does not pay a walker pass per entry.
type OnLogAlgorithmPolicyResolver struct {
	source    AlgorithmPolicyAmendmentSource
	sizes     TreeSizeProvider
	bootstrap network.BootstrapDocument
	logDID    string
	networkID [32]byte
	ttl       time.Duration

	mu       sync.RWMutex
	cached   authz.AlgorithmPolicy
	cachedAt time.Time
	loaded   bool
}

// NewOnLogAlgorithmPolicyResolver constructs the amendment-aware resolver.
// source + sizes + logDID are required; the genesis baseline is synthesized from
// the bootstrap and validated at construction (fail boot on a bad baseline).
func NewOnLogAlgorithmPolicyResolver(
	source AlgorithmPolicyAmendmentSource,
	sizes TreeSizeProvider,
	bootstrap network.BootstrapDocument,
	logDID string,
	networkID [32]byte,
	ttl time.Duration,
) (*OnLogAlgorithmPolicyResolver, error) {
	if source == nil {
		return nil, fmt.Errorf("admission: OnLogAlgorithmPolicyResolver: source required")
	}
	if sizes == nil {
		return nil, fmt.Errorf("admission: OnLogAlgorithmPolicyResolver: sizes required")
	}
	if logDID == "" {
		return nil, fmt.Errorf("admission: OnLogAlgorithmPolicyResolver: logDID required")
	}
	if err := GenesisAlgorithmPolicyFromBootstrap(bootstrap).Validate(); err != nil {
		return nil, fmt.Errorf("admission: OnLogAlgorithmPolicyResolver: genesis baseline invalid: %w", err)
	}
	return &OnLogAlgorithmPolicyResolver{
		source:    source,
		sizes:     sizes,
		bootstrap: bootstrap,
		logDID:    logDID,
		networkID: networkID,
		ttl:       ttl,
	}, nil
}

// Current resolves the algorithm policy in effect at the current tree size.
func (r *OnLogAlgorithmPolicyResolver) Current(ctx context.Context) (authz.AlgorithmPolicy, error) {
	if r.ttl > 0 {
		r.mu.RLock()
		fresh := r.loaded && time.Since(r.cachedAt) < r.ttl
		cached := r.cached
		r.mu.RUnlock()
		if fresh {
			return cached, nil
		}
	}

	treeSize, err := r.sizes.LatestTreeSize(ctx)
	if err != nil {
		return authz.AlgorithmPolicy{}, fmt.Errorf("%w: tree-size fetch: %v", ErrAlgorithmPolicyResolverFailed, err)
	}
	amendments, err := r.source(ctx)
	if err != nil {
		return authz.AlgorithmPolicy{}, fmt.Errorf("%w: amendment source: %v", ErrAlgorithmPolicyResolverFailed, err)
	}

	originPos := types.LogPosition{LogDID: r.logDID, Sequence: 0}
	genesisRec := authz.GenesisAlgorithmPolicyRecord(
		GenesisAlgorithmPolicyFromBootstrap(r.bootstrap), originPos, r.networkID)
	records := make([]authz.AlgorithmPolicyRecord, 0, 1+len(amendments))
	records = append(records, genesisRec)
	records = append(records, amendments...)
	sort.Sort(authz.AlgorithmPolicyByPosition(records))

	asOf := types.LogPosition{LogDID: r.logDID, Sequence: treeSize}
	policy, err := authz.ResolveAlgorithmPolicyAt(records, asOf)
	if err != nil {
		return authz.AlgorithmPolicy{}, errors.Join(ErrAlgorithmPolicyResolverFailed, err)
	}

	if r.ttl > 0 {
		r.mu.Lock()
		r.cached = policy
		r.cachedAt = time.Now()
		r.loaded = true
		r.mu.Unlock()
	}
	return policy, nil
}

// Compile-time guards.
var (
	_ AlgorithmPolicyResolver = (*GenesisAlgorithmPolicyResolver)(nil)
	_ AlgorithmPolicyResolver = (*OnLogAlgorithmPolicyResolver)(nil)
)
