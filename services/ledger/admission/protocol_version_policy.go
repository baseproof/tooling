/*
FILE PATH: admission/protocol_version_policy.go

On-log PROTOCOL-VERSION admission gate (crypto-agility).

# WHAT THIS ENFORCES

Before signature verification, this gate rejects a submission whose wire-format
protocol version (the 2-byte envelope preamble) is not admitted for WRITES by
the network's CURRENT protocol-version policy. The policy is the SDK's
authz.ProtocolVersionAdmissionPolicy — a per-version admission state:

	write_only → admitted for writes (PermitsWrite == true)
	read_write → admitted for writes + reads (PermitsWrite == true)
	read_only  → reads only; new writes REJECTED (PermitsWrite == false)
	forbidden  → REJECTED (PermitsWrite == false)

A version absent from the policy is also rejected (PermitsWrite == false).

# WHY A GATE (vs the hardcoded version check)

Today both submission paths hardcode "wire version == envelope.CurrentProtocolVersion()".
That cannot express a migration window — e.g. admit v1 + v2 for writes during a
rollout, then move v1 to read_only — without a redeploy. The protocol-version
policy governs admitted versions on-log via BP-ENTRY-NETWORK-PROTOCOL-VERSION-V1
amendments. When the gate is unwired the legacy "current version only" rule
stands (see api.admitProtocolVersion).

# GENESIS BASELINE

There is no GenesisProtocolVersion field on the BootstrapDocument, so the
genesis baseline is SYNTHESIZED: the binary's current wire version
(envelope.CurrentProtocolVersion()) admitted read_write. On-log amendments then
add versions / move versions to read_only / forbidden.

# FEATURE FLAG

Gated by Gates.ProtocolVersion (default OFF). Genesis-only resolver applies the
synthesized baseline; the amendment-aware OnLog resolver (wired when
LEDGER_PROTOCOL_VERSION_SCHEMA is set) applies on-log decisions.

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
	"github.com/baseproof/baseproof/types"
)

// ErrProtocolVersionNotAdmitted is returned when a submission's wire-format
// protocol version is not admitted for writes by the network's current policy
// (read_only / forbidden / absent). Routes to 422 via admission/error_mapping.go.
var ErrProtocolVersionNotAdmitted = errors.New(
	"admission: protocol version not admitted for writes by network policy")

// ErrProtocolVersionResolverFailed is returned when the resolver cannot supply a
// current policy. Distinct from ErrProtocolVersionNotAdmitted so the pipeline
// routes it as 500 (infrastructure), not 422 (policy reject).
var ErrProtocolVersionResolverFailed = errors.New(
	"admission: protocol version policy resolver failed")

// ProtocolVersionResolver returns the network protocol-version admission policy
// in force right now.
type ProtocolVersionResolver interface {
	Current(ctx context.Context) (authz.ProtocolVersionAdmissionPolicy, error)
}

// VerifyEntryProtocolVersion enforces the network protocol-version policy on a
// submission's wire-format version. Returns nil iff the version PermitsWrite.
//
//   - nil resolver → gate disabled (caller opted out via Gates.ProtocolVersion).
//   - resolver.Current error → ErrProtocolVersionResolverFailed (500).
//   - version not write-admitted → ErrProtocolVersionNotAdmitted (422).
func VerifyEntryProtocolVersion(
	ctx context.Context,
	resolver ProtocolVersionResolver,
	wireVersion uint16,
) error {
	if resolver == nil {
		return nil
	}
	policy, err := resolver.Current(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocolVersionResolverFailed, err)
	}
	if !policy.PermitsWrite(wireVersion) {
		state := "absent"
		if rec, ok := policy.Lookup(wireVersion); ok {
			state = string(rec.AdmittedFor)
		}
		return fmt.Errorf("%w: version %d (admitted_for=%s)",
			ErrProtocolVersionNotAdmitted, wireVersion, state)
	}
	return nil
}

// GenesisProtocolVersionPolicy synthesizes the genesis protocol-version policy:
// the binary's current wire version, admitted read_write. The records[0]
// baseline the walker amends.
func GenesisProtocolVersionPolicy() authz.ProtocolVersionAdmissionPolicy {
	return authz.ProtocolVersionAdmissionPolicy{
		AdmittedVersions: []authz.ProtocolVersionRecord{{
			Version:     envelope.CurrentProtocolVersion(),
			AdmittedFor: authz.ProtocolVersionReadWrite,
		}},
	}
}

// ─────────────────────────────────────────────────────────────────────
// GenesisProtocolVersionResolver — static (genesis baseline only)
// ─────────────────────────────────────────────────────────────────────

// GenesisProtocolVersionResolver always returns the synthesized genesis policy.
type GenesisProtocolVersionResolver struct {
	policy authz.ProtocolVersionAdmissionPolicy
}

// NewGenesisProtocolVersionResolver builds the static resolver, failing on a
// malformed synthesized policy (a defensive impossibility — the current version
// is always a valid single read_write entry).
func NewGenesisProtocolVersionResolver() (*GenesisProtocolVersionResolver, error) {
	p := GenesisProtocolVersionPolicy()
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("admission: genesis protocol-version policy invalid: %w", err)
	}
	return &GenesisProtocolVersionResolver{policy: p}, nil
}

// Current implements ProtocolVersionResolver. Ignores ctx — no I/O.
func (r *GenesisProtocolVersionResolver) Current(_ context.Context) (authz.ProtocolVersionAdmissionPolicy, error) {
	return r.policy, nil
}

// ─────────────────────────────────────────────────────────────────────
// OnLogProtocolVersionResolver — amendment-aware
// ─────────────────────────────────────────────────────────────────────

// ProtocolVersionAmendmentSource returns the on-log
// BP-ENTRY-NETWORK-PROTOCOL-VERSION-V1 records (unsorted is fine). Wired from
// the QueryAPI. Empty slice is valid: the resolver serves the genesis baseline.
type ProtocolVersionAmendmentSource func(ctx context.Context) ([]authz.ProtocolVersionAdmissionRecord, error)

// OnLogProtocolVersionResolver walks on-log amendments on top of the synthesized
// genesis baseline, caching behind a TTL. Mirrors OnLogAlgorithmPolicyResolver.
type OnLogProtocolVersionResolver struct {
	source    ProtocolVersionAmendmentSource
	sizes     TreeSizeProvider
	logDID    string
	networkID [32]byte
	ttl       time.Duration

	mu       sync.RWMutex
	cached   authz.ProtocolVersionAdmissionPolicy
	cachedAt time.Time
	loaded   bool
}

// NewOnLogProtocolVersionResolver constructs the amendment-aware resolver.
func NewOnLogProtocolVersionResolver(
	source ProtocolVersionAmendmentSource,
	sizes TreeSizeProvider,
	logDID string,
	networkID [32]byte,
	ttl time.Duration,
) (*OnLogProtocolVersionResolver, error) {
	if source == nil {
		return nil, fmt.Errorf("admission: OnLogProtocolVersionResolver: source required")
	}
	if sizes == nil {
		return nil, fmt.Errorf("admission: OnLogProtocolVersionResolver: sizes required")
	}
	if logDID == "" {
		return nil, fmt.Errorf("admission: OnLogProtocolVersionResolver: logDID required")
	}
	return &OnLogProtocolVersionResolver{
		source:    source,
		sizes:     sizes,
		logDID:    logDID,
		networkID: networkID,
		ttl:       ttl,
	}, nil
}

// Current resolves the protocol-version policy in effect at the current tree size.
func (r *OnLogProtocolVersionResolver) Current(ctx context.Context) (authz.ProtocolVersionAdmissionPolicy, error) {
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
		return authz.ProtocolVersionAdmissionPolicy{}, fmt.Errorf("%w: tree-size fetch: %v", ErrProtocolVersionResolverFailed, err)
	}
	amendments, err := r.source(ctx)
	if err != nil {
		return authz.ProtocolVersionAdmissionPolicy{}, fmt.Errorf("%w: amendment source: %v", ErrProtocolVersionResolverFailed, err)
	}

	originPos := types.LogPosition{LogDID: r.logDID, Sequence: 0}
	genesisRec := authz.GenesisProtocolVersionAdmissionRecord(
		GenesisProtocolVersionPolicy(), originPos, r.networkID)
	records := make([]authz.ProtocolVersionAdmissionRecord, 0, 1+len(amendments))
	records = append(records, genesisRec)
	records = append(records, amendments...)
	sort.Sort(authz.ProtocolVersionAdmissionByPosition(records))

	asOf := types.LogPosition{LogDID: r.logDID, Sequence: treeSize}
	policy, err := authz.ResolveProtocolVersionAdmissionAt(records, asOf)
	if err != nil {
		return authz.ProtocolVersionAdmissionPolicy{}, errors.Join(ErrProtocolVersionResolverFailed, err)
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
	_ ProtocolVersionResolver = (*GenesisProtocolVersionResolver)(nil)
	_ ProtocolVersionResolver = (*OnLogProtocolVersionResolver)(nil)
)
