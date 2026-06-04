/*
FILE PATH: admission/onlog_policy.go

DESCRIPTION:

	OnLogAdmissionPolicy — resolves the CURRENT admission policy (whether write
	authorization is required + the cost regime) from the on-log
	BP-ENTRY-ADMISSION-POLICY-V1 change entries plus the network's genesis policy, exactly
	like the published Mode-B difficulty schedule. Gate 5 and the cost selection
	consult it; policy is on-log, published, and evolvable (every change is a
	sequenced entry).

	SECURE BY DEFAULT: when nothing is configured on-log and no genesis is wired,
	the policy is SecureDefaultPolicy — gating REQUIRED, cost UNCHARGED. A fresh
	ledger therefore requires write authorization from the first write (and, with
	an empty authority keyset, fails closed until bootstrap seeds authorities).
*/
package admission

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/baseproof/baseproof/authz"
)

// SecureDefaultPolicy is the fail-safe policy: gating required, no cost. Used as
// the genesis fallback when none is wired, so the ledger is default-require.
var SecureDefaultPolicy = authz.AdmissionPolicy{
	GatingRequired: true,
	CostMode:       authz.CostModeUncharged,
}

// PolicySource returns the on-log BP-ENTRY-ADMISSION-POLICY-V1 change records (unsorted
// is fine — the resolver sorts). Wired from the QueryAPI.
type PolicySource func(ctx context.Context) ([]authz.AdmissionPolicyRecord, error)

// AdmissionPolicyResolver resolves the current admission policy.
type AdmissionPolicyResolver interface {
	Current(ctx context.Context) (authz.AdmissionPolicy, error)
}

// OnLogAdmissionPolicy serves the current policy (latest on-log change, else
// genesis) behind a TTL cache.
type OnLogAdmissionPolicy struct {
	source  PolicySource
	genesis authz.AdmissionPolicy
	ttl     time.Duration

	mu     sync.RWMutex
	cached authz.AdmissionPolicy
	loaded bool
	at     time.Time
}

// NewOnLogAdmissionPolicy constructs the resolver. genesis is the network's
// founding policy (from the BootstrapDocument); a zero/invalid genesis falls
// back to SecureDefaultPolicy so the ledger is never accidentally open. A
// non-positive ttl disables caching.
func NewOnLogAdmissionPolicy(source PolicySource, genesis authz.AdmissionPolicy, ttl time.Duration) *OnLogAdmissionPolicy {
	if genesis.Validate() != nil {
		genesis = SecureDefaultPolicy
	}
	return &OnLogAdmissionPolicy{source: source, genesis: genesis, ttl: ttl}
}

// Current returns the policy in effect now: the most recent on-log
// BP-ENTRY-ADMISSION-POLICY-V1 change, else the genesis policy.
func (p *OnLogAdmissionPolicy) Current(ctx context.Context) (authz.AdmissionPolicy, error) {
	if p.ttl > 0 {
		p.mu.RLock()
		fresh := p.loaded && time.Since(p.at) < p.ttl
		cached := p.cached
		p.mu.RUnlock()
		if fresh {
			return cached, nil
		}
	}

	recs, err := p.source(ctx)
	if err != nil {
		return authz.AdmissionPolicy{}, err
	}
	pol := p.genesis
	if len(recs) > 0 {
		sort.Sort(authz.AdmissionPolicyByPosition(recs))
		pol = recs[len(recs)-1].Policy // latest change = current
	}

	p.mu.Lock()
	p.cached = pol
	p.loaded = true
	p.at = time.Now()
	p.mu.Unlock()
	return pol, nil
}

// StaticAdmissionPolicy is a fixed-policy resolver (tests / degraded boot).
type StaticAdmissionPolicy struct{ Policy authz.AdmissionPolicy }

// Current returns the fixed policy.
func (s StaticAdmissionPolicy) Current(context.Context) (authz.AdmissionPolicy, error) {
	return s.Policy, nil
}
