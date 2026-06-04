/*
FILE PATH: admission/onlog_keyset.go

DESCRIPTION:

	OnLogAdmissionKeyset — the on-log-backed AdmissionKeyset for gate 5. The
	authorized admission-authority set is on-log policy (admission_authority_v1
	snapshot entries); this resolver projects them and serves the CURRENT set
	(the latest snapshot) behind a short TTL cache so the admission hot path
	does not re-query per submission.

	Sourcing is injected (a KeysetSource closure wired in cmd/ledger/boot/wire
	from the QueryAPI) so this type stays free of store/pgx and is unit-testable
	with a fake source. Zero-trust: the set comes from the log, never config.
*/
package admission

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/baseproof/baseproof/authz"
)

// KeysetSource returns the full set of on-log admission_authority_v1 snapshot
// records (unsorted is fine — the resolver sorts). Wired from the QueryAPI.
type KeysetSource func(ctx context.Context) ([]authz.EOAKeysetRecord, error)

// OnLogAdmissionKeyset serves the current authorized set with a TTL cache.
type OnLogAdmissionKeyset struct {
	source  KeysetSource
	genesis [][20]byte
	ttl     time.Duration

	mu     sync.RWMutex
	cached [][20]byte
	loaded bool
	at     time.Time
}

// NewOnLogAdmissionKeyset constructs the resolver. genesis is the founding
// authority set from the BootstrapDocument (the fallback when no on-log
// admission_authority_v1 snapshot exists yet), so default-require gating works
// from genesis. A non-positive ttl disables caching (every Current re-sources).
func NewOnLogAdmissionKeyset(source KeysetSource, genesis [][20]byte, ttl time.Duration) *OnLogAdmissionKeyset {
	return &OnLogAdmissionKeyset{source: source, genesis: genesis, ttl: ttl}
}

// Current returns the members of the latest on-log admission_authority_v1
// snapshot (highest position), else the genesis authority set. Empty (nil) only
// when neither exists — fail-closed: VerifyWriteAuthorization then rejects with
// ErrEmptyAuthoritySet.
func (k *OnLogAdmissionKeyset) Current(ctx context.Context) ([][20]byte, error) {
	if k.ttl > 0 {
		k.mu.RLock()
		fresh := k.loaded && time.Since(k.at) < k.ttl
		cached := k.cached
		k.mu.RUnlock()
		if fresh {
			return cached, nil
		}
	}

	recs, err := k.source(ctx)
	if err != nil {
		return nil, err
	}
	members := k.genesis
	if len(recs) > 0 {
		sort.Sort(authz.EOAKeysetByPosition(recs))
		members = recs[len(recs)-1].Members // latest snapshot = current
	}

	k.mu.Lock()
	k.cached = members
	k.loaded = true
	k.at = time.Now()
	k.mu.Unlock()
	return members, nil
}
