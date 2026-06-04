/*
FILE PATH: internal/auditorregistry/fetcher.go

v1.33.1 SDK adoption — amendment-aware materialization of the
on-log AuditorRegistrationV1 + AuditorScopeAmendmentV1 streams
into the api.AuditorsView shape served by GET /v1/network/auditors.

# WHY THIS PACKAGE EXISTS

The gate (gossipnet/auditor_scope_gate.go) enforces the MERGED
auditor scope: network.ResolveAuditorAt(records, amendments, did,
asOf) returns the registration with the most recent amendment's
NewScope merged in. Pre-v1.33.1 the fetcher that backs the
materialized projection at GET /v1/network/auditors ignored the
amendment stream and served the raw registration scope — meaning
the gate and the API would silently disagree the moment any
AuditorScopeAmendmentV1 entry was admitted on-log. Consumers
hitting the endpoint would believe an auditor's scope was
{equivocation} while the gate enforced {equivocation,smt_replay}
because of a later amendment.

This file closes that gap. The fetcher consumes BOTH on-log
streams and serves the merged view, locking gate/API consistency
under amendments.

# WHY IT'S A SEPARATE PACKAGE

Tested via the actual fetcher type, not a stub. Promoting to an
internal package lets the test live alongside the production
code (not behind cmd/.../wire's unexported type) while keeping
the type out of the public API surface — internal/ prevents
external imports.
*/
package auditorregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/admission"
	"github.com/baseproof/tooling/services/ledger/api"
)

// RegistrySource returns the on-log AuditorRegistrationV1 records.
type RegistrySource func(ctx context.Context) ([]network.AuditorRegistrationRecord, error)

// AmendmentSource returns the on-log AuditorScopeAmendmentV1 records.
// A nil source OR an empty slice both mean "no amendments
// published" — the fetcher serves the registration stream alone.
type AmendmentSource func(ctx context.Context) ([]network.AuditorScopeAmendmentRecord, error)

// Fetcher implements api.AuditorRegistryFetcher backed by the
// on-log walker sources. Amendment-aware: per-DID dispatch through
// network.ResolveAuditorAt carries the amendment merge into the
// projection's Scope field.
type Fetcher struct {
	registry   RegistrySource
	amendments AmendmentSource
	treeSizer  admission.TreeSizeProvider
}

// New constructs a Fetcher. registry is required; amendments may
// be nil (treated as empty). treeSizer is required — the projection
// materializes AT the latest committed tree size and consumers
// re-verify via network.ResolveAuditorAt at that position.
func New(registry RegistrySource, amendments AmendmentSource, treeSizer admission.TreeSizeProvider) (*Fetcher, error) {
	if registry == nil {
		return nil, errors.New("auditorregistry: registry source required")
	}
	if treeSizer == nil {
		return nil, errors.New("auditorregistry: tree size provider required")
	}
	return &Fetcher{
		registry:   registry,
		amendments: amendments,
		treeSizer:  treeSizer,
	}, nil
}

// LoadCurrentAuditors materializes the current active-auditor set
// with the amendment merge applied per DID.
//
// Semantics:
//   - Pull both streams.
//   - asOf is the latest tree size (zero on cold start; the SDK's
//     ResolveAuditorAt treats every record with EffectivePos==zero
//     as in-effect).
//   - Collect the unique set of AuditorDIDs from registrations.
//   - For each DID, call network.ResolveAuditorAt(records,
//     amendments, did, asOf) — returns the registration with the
//     amendment-merged Scope, or an error/sentinel we filter out.
//   - Retired and not-registered DIDs are filtered (the materialized
//     view is the CURRENT active set).
//   - Per-DID errors are non-fatal: a single bad record does not
//     drop the whole view; we just skip it. A failure of the
//     amendment source IS fatal (mirrors the gate's fail-closed
//     posture — wrong source state is more dangerous than no view).
func (f *Fetcher) LoadCurrentAuditors(ctx context.Context) (*api.AuditorsView, error) {
	recs, err := f.registry(ctx)
	if err != nil {
		return nil, fmt.Errorf("auditorregistry: registry source: %w", err)
	}

	var amends []network.AuditorScopeAmendmentRecord
	if f.amendments != nil {
		amends, err = f.amendments(ctx)
		if err != nil {
			return nil, fmt.Errorf("auditorregistry: amendment source: %w", err)
		}
	}

	asOfSize, _ := f.treeSizer.LatestTreeSize(ctx)
	asOf := types.LogPosition{Sequence: asOfSize}

	seen := map[string]struct{}{}
	dids := make([]string, 0, len(recs))
	for i := range recs {
		did := recs[i].Payload.AuditorDID
		if _, ok := seen[did]; ok {
			continue
		}
		seen[did] = struct{}{}
		dids = append(dids, did)
	}

	out := make([]api.AuditorEntry, 0, len(dids))
	for _, did := range dids {
		reg, err := network.ResolveAuditorAt(recs, amends, did, asOf)
		if err != nil {
			// Filter retired / not-registered / unsorted-records
			// per-DID. The view is the CURRENT active set.
			continue
		}
		out = append(out, api.AuditorEntry{
			AuditorDID:  reg.AuditorDID,
			PublicKey:   api.EncodeAuditorPublicKey(reg.PublicKey),
			SchemeTag:   reg.SchemeTag,
			FindingsURL: reg.FindingsURL,
			Scope:       reg.Scope.String(),
		})
	}
	return &api.AuditorsView{AsOfSeq: asOfSize, Auditors: out}, nil
}

// Compile-time guard: *Fetcher implements api.AuditorRegistryFetcher.
var _ api.AuditorRegistryFetcher = (*Fetcher)(nil)
