/*
FILE PATH: store/entry_kind.go

EntryKindProjection — the ONE extraction home for the entry_index `kind`
projection (migration 0022). Both EntryRow producers call it
(sequencer/loop.go buildLiveStagedEntry and recovery/rebuild.go entryRowFor),
so the forward path and the rebuild path cannot drift — the bit-exact-rebuild
integration test rides on that.
*/
package store

import (
	"encoding/json"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/kinds"
)

// recognizedEntryKinds is the closed set of entry-payload kind discriminators
// the projection records, built once from the SDK's authoritative catalog. A
// `kind` field outside this set projects "" (NULL) — the index never carries
// an attacker-chosen string, only a value the SDK itself enumerates.
var recognizedEntryKinds = func() map[string]struct{} {
	all := kinds.AllEntryKinds()
	m := make(map[string]struct{}, len(all))
	for _, k := range all {
		m[k] = struct{}{}
	}
	return m
}()

// EntryKindProjection returns the entry payload's `kind` discriminator when it
// is one of the SDK's recognized entry kinds (kinds.AllEntryKinds()), or ""
// for every other entry. "" means "no projection" (SQL NULL — invisible to
// idx_entry_kind).
//
// DISCOVERY, NOT AUTHORITY: the value is the publisher's own payload field,
// recorded so by-kind consumers (the AuthoritativeResolver's schema-position
// derivation, #114) can FIND the latest declaration of a kind in one index
// seek; everything trust-bearing is re-established by the consumer from the
// entry bytes. A payload that is not JSON, carries no `kind`, or carries an
// unrecognized `kind` projects nothing — omission fails toward the resolver
// finding no declaration (canary / boot-refusal), never toward a forged one,
// so this probe is deliberately tolerant. It is the SAME structural probe the
// admission firewall pays (admission.VerifyNetworkPayloadEntry) — a single
// json.Unmarshal of a one-field shape, bounded allocation.
func EntryKindProjection(entry *envelope.Entry) string {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return ""
	}
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &probe); err != nil {
		return ""
	}
	if _, ok := recognizedEntryKinds[probe.Kind]; !ok {
		return ""
	}
	return probe.Kind
}
