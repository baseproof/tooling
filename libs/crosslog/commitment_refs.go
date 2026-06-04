/*
FILE PATH: libs/crosslog/commitment_refs.go

Discovers the on-log SMT-derivation commitment-ref entries (#190) from a flat
slice of pre-positioned envelope entries, returning them sorted ascending by
LogRangeStart — the order the chained fraud-proof verifier replays them.

# WHY STRUCTURAL DETECTION

The ledger publishes a commitment ref as a COMMENTARY entry whose DomainPayload
is a bare json.Marshal(storage.SMTDerivationCommitmentRef) — there is no "kind"
discriminator to switch on (unlike the network-governance kinds). So discovery
is structural: a payload that round-trips into an SMTDerivationCommitmentRef
carrying a NON-ZERO MutationsCID whose algorithm the ref restates in HashAlgo
(the NewSMTDerivationCommitmentRef invariant) is a commitment ref. Every other
commentary payload — anchors, governance amendments, application entries —
leaves MutationsCID zero and is skipped.

This is the read-side counterpart of ledger builder/commitment_publisher.go,
which json.Marshals the ref into the commentary entry. The detected refs feed
verifier.VerifyDerivationCommitmentRef (see libs/monitoring derivation-commitment
monitor).

KEY DEPENDENCIES: baseproof/storage.
*/
package crosslog

import (
	"encoding/json"
	"log/slog"
	"sort"

	"github.com/baseproof/baseproof/storage"
)

// DiscoverCommitmentRefs structurally detects the SMT-derivation commitment-ref
// commentary entries in entries and returns them sorted ascending by
// LogRangeStart. logger nil routes to slog.Default().
func DiscoverCommitmentRefs(entries []EntryAtPosition, logger *slog.Logger) []storage.SMTDerivationCommitmentRef {
	if logger == nil {
		logger = slog.Default()
	}
	var out []storage.SMTDerivationCommitmentRef
	for _, e := range entries {
		if e.Entry == nil || len(e.Entry.DomainPayload) == 0 {
			continue
		}
		var ref storage.SMTDerivationCommitmentRef
		if err := json.Unmarshal(e.Entry.DomainPayload, &ref); err != nil {
			continue
		}
		// Structural signature of a commitment ref (vs any other commentary
		// payload): a non-zero MutationsCID whose algorithm the ref restates.
		if ref.MutationsCID.IsZero() || ref.HashAlgo != ref.MutationsCID.Algorithm {
			continue
		}
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LogRangeStart.Less(out[j].LogRangeStart)
	})
	logger.Info("crosslog/commitment_refs: discovered", "count", len(out))
	return out
}
