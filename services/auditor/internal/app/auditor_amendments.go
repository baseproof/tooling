/*
FILE PATH: services/auditor/internal/app/auditor_amendments.go

Ladder 2 D5 (#21) — operator-manifest loader for the v1.33.x
AuditorScopeAmendmentV1 record stream (SDK Gap 2).

# WHAT THIS FILE DOES

Reads a JSON-shaped operator manifest file containing
`[]wireAmendmentSpec` and returns the SDK-typed
`network.AuditorScopeAmendmentByPosition` slice ready for
`app.Deps.AuditorAmendments`.

Symmetric to LoadAuditorRegistryFromFile — the same shape the auditor
binary already uses for the registration manifest. Sorted on the
producer side so the SDK's ResolveAuditorAt 4-arg signature receives
a contract-valid slice regardless of operator file ordering (#21 B1
applied to amendments).

# WIRE SHAPE OF THE FILE

JSON array of objects:

	[
	  {
	    "effective_seq": 100,
	    "auditor_did":   "did:web:auditor-a.example.org",
	    "new_scope":     6,
	    "reason":        "Gap 2 amendment: expand from Equivocation-only to SMTReplay+HistoryRewrite"
	  },
	  ...
	]

# WHY OPERATOR-FILE FIRST

The audit's plan calls for an on-log walker (read records via
crosslog.MaterializeFromEntries). That works once the network has
published AuditorScopeAmendmentV1 entries on-log. The file-based
loader covers the bootstrap window before any on-log entries exist —
operators can declare in-flight scope amendments in a deployment
manifest, run with the file-based loader, and migrate to the walker-
driven flow once on-log entries land.

# RELATIONSHIP TO AUDITOR_AMENDMENT_FILE

main.go reads AUDITOR_AMENDMENT_FILE; if set, the loader runs and
threads the result through app.Deps.AuditorAmendments. If unset, the
Deps field is nil — the reconciler's gate treats this as "no
amendments yet", equivalent to v1.32.0 registration-only semantics.
*/
package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// wireAmendmentSpec is the JSON shape of a single amendment entry.
// AuditorDID, NewScope, and Reason mirror the SDK's
// network.AuditorScopeAmendment fields; EffectiveSeq is supplied as a
// scalar (the JSON file is operator-authored, no LogPosition struct).
type wireAmendmentSpec struct {
	EffectiveSeq uint64               `json:"effective_seq"`
	AuditorDID   string               `json:"auditor_did"`
	NewScope     network.AuditorScope `json:"new_scope"`
	Reason       string               `json:"reason,omitempty"`
}

// LoadAuditorAmendmentsFromFile reads the JSON-shape amendment manifest
// at path and returns the SDK-typed AuditorScopeAmendmentByPosition
// slice ready for app.Deps.AuditorAmendments.
//
// Path empty returns (nil, nil) — the no-amendments-configured path.
// The resulting nil slice in Deps preserves the v1.32.0 registration-
// only behavior.
//
// Per-spec validation runs through the SDK's AuditorScopeAmendment.Validate
// on every row. A malformed manifest surfaces at boot with the offending
// row's index + AuditorDID in the error.
//
// The result is sorted by EffectivePos ascending — the SDK's
// ResolveAuditorAt contract requires sorted input; the loader honors
// that contract symmetrically with LoadAuditorRegistryFromFile.
func LoadAuditorAmendmentsFromFile(path string) (network.AuditorScopeAmendmentByPosition, error) {
	if path == "" {
		return nil, nil
	}
	// Ladder 5 P8 (#21): hard-bound the read at MaxRegistryFileBytes
	// via io.LimitReader — same discipline as LoadAuditorRegistryFromFile.
	// See services/auditor/internal/app/limits.go for the rationale.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("auditor/app: read amendment file %q: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxRegistryFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("auditor/app: read amendment file %q: %w", path, err)
	}
	if int64(len(raw)) > MaxRegistryFileBytes {
		return nil, fmt.Errorf("auditor/app: amendment file %q exceeds %d bytes (MaxRegistryFileBytes); "+
			"refusing to boot — split the manifest or raise the cap",
			path, MaxRegistryFileBytes)
	}
	var wires []wireAmendmentSpec
	if err := json.Unmarshal(raw, &wires); err != nil {
		return nil, fmt.Errorf("auditor/app: parse amendment file %q: %w", path, err)
	}
	if len(wires) > MaxRegistryRecords {
		return nil, fmt.Errorf("auditor/app: amendment file %q has %d records, exceeds MaxRegistryRecords %d; "+
			"refusing to boot — split the manifest or raise the cap",
			path, len(wires), MaxRegistryRecords)
	}
	out := make(network.AuditorScopeAmendmentByPosition, 0, len(wires))
	for i, w := range wires {
		a := network.AuditorScopeAmendment{
			AuditorDID: w.AuditorDID,
			NewScope:   w.NewScope,
			Reason:     w.Reason,
		}
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("auditor/app: amendments[%d] (DID=%q): %w",
				i, w.AuditorDID, err)
		}
		out = append(out, network.AuditorScopeAmendmentRecord{
			EffectivePos: types.LogPosition{Sequence: w.EffectiveSeq},
			Payload:      a,
		})
	}
	// Sort by EffectivePos ascending so the SDK's ResolveAuditorAt
	// contract is satisfied at the boundary regardless of operator
	// manifest ordering. Symmetric to BuildAuditorRegistryFromConfig's
	// sort step (Ladder 1 B1).
	sort.Sort(out)
	return out, nil
}
