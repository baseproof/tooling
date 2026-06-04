/*
FILE PATH: services/auditor/internal/app/auditor_registry.go

D2 — auditor wiring for the v1.32.0 auditor-scope gate.

# WHAT THIS FILE DOES

Reads a JSON-shaped operator manifest file containing
`[]crosslog.AuditorSpec` and returns the SDK-typed
`network.AuditorRegistrationByPosition` slice ready for
`app.Deps.AuditorRegistry`.

The auditor binary calls `LoadAuditorRegistryFromFile(path)` once
at boot (gated on the D7 backward-compat env var
AUDITOR_ENFORCE_SCOPES) and threads the result through Deps. The
gossipingest pipeline then runs the v1.32.0 scope check on every
verified finding before dispatch — symmetric to the ledger's
gossipnet/auditor_scope_gate.go.

# WIRE SHAPE OF THE FILE

JSON array of objects matching crosslog.AuditorSpec:

	[
	  {
	    "effective_seq":      0,
	    "auditor_did":        "did:web:auditor-a.example.org",
	    "public_key":         "<hex>",
	    "scheme_tag":         1,
	    "proof_of_possession": "",
	    "findings_url":       "https://auditor-a.example.org/v1/findings",
	    "scope":              2,
	    "retired_at":         null
	  },
	  ...
	]

PublicKey + ProofOfPossession use hex on the wire (JSON cannot
carry raw bytes); the loader decodes them before validation.

# WHY FILE-BASED FIRST

The audit's plan calls for an on-log walker (read records from
the log via crosslog.MaterializeFromEntries). That works once the
network has published AuditorRegistrationV1 entries on-log. The
file-based loader covers the bootstrap window before any on-log
entries exist — operators can list the network's trusted auditors
in a deployment manifest, run with AUDITOR_ENFORCE_SCOPES=true,
and migrate to the walker-driven flow once on-log entries land.

A future patch swaps this loader for
crosslog.MaterializeFromEntries(scan) without touching app.go or
main.go — the Deps shape is stable.

# RELATIONSHIP TO D7

D7 (AUDITOR_ENFORCE_SCOPES env var) gates whether main calls
this loader. When the env var is false (default — preserves
pre-v1.32 behavior), main passes nil for app.Deps.AuditorRegistry
and the scope check is a no-op. When true, main loads the file
and threads the result through. Either path is operationally
valid; the toggle is the rollout knob.
*/
package app

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/crosslog"
)

// wireAuditorSpec is the JSON shape of a single registry entry.
// Mirrors crosslog.AuditorSpec with hex-encoded byte fields (JSON
// cannot carry raw bytes natively).
type wireAuditorSpec struct {
	EffectiveSeq      uint64               `json:"effective_seq"`
	AuditorDID        string               `json:"auditor_did"`
	PublicKey         string               `json:"public_key"`
	SchemeTag         byte                 `json:"scheme_tag"`
	ProofOfPossession string               `json:"proof_of_possession"`
	FindingsURL       string               `json:"findings_url"`
	Scope             network.AuditorScope `json:"scope"`
	RetiredAt         *uint64              `json:"retired_at"`
}

// LoadAuditorRegistryFromFile reads the JSON-shape registry manifest
// at path and returns the SDK-typed AuditorRegistrationByPosition
// slice ready for app.Deps.AuditorRegistry.
//
// Path empty returns (nil, nil) — the D7 backward-compat path
// (AUDITOR_ENFORCE_SCOPES=false). The resulting nil registry in
// Deps preserves the pre-v1.32 ingest behavior.
//
// Per-spec validation runs through crosslog.BuildAuditorRegistryFromConfig
// which calls the SDK's AuditorRegistration.Validate on every row.
// A malformed manifest surfaces at boot with the offending row's
// index + AuditorDID in the error.
func LoadAuditorRegistryFromFile(path string) (network.AuditorRegistrationByPosition, error) {
	if path == "" {
		return nil, nil
	}
	// Ladder 5 P8 (#21): hard-bound the read at MaxRegistryFileBytes
	// via io.LimitReader so an oversized or non-JSON file fails the
	// cap check BEFORE json.Unmarshal allocates. We read max+1 so we
	// can detect "file was actually larger than the cap" (the
	// LimitReader truncates silently — only the trailing byte tells
	// us we hit the boundary vs landed exactly at it).
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("auditor/app: read registry file %q: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxRegistryFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("auditor/app: read registry file %q: %w", path, err)
	}
	if int64(len(raw)) > MaxRegistryFileBytes {
		return nil, fmt.Errorf("auditor/app: registry file %q exceeds %d bytes (MaxRegistryFileBytes); "+
			"refusing to boot — split the manifest or raise the cap",
			path, MaxRegistryFileBytes)
	}
	var wires []wireAuditorSpec
	if err := json.Unmarshal(raw, &wires); err != nil {
		return nil, fmt.Errorf("auditor/app: parse registry file %q: %w", path, err)
	}
	if len(wires) > MaxRegistryRecords {
		return nil, fmt.Errorf("auditor/app: registry file %q has %d records, exceeds MaxRegistryRecords %d; "+
			"refusing to boot — split the manifest or raise the cap",
			path, len(wires), MaxRegistryRecords)
	}

	specs := make([]crosslog.AuditorSpec, 0, len(wires))
	for i, w := range wires {
		pub, err := hex.DecodeString(w.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("auditor/app: registry[%d] (DID=%q): public_key hex: %w",
				i, w.AuditorDID, err)
		}
		var pop []byte
		if w.ProofOfPossession != "" {
			pop, err = hex.DecodeString(w.ProofOfPossession)
			if err != nil {
				return nil, fmt.Errorf("auditor/app: registry[%d] (DID=%q): proof_of_possession hex: %w",
					i, w.AuditorDID, err)
			}
		}
		specs = append(specs, crosslog.AuditorSpec{
			EffectiveSeq:      w.EffectiveSeq,
			AuditorDID:        w.AuditorDID,
			PublicKey:         pub,
			SchemeTag:         w.SchemeTag,
			ProofOfPossession: pop,
			FindingsURL:       w.FindingsURL,
			Scope:             w.Scope,
			RetiredAt:         w.RetiredAt,
		})
	}
	return crosslog.BuildAuditorRegistryFromConfig(specs)
}
