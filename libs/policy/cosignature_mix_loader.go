/*
FILE PATH: libs/policy/cosignature_mix_loader.go

DESCRIPTION:

	File-backed loader for the cosignature-mix policy. Reads a
	JSON file with shape:

	  {
	    "rules": [
	      {
	        "event_type": "amendment",
	        "allowed_filer_roles": ["operator", "registrar"],
	        "required_signer_roles": ["approver"],
	        "min_signer_cosigners": 1,
	        "intra_exchange_only": true,
	        "required_credentials": ["registration_number"]
	      },
	      ...
	    ]
	  }

	ParseJSON for in-memory deserialization, LoadFile for disk +
	parse, ReloadFromFile for the SIGHUP hot-reload path. Failed
	reload (missing file, parse error, validation error) keeps the
	previous policy in effect — the system never goes policy-less at
	runtime.

	Deployments may skip the file path entirely and use a Go-defined
	slice via NewInMemoryPolicy.

OVERVIEW:

	ParseJSON          — bytes → InMemoryPolicy.
	LoadFile           — path → InMemoryPolicy.
	ReloadFromFile     — atomic refresh of an existing policy
	                     (revalidates under the policy's options).

KEY DEPENDENCIES:
  - libs/policy/cosignature_mix.go (CosignatureRule, InMemoryPolicy).
*/
package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// policyFile is the on-disk JSON shape.
type policyFile struct {
	Rules []CosignatureRule `json:"rules"`
}

// ParseJSON decodes JSON bytes into a fresh InMemoryPolicy. Options
// (e.g. WithKnownFilerRoles) apply to this parse and are retained by
// the returned policy for later Add / Replace / ReloadFromFile.
func ParseJSON(data []byte, opts ...Option) (*InMemoryPolicy, error) {
	var f policyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("policy/cosignature_mix: parse: %w", err)
	}
	return NewInMemoryPolicy(f.Rules, opts...)
}

// LoadFile reads, parses, and validates a policy JSON file.
func LoadFile(path string, opts ...Option) (*InMemoryPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy/cosignature_mix: read %q: %w", path, err)
	}
	return ParseJSON(data, opts...)
}

// ReloadFromFile re-reads a JSON file and atomically replaces the
// policy's rules, validating under the options the policy was
// constructed with. Used by SIGHUP handlers; failed reloads bubble
// up and the caller leaves the previous policy in effect.
func (p *InMemoryPolicy) ReloadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy/cosignature_mix: read %q: %w", path, err)
	}
	var f policyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("policy/cosignature_mix: parse %q: %w", path, err)
	}
	return p.Replace(f.Rules)
}
