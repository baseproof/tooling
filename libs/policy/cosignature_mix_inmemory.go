/*
FILE PATH: libs/policy/cosignature_mix_inmemory.go

DESCRIPTION:

	InMemoryPolicy method implementations. Split out of
	cosignature_mix.go to keep that file focused on the type
	surface.

OVERVIEW:

	Lookup     — return a copy of the rule or ErrRuleNotFound.
	List       — copies, sorted by event_type.
	Add        — late insertion (used by tests + reload paths).
	Replace    — atomic swap of the entire table.

KEY DEPENDENCIES:
  - libs/policy/cosignature_mix.go (CosignatureRule, sentinels,
    validateRule, InMemoryPolicy struct, options).
*/
package policy

import (
	"fmt"
	"sort"
)

// Lookup returns the rule for eventType. The returned rule is a copy —
// callers cannot mutate the table through it.
func (p *InMemoryPolicy) Lookup(eventType string) (*CosignatureRule, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.rules[eventType]
	if !ok {
		return nil, fmt.Errorf("%w: event_type=%s", ErrRuleNotFound, eventType)
	}
	cp := *r
	return &cp, nil
}

// List returns copies of all rules sorted by event_type for
// deterministic consumption (UI, audit reports).
func (p *InMemoryPolicy) List() []*CosignatureRule {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*CosignatureRule, 0, len(p.rules))
	for _, r := range p.rules {
		cp := *r
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].EventType < out[j].EventType
	})
	return out
}

// Add inserts a new rule. Returns ErrInvalidRule on bad fields,
// ErrDuplicateRule when EventType already exists. Validates under the
// options the policy was constructed with.
func (p *InMemoryPolicy) Add(r CosignatureRule) error {
	if err := validateRule(r, p.opts.knownFilerRoles); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, dup := p.rules[r.EventType]; dup {
		return fmt.Errorf("%w: event_type=%s", ErrDuplicateRule, r.EventType)
	}
	cp := r
	p.rules[r.EventType] = &cp
	return nil
}

// Replace atomically swaps the policy contents. Validates and
// rejects duplicates BEFORE installing — partial reload is not
// supported (a typo in one rule must not silently corrupt others).
//
// Used by the JSON loader's hot-reload path and by tests that need
// to reset the policy between cases.
func (p *InMemoryPolicy) Replace(rules []CosignatureRule) error {
	next := make(map[string]*CosignatureRule, len(rules))
	for _, r := range rules {
		if err := validateRule(r, p.opts.knownFilerRoles); err != nil {
			return err
		}
		if _, dup := next[r.EventType]; dup {
			return fmt.Errorf("%w: event_type=%s", ErrDuplicateRule, r.EventType)
		}
		cp := r
		next[r.EventType] = &cp
	}
	p.mu.Lock()
	p.rules = next
	p.mu.Unlock()
	return nil
}
