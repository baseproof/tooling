/*
FILE PATH: libs/bundle/standalone_chains.go

The Wave-2 deferred-section wiring for StandaloneLedgerGather: the governance
evolution chains, gathered index-backed and assembled on the proof's single
cosigned checkpoint.

# THE GOVERNANCE CHAINS (this file)

Each of the six governance v2 sections evolves one network parameter from a
pinned on-log schema. The gather discovers a chain's amendments by that schema's
position — GET /v1/query/schema_ref/{did:seq} (idx_schema_ref, O(amendments),
NEVER a scan) — then assembles them into the wire section on the shared checkpoint
(inclusion + K-of-N cosign per element; no SMT — baseproof#23). The schema
position per chain is per-network vocabulary, supplied via WithGovernanceSchemas;
a chain with no schema configured is left null (a network without that surface).

# ONE CHECKPOINT FOR THE WHOLE PROOF

Every leg (target entry + every section) anchors on a single cosigned head
(getHorizon, fetched once and cached). A genuine consumer must not stitch a proof
across two checkpoints, so the gather pins one.
*/
package bundle

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/baseproof/baseproof/types"
)

// GatherOption configures optional gather capabilities (the Wave-2 deferred
// sections). With no options a gather produces a Part-I + receipt proof.
type GatherOption func(*StandaloneLedgerGather)

// WithGovernanceSchemas sets the per-chain governance schema positions the gather
// discovers amendments by. Keys are the v2 section names — "signature_policy_chain",
// "algorithm_policy_chain", "protocol_version_chain", "admission_keyset_chain",
// "auditor_registration_chain", "auditor_scope_amendment_chain". A section absent
// from the map is left null (the network has no such governance surface). This is
// the vocabulary the Wave-4 NetworkBundle will carry.
func WithGovernanceSchemas(schemas map[string]types.LogPosition) GatherOption {
	return func(g *StandaloneLedgerGather) {
		g.governance = make(map[string]types.LogPosition, len(schemas))
		for k, v := range schemas {
			g.governance[k] = v
		}
	}
}

// governanceSchemaSections is the set of v2 sections discovered by schema_ref
// (their amendments all pin one governance schema).
var governanceSchemaSections = map[string]bool{
	"signature_policy_chain":        true,
	"algorithm_policy_chain":        true,
	"protocol_version_chain":        true,
	"admission_keyset_chain":        true,
	"auditor_registration_chain":    true,
	"auditor_scope_amendment_chain": true,
}

// getHorizon returns the proof's cosigned checkpoint, fetched once and cached so
// every leg of the proof binds to the SAME head.
func (g *StandaloneLedgerGather) getHorizon() (types.CosignedTreeHead, error) {
	if g.horizon != nil {
		return *g.horizon, nil
	}
	h, err := g.client.Horizon()
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("bundle/standalone: Horizon: %w", err)
	}
	g.horizon = &h
	return h, nil
}

// governanceSection discovers a governance chain's amendments by its pinned schema
// position (index-backed, never a scan) and assembles them on the checkpoint. An
// unconfigured chain, or one with no amendments, yields a null section.
func (g *StandaloneLedgerGather) governanceSection(ctx context.Context, name string) (json.RawMessage, error) {
	schemaPos, ok := g.governance[name]
	if !ok {
		return nil, nil // no schema configured ⇒ this network has no such surface
	}
	discovered, err := g.discoverer.DiscoverBySchemaRef(ctx, schemaPos)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: discover %s @ %s:%d: %w", name, schemaPos.LogDID, schemaPos.Sequence, err)
	}
	if len(discovered) == 0 {
		return nil, nil // no amendments on this chain ⇒ null section (no checkpoint needed)
	}
	head, err := g.getHorizon()
	if err != nil {
		return nil, err
	}
	return AssembleEvolutionChain(ctx, g, discovered, head)
}
