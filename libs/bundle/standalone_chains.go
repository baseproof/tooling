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
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/core/envelope"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/schema"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// maxSchemaChainDepth bounds the schema-succession walk. MUST match the SDK's
// verifier.maxSchemaChainDepth (schema_succession.go) so the gather never produces
// a chain deeper than VerifyStandalone will accept.
const maxSchemaChainDepth = 100

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

// WithSignerRotationSchema sets the on-log position of the network's signer-rotation
// schema (BP-ENTRY-SIGNER-ROTATION-PAYLOAD-V1). With it set, the gather populates
// signer_rotation_chain by discovering rotations by that schema and filtering to the
// target entry's signer. Unset ⇒ signer_rotation_chain is left null.
func WithSignerRotationSchema(pos types.LogPosition) GatherOption {
	return func(g *StandaloneLedgerGather) {
		p := pos
		g.signerRotationSchema = &p
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

// burnSection fetches the network's observed burn (equivocation) status from
// GET /v1/burn — a FETCHED FACT, never a constant — and encodes it as the v2
// burn_attestation, stamped with the proof's checkpoint tree size (as_of). A
// burned network (is_burned=true) is faithfully carried; VerifyStandalone then
// fails it closed (ErrEquivocatedLog).
func (g *StandaloneLedgerGather) burnSection(ctx context.Context) (json.RawMessage, error) {
	var body struct {
		IsBurned bool `json:"is_burned"`
	}
	if err := g.getJSON(ctx, g.baseURL+"/v1/burn", &body); err != nil {
		return nil, fmt.Errorf("bundle/standalone: burn status: %w", err)
	}
	head, err := g.getHorizon()
	if err != nil {
		return nil, err
	}
	return sdkbundle.EncodeBurnAttestation(body.IsBurned, head.TreeSize)
}

// targetEntry fetches and deserializes the proof's target entry once (cached). Its
// header drives the signer-rotation and schema chains.
func (g *StandaloneLedgerGather) targetEntry(ctx context.Context) (*envelope.Entry, error) {
	if g.targetEntryCache != nil {
		return g.targetEntryCache, nil
	}
	canonical, _, err := g.FetchEntry(ctx, g.seq)
	if err != nil {
		return nil, err
	}
	e, err := envelope.Deserialize(canonical)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: deserialize target entry %d: %w", g.seq, err)
	}
	g.targetEntryCache = e
	return e, nil
}

// fetchCanonical returns just the canonical bytes for a sequence (the shape the
// chain helpers consume).
func (g *StandaloneLedgerGather) fetchCanonical(ctx context.Context, seq uint64) ([]byte, error) {
	b, _, err := g.FetchEntry(ctx, seq)
	return b, err
}

// signerRotationSection gathers the target entry signer's on-log key-rotation chain.
//
// Discovery is by the network's rotation SCHEMA (schema_ref, O(rotations)) — NOT by
// signer_did. Tracing the SDK shows why signer_did is wrong here: (1) the rotation
// PAYLOAD's signer may differ from the entry's header signer for an authority-issued
// rotation, so signer_did(target) misses those; and (2) signer_did(target) is O(the
// signer's entries) — O(N) for a prolific signer — violating the index/scale
// contract. Discovering by the rotation schema (rotations are rare network-wide)
// then filtering on the decoded payload's signer is both complete and bounded.
//
// Unset rotation schema, or no rotation of this signer, ⇒ null section.
func (g *StandaloneLedgerGather) signerRotationSection(ctx context.Context) (json.RawMessage, error) {
	if g.signerRotationSchema == nil {
		return nil, nil
	}
	entry, err := g.targetEntry(ctx)
	if err != nil {
		return nil, err
	}
	candidates, err := g.discoverer.DiscoverBySchemaRef(ctx, *g.signerRotationSchema)
	if err != nil {
		return nil, fmt.Errorf("bundle/standalone: discover signer rotations: %w", err)
	}
	kept, err := filterRotationsForSigner(ctx, candidates, entry.Header.SignerDID, g.fetchCanonical)
	if err != nil {
		return nil, err
	}
	if len(kept) == 0 {
		return nil, nil // this signer never rotated ⇒ null section
	}
	head, err := g.getHorizon()
	if err != nil {
		return nil, err
	}
	return AssembleEvolutionChain(ctx, g, kept, head)
}

// filterRotationsForSigner keeps the candidates whose decoded rotation payload
// rotates `signer` (payload.SignerDID == signer). An entry on the rotation schema
// that is NOT a rotation payload is skipped; a malformed rotation payload is a hard
// error (an integrity problem, not background traffic).
func filterRotationsForSigner(ctx context.Context, candidates []DiscoveredEntry, signer string, fetch func(context.Context, uint64) ([]byte, error)) ([]DiscoveredEntry, error) {
	var kept []DiscoveredEntry
	for _, c := range candidates {
		canonical, err := fetch(ctx, c.Sequence)
		if err != nil {
			return nil, err
		}
		e, err := envelope.Deserialize(canonical)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: signer rotation %d deserialize: %w", c.Sequence, err)
		}
		rp, err := verifier.DecodeRotationPayload(e.DomainPayload)
		if err != nil {
			if errors.Is(err, verifier.ErrRotationKindMismatch) {
				continue // on the rotation schema but not a rotation payload — skip
			}
			return nil, fmt.Errorf("bundle/standalone: signer rotation %d decode: %w", c.Sequence, err)
		}
		if rp.SignerDID == signer {
			kept = append(kept, c)
		}
	}
	return kept, nil
}

// schemaChainSection gathers the target entry's schema-succession history: from the
// entry's SchemaRef, walk predecessor_schema links — extracted exactly as the SDK's
// verifier.WalkSchemaChain does — collecting each version. A no-SchemaRef entry ⇒
// null.
func (g *StandaloneLedgerGather) schemaChainSection(ctx context.Context) (json.RawMessage, error) {
	entry, err := g.targetEntry(ctx)
	if err != nil {
		return nil, err
	}
	ref := entry.Header.SchemaRef
	if ref == nil {
		return nil, nil
	}
	chain, err := walkSchemaPredecessors(ctx, *ref, g.fetchCanonical)
	if err != nil {
		return nil, err
	}
	head, err := g.getHorizon()
	if err != nil {
		return nil, err
	}
	return AssembleEvolutionChain(ctx, g, chain, head)
}

// walkSchemaPredecessors walks the schema-succession chain from `start`, following
// predecessor_schema (extracted via schema.NewJSONParameterExtractor, exactly as the
// SDK), cycle- and depth-guarded (maxSchemaChainDepth, matching the SDK so the gather
// never produces a chain the verifier rejects). A predecessor on a foreign log is
// rejected (out of single-network scope), and a chain that does not terminate within
// the depth bound is an error — never a silent truncation.
func walkSchemaPredecessors(ctx context.Context, start types.LogPosition, fetch func(context.Context, uint64) ([]byte, error)) ([]DiscoveredEntry, error) {
	extractor := schema.NewJSONParameterExtractor()
	logDID := start.LogDID
	visited := make(map[uint64]bool)
	var chain []DiscoveredEntry
	cur := start
	for depth := 0; depth < maxSchemaChainDepth; depth++ {
		if cur.LogDID != logDID {
			return nil, fmt.Errorf("bundle/standalone: schema_chain crosses logs (%s != %s) — out of single-network scope", cur.LogDID, logDID)
		}
		if visited[cur.Sequence] {
			return nil, fmt.Errorf("bundle/standalone: schema_chain cycle at sequence %d", cur.Sequence)
		}
		visited[cur.Sequence] = true
		canonical, err := fetch(ctx, cur.Sequence)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: fetch schema %d: %w", cur.Sequence, err)
		}
		se, err := envelope.Deserialize(canonical)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: schema %d deserialize: %w", cur.Sequence, err)
		}
		params, err := extractor.Extract(se)
		if err != nil {
			return nil, fmt.Errorf("bundle/standalone: schema %d extract: %w", cur.Sequence, err)
		}
		chain = append(chain, DiscoveredEntry{Sequence: cur.Sequence})
		if params.PredecessorSchema == nil {
			return chain, nil
		}
		cur = *params.PredecessorSchema
	}
	return nil, fmt.Errorf("bundle/standalone: schema_chain exceeds max depth %d (unterminated)", maxSchemaChainDepth)
}
