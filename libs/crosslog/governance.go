/*
FILE PATH: libs/crosslog/governance.go

Projects the THREE on-log network-governance amendment chains — signature
policy, algorithm policy, protocol-version admission — from a flat slice of
pre-positioned envelope entries into the genesis-seeded, EffectivePos-sorted
record slices that the SDK's Resolve…At walkers consume:

  - network.ResolveSignaturePolicyAt        ← SignaturePolicyByPosition
  - authz.ResolveAlgorithmPolicyAt          ← AlgorithmPolicyByPosition
  - authz.ResolveProtocolVersionAdmissionAt ← ProtocolVersionAdmissionByPosition

# WHY THIS HELPER EXISTS

The auditor's job is to INDEPENDENTLY re-derive the network governance state the
ledger enforces at admission. The SDK ships the walkers + decoders; this helper
does the kind-discriminated decode + genesis seeding + sort in one place so the
monitors get a resolver-ready chain. It is the governance sibling of
MaterializeFromEntries (which handles the four witness/auditor network kinds).

# GENESIS SEEDING (records[0]) — MATCHES THE LEDGER

Every SDK Resolve…At walker requires records[0] to be the genesis baseline (it
returns ErrXxxRecordsEmpty / ErrXxxNoneInEffect otherwise). The ledger
SYNTHESIZES the genesis baselines from the bootstrap document — there are no
dedicated GenesisAlgorithmPolicy / GenesisProtocolVersion fields — and the
auditor MUST synthesize them the SAME way or it would diverge from the ledger
and raise false findings:

  - signature policy : doc.GenesisSignaturePolicy verbatim
    (network.GenesisRecordFromBootstrap).
  - algorithm policy : every AllowedEntrySigSchemes algorithm starts ACTIVE
    (mirrors ledger admission.GenesisAlgorithmPolicyFromBootstrap).
  - protocol version : the binary's current wire version, read_write
    (mirrors ledger admission.GenesisProtocolVersionPolicy).

GovernanceGenesisFromBootstrap centralizes that synthesis so the rule lives in
exactly one place on the auditor side.

# WARN-AND-CONTINUE ERROR MODEL

Mirrors MaterializeFromEntries: a per-entry decode failure logs a structured
warn and continues; a kind-mismatched entry (the common case — application
payloads, witness/auditor kinds, findings) is silently skipped. A single
malformed governance entry never aborts the projection.

KEY DEPENDENCIES: baseproof/network, baseproof/authz, baseproof/kinds, baseproof/types,
baseproof/core/envelope.
*/
package crosslog

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/kinds"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// GovernanceGenesis carries the synthesized genesis records (records[0]) for
// each governance chain. The auditor derives them from the bootstrap document
// the SAME way the ledger does (see GovernanceGenesisFromBootstrap).
type GovernanceGenesis struct {
	SignaturePolicy network.SignaturePolicyRecord
	AlgorithmPolicy authz.AlgorithmPolicyRecord
	ProtocolVersion authz.ProtocolVersionAdmissionRecord
}

// GovernanceGenesisFromBootstrap synthesizes the three genesis records from the
// bootstrap document, mirroring the ledger's admission genesis rule exactly:
//
//   - signature policy : doc.GenesisSignaturePolicy.
//   - algorithm policy : every doc.GenesisSignaturePolicy.AllowedEntrySigSchemes
//     algorithm starts ACTIVE.
//   - protocol version : envelope.CurrentProtocolVersion(), read_write.
//
// originLogDID is the network's log DID (the auditor's exchange DID); the
// genesis records are stamped at {originLogDID, Sequence: 0} so they sort before
// every on-log amendment. identity is carried as the records' advisory
// Checkpoint (the ledger passes the NetworkID; callers may pass the zero value).
func GovernanceGenesisFromBootstrap(
	doc network.BootstrapDocument,
	originLogDID string,
	identity [32]byte,
) GovernanceGenesis {
	originPos := types.LogPosition{LogDID: originLogDID, Sequence: 0}
	return GovernanceGenesis{
		SignaturePolicy: network.GenesisRecordFromBootstrap(doc, originPos, identity),
		AlgorithmPolicy: authz.GenesisAlgorithmPolicyRecord(
			genesisAlgorithmPolicy(doc), originPos, identity),
		ProtocolVersion: authz.GenesisProtocolVersionAdmissionRecord(
			genesisProtocolVersionPolicy(), originPos, identity),
	}
}

// GenesisCosignSchemeTags resolves a network's admitted cosignature scheme
// tags (AllowedCosignSchemeTags) from the GENESIS signature policy synthesized
// from the bootstrap document, through the SDK governance walker
// (network.ResolveSignaturePolicyAt over MaterializeGovernance's genesis-seeded
// chain). It is the ONE canonical path for "read the cosign policy from the
// bootstrap", so every consumer (auditor, judicial-network, ...) resolves it
// identically instead of each composing the walker — or field-reading
// doc.GenesisSignaturePolicy.AllowedCosignSchemeTags — on its own. Pair it with
// BuildWitnessSetsForPolicy.
//
// A bootstrap that declares no genesis signature policy returns (nil, nil): the
// caller's ECDSA-only default (BuildWitnessSetsForPolicy routes nil tags to its
// ECDSA-only path). A declared policy is resolved and its tags returned; the
// walker's validation surfaces a malformed policy as an error.
func GenesisCosignSchemeTags(doc network.BootstrapDocument, networkID [32]byte) ([]uint8, error) {
	if len(doc.GenesisSignaturePolicy.AllowedCosignSchemeTags) == 0 {
		return nil, nil
	}
	gov := GovernanceGenesisFromBootstrap(doc, doc.ExchangeDID, networkID)
	materialized := MaterializeGovernance(nil, gov, slog.Default())
	policy, err := network.ResolveSignaturePolicyAt(
		materialized.SignaturePolicies,
		types.LogPosition{LogDID: doc.ExchangeDID, Sequence: 0},
	)
	if err != nil {
		return nil, fmt.Errorf("crosslog: resolve genesis signature policy: %w", err)
	}
	return policy.AllowedCosignSchemeTags, nil
}

// genesisAlgorithmPolicy synthesizes the genesis algorithm policy: every
// genesis-allowed entry signature scheme starts ACTIVE. Mirrors the ledger's
// admission.GenesisAlgorithmPolicyFromBootstrap.
func genesisAlgorithmPolicy(doc network.BootstrapDocument) authz.AlgorithmPolicy {
	allowed := doc.GenesisSignaturePolicy.AllowedEntrySigSchemes
	recs := make([]authz.AlgorithmRecord, 0, len(allowed))
	for _, algo := range allowed {
		recs = append(recs, authz.AlgorithmRecord{
			AlgoID:         algo,
			LifecycleState: authz.AlgorithmActive,
		})
	}
	return authz.AlgorithmPolicy{Algorithms: recs}
}

// genesisProtocolVersionPolicy synthesizes the genesis protocol-version policy:
// the binary's current wire version, admitted read_write. Mirrors the ledger's
// admission.GenesisProtocolVersionPolicy.
func genesisProtocolVersionPolicy() authz.ProtocolVersionAdmissionPolicy {
	return authz.ProtocolVersionAdmissionPolicy{
		AdmittedVersions: []authz.ProtocolVersionRecord{{
			Version:     envelope.CurrentProtocolVersion(),
			AdmittedFor: authz.ProtocolVersionReadWrite,
		}},
	}
}

// MaterializedGovernance is the three genesis-seeded, EffectivePos-sorted record
// chains a governance-compliance monitor resolves. Each is ready to hand
// straight to its SDK Resolve…At walker (the ErrRecordsUnsorted contract is
// satisfied at this boundary).
type MaterializedGovernance struct {
	SignaturePolicies network.SignaturePolicyByPosition
	AlgorithmPolicies authz.AlgorithmPolicyByPosition
	ProtocolVersions  authz.ProtocolVersionAdmissionByPosition
}

// kindProbe reads just the discriminator from a governance payload so dispatch
// hits exactly one decoder (the kind-probe discipline MaterializeFromEntries
// adopted — no try-each-decoder cascade).
type kindProbe struct {
	Kind string `json:"kind"`
}

// MaterializeGovernance seeds the genesis records[0] for each chain, decodes the
// on-log amendment entries into the matching chain, and returns the three
// EffectivePos-sorted slices. Per-entry decode failures log a structured warn
// and continue; kind-mismatched entries (the majority) are silently skipped.
//
// The genesis records are always present (records[0]); an empty entries slice
// therefore yields genesis-only chains, which resolve cleanly to the founding
// policy. logger nil routes to slog.Default().
func MaterializeGovernance(
	entries []EntryAtPosition,
	genesis GovernanceGenesis,
	logger *slog.Logger,
) MaterializedGovernance {
	if logger == nil {
		logger = slog.Default()
	}

	out := MaterializedGovernance{
		SignaturePolicies: network.SignaturePolicyByPosition{genesis.SignaturePolicy},
		AlgorithmPolicies: authz.AlgorithmPolicyByPosition{genesis.AlgorithmPolicy},
		ProtocolVersions:  authz.ProtocolVersionAdmissionByPosition{genesis.ProtocolVersion},
	}

	for _, e := range entries {
		if e.Entry == nil {
			continue
		}
		payload := e.Entry.DomainPayload
		if len(payload) == 0 {
			continue
		}
		var probe kindProbe
		if err := json.Unmarshal(payload, &probe); err != nil {
			logger.Warn("crosslog/governance: payload not JSON-parseable",
				"seq", e.Position.Sequence, "err", err)
			continue
		}
		switch probe.Kind {
		case kinds.EntryNetworkSignaturePolicyV1:
			p, err := network.DecodeSignaturePolicyAmendmentPayload(payload)
			if err != nil {
				logger.Warn("crosslog/governance: signature_policy decode rejected",
					"seq", e.Position.Sequence, "err", err)
				continue
			}
			out.SignaturePolicies = append(out.SignaturePolicies,
				network.ToSignaturePolicyRecord(p, e.Position, e.Checkpoint))
			logger.Debug("crosslog/governance: signature_policy_amendment",
				"seq", e.Position.Sequence)
		case kinds.EntryNetworkAlgorithmPolicyV1:
			p, err := authz.DecodeAlgorithmPolicyPayload(payload)
			if err != nil {
				logger.Warn("crosslog/governance: algorithm_policy decode rejected",
					"seq", e.Position.Sequence, "err", err)
				continue
			}
			out.AlgorithmPolicies = append(out.AlgorithmPolicies,
				p.ToRecord(e.Position, e.Checkpoint))
			logger.Debug("crosslog/governance: algorithm_policy_amendment",
				"seq", e.Position.Sequence, "algorithms", len(p.Algorithms))
		case kinds.EntryNetworkProtocolVersionV1:
			p, err := authz.DecodeProtocolVersionAdmissionPayload(payload)
			if err != nil {
				logger.Warn("crosslog/governance: protocol_version decode rejected",
					"seq", e.Position.Sequence, "err", err)
				continue
			}
			out.ProtocolVersions = append(out.ProtocolVersions,
				p.ToRecord(e.Position, e.Checkpoint))
			logger.Debug("crosslog/governance: protocol_version_amendment",
				"seq", e.Position.Sequence, "versions", len(p.AdmittedVersions))
		default:
			// Some other kind — silently skip (the common case).
		}
	}

	sort.Sort(out.SignaturePolicies)
	sort.Sort(out.AlgorithmPolicies)
	sort.Sort(out.ProtocolVersions)

	logger.Info("crosslog/governance: complete",
		"signature_policies", len(out.SignaturePolicies),
		"algorithm_policies", len(out.AlgorithmPolicies),
		"protocol_versions", len(out.ProtocolVersions))
	return out
}
