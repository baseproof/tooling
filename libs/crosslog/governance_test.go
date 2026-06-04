package crosslog

import (
	"io"
	"log/slog"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

const govLogDID = "did:web:ledger.example"

func govSilent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func govPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: govLogDID, Sequence: seq}
}

// entryWithPayload wraps an encoded governance payload as a positioned entry.
func entryWithPayload(seq uint64, payload []byte) EntryAtPosition {
	return EntryAtPosition{
		Position: govPos(seq),
		Entry:    &envelope.Entry{DomainPayload: payload},
	}
}

func sampleBootstrap() network.BootstrapDocument {
	return network.BootstrapDocument{
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{envelope.SigAlgoECDSA, envelope.SigAlgoEd25519},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
}

func TestGovernanceGenesisFromBootstrap_SynthesizesAllThree(t *testing.T) {
	g := GovernanceGenesisFromBootstrap(sampleBootstrap(), govLogDID, [32]byte{})

	// All three genesis records sit at {logDID, 0} so they sort before amendments.
	for name, pos := range map[string]types.LogPosition{
		"signature": g.SignaturePolicy.EffectivePos,
		"algorithm": g.AlgorithmPolicy.EffectivePos,
		"protocol":  g.ProtocolVersion.EffectivePos,
	} {
		if pos != govPos(0) {
			t.Errorf("%s genesis EffectivePos = %v, want %v", name, pos, govPos(0))
		}
	}

	// Signature policy is the bootstrap policy verbatim.
	if got := g.SignaturePolicy.Policy.AllowedEntrySigSchemes; len(got) != 2 {
		t.Fatalf("signature genesis schemes = %v, want 2", got)
	}

	// Algorithm policy: every allowed entry scheme starts ACTIVE.
	algos := g.AlgorithmPolicy.Policy.Algorithms
	if len(algos) != 2 {
		t.Fatalf("algorithm genesis = %d records, want 2", len(algos))
	}
	for _, a := range algos {
		if a.LifecycleState != authz.AlgorithmActive {
			t.Errorf("algo 0x%04X genesis state = %q, want active", a.AlgoID, a.LifecycleState)
		}
	}
	if !g.AlgorithmPolicy.Policy.IsActive(envelope.SigAlgoEd25519) {
		t.Error("Ed25519 should be active at genesis")
	}

	// Protocol version: the current wire version, read_write.
	pv := g.ProtocolVersion.Policy
	if !pv.PermitsWrite(envelope.CurrentProtocolVersion()) {
		t.Errorf("current version %d should be write-admitted at genesis", envelope.CurrentProtocolVersion())
	}
}

func TestMaterializeGovernance_SeedsGenesisAndDecodesAmendments(t *testing.T) {
	genesis := GovernanceGenesisFromBootstrap(sampleBootstrap(), govLogDID, [32]byte{})

	sigAmend, err := network.EncodeSignaturePolicyAmendmentPayload(network.SignaturePolicy{
		AllowedEntrySigSchemes:  []uint16{envelope.SigAlgoECDSA, envelope.SigAlgoEd25519, envelope.SigAlgoMLDSA65},
		AllowedCosignSchemeTags: []uint8{0x01, 0x02},
		MinSignaturesPerEntry:   2,
	})
	if err != nil {
		t.Fatalf("encode signature amendment: %v", err)
	}
	algoAmend, err := authz.EncodeAlgorithmPolicyPayload(authz.AlgorithmPolicy{
		Algorithms: []authz.AlgorithmRecord{
			{AlgoID: envelope.SigAlgoECDSA, LifecycleState: authz.AlgorithmDeprecated},
		},
	})
	if err != nil {
		t.Fatalf("encode algorithm amendment: %v", err)
	}
	protoAmend, err := authz.EncodeProtocolVersionAdmissionPayload(authz.ProtocolVersionAdmissionPolicy{
		AdmittedVersions: []authz.ProtocolVersionRecord{
			{Version: envelope.CurrentProtocolVersion(), AdmittedFor: authz.ProtocolVersionReadOnly},
		},
	})
	if err != nil {
		t.Fatalf("encode protocol amendment: %v", err)
	}

	// Intentionally out of sequence order; the projector sorts.
	entries := []EntryAtPosition{
		entryWithPayload(30, protoAmend),
		entryWithPayload(10, sigAmend),
		entryWithPayload(20, algoAmend),
	}

	mat := MaterializeGovernance(entries, genesis, govSilent())

	// Each chain = genesis + one amendment, sorted with genesis first.
	if len(mat.SignaturePolicies) != 2 || len(mat.AlgorithmPolicies) != 2 || len(mat.ProtocolVersions) != 2 {
		t.Fatalf("chain lengths = (%d,%d,%d), want (2,2,2)",
			len(mat.SignaturePolicies), len(mat.AlgorithmPolicies), len(mat.ProtocolVersions))
	}
	if mat.SignaturePolicies[0].EffectivePos != govPos(0) {
		t.Error("signature genesis must be records[0]")
	}
	if mat.SignaturePolicies[1].EffectivePos != govPos(10) {
		t.Errorf("signature amendment at %v, want seq 10", mat.SignaturePolicies[1].EffectivePos)
	}

	// The amendments resolve at their position via the SDK walkers.
	sigNow, err := network.ResolveSignaturePolicyAt(mat.SignaturePolicies, govPos(100))
	if err != nil {
		t.Fatalf("resolve signature: %v", err)
	}
	if sigNow.MinSignaturesPerEntry != 2 {
		t.Errorf("resolved MinSignaturesPerEntry = %d, want 2 (amended)", sigNow.MinSignaturesPerEntry)
	}
	algoNow, err := authz.ResolveAlgorithmPolicyAt(mat.AlgorithmPolicies, govPos(100))
	if err != nil {
		t.Fatalf("resolve algorithm: %v", err)
	}
	if rec, _ := algoNow.Lookup(envelope.SigAlgoECDSA); rec.LifecycleState != authz.AlgorithmDeprecated {
		t.Errorf("ECDSA resolved state = %q, want deprecated", rec.LifecycleState)
	}
	protoNow, err := authz.ResolveProtocolVersionAdmissionAt(mat.ProtocolVersions, govPos(100))
	if err != nil {
		t.Fatalf("resolve protocol: %v", err)
	}
	if protoNow.PermitsWrite(envelope.CurrentProtocolVersion()) {
		t.Error("version should be read_only (not write-admitted) after the amendment")
	}
}

func TestMaterializeGovernance_SkipsUnknownAndMalformed(t *testing.T) {
	genesis := GovernanceGenesisFromBootstrap(sampleBootstrap(), govLogDID, [32]byte{})

	entries := []EntryAtPosition{
		entryWithPayload(5, []byte(`{"kind":"BP-ENTRY-SOME-OTHER-KIND","x":1}`)), // unknown kind → skip
		entryWithPayload(6, []byte(`{not json`)),                                 // malformed → warn+skip
		{Position: govPos(7), Entry: nil},                                        // nil entry → skip
		{Position: govPos(8), Entry: &envelope.Entry{DomainPayload: nil}},        // empty payload → skip
	}

	mat := MaterializeGovernance(entries, genesis, govSilent())

	// Only the genesis records survive; no amendment was decoded.
	if len(mat.SignaturePolicies) != 1 || len(mat.AlgorithmPolicies) != 1 || len(mat.ProtocolVersions) != 1 {
		t.Fatalf("chain lengths = (%d,%d,%d), want (1,1,1) genesis-only",
			len(mat.SignaturePolicies), len(mat.AlgorithmPolicies), len(mat.ProtocolVersions))
	}
}

// A nil logger routes to slog.Default() rather than panicking, and the genesis
// records are still seeded.
func TestMaterializeGovernance_NilLogger(t *testing.T) {
	genesis := GovernanceGenesisFromBootstrap(sampleBootstrap(), govLogDID, [32]byte{})
	mat := MaterializeGovernance(nil, genesis, nil)
	if len(mat.SignaturePolicies) != 1 || len(mat.AlgorithmPolicies) != 1 || len(mat.ProtocolVersions) != 1 {
		t.Fatalf("nil logger must still seed genesis-only chains, got (%d,%d,%d)",
			len(mat.SignaturePolicies), len(mat.AlgorithmPolicies), len(mat.ProtocolVersions))
	}
}

// Each governance kind has a decode-reject (warn-and-skip) path; a payload that
// claims the kind but fails the SDK's structural validation is dropped, leaving
// the chain genesis-only.
func TestMaterializeGovernance_RejectsMalformedSignatureAndProtocol(t *testing.T) {
	genesis := GovernanceGenesisFromBootstrap(sampleBootstrap(), govLogDID, [32]byte{})
	entries := []EntryAtPosition{
		entryWithPayload(10, []byte(`{"kind":"BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1","policy":{"allowed_entry_sig_schemes":[]}}`)),
		entryWithPayload(11, []byte(`{"kind":"BP-ENTRY-NETWORK-PROTOCOL-VERSION-V1","admitted_versions":[]}`)),
	}
	mat := MaterializeGovernance(entries, genesis, govSilent())
	if len(mat.SignaturePolicies) != 1 {
		t.Errorf("malformed signature amendment must be skipped, got %d", len(mat.SignaturePolicies))
	}
	if len(mat.ProtocolVersions) != 1 {
		t.Errorf("malformed protocol amendment must be skipped, got %d", len(mat.ProtocolVersions))
	}
}

func TestMaterializeGovernance_RejectsMalformedAmendmentButKeepsValidOnes(t *testing.T) {
	genesis := GovernanceGenesisFromBootstrap(sampleBootstrap(), govLogDID, [32]byte{})

	// A payload that claims the algorithm-policy kind but is structurally invalid
	// (empty algorithms) — the SDK decoder rejects it; the projector warns + skips
	// it but still keeps the valid signature amendment.
	badAlgo := []byte(`{"kind":"BP-ENTRY-NETWORK-ALGORITHM-POLICY-V1","algorithms":[]}`)
	goodSig, err := network.EncodeSignaturePolicyAmendmentPayload(network.SignaturePolicy{
		AllowedEntrySigSchemes:  []uint16{envelope.SigAlgoECDSA},
		AllowedCosignSchemeTags: []uint8{0x01},
		MinSignaturesPerEntry:   1,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	mat := MaterializeGovernance([]EntryAtPosition{
		entryWithPayload(10, badAlgo),
		entryWithPayload(11, goodSig),
	}, genesis, govSilent())

	if len(mat.AlgorithmPolicies) != 1 {
		t.Errorf("bad algorithm amendment must be skipped (genesis-only), got %d", len(mat.AlgorithmPolicies))
	}
	if len(mat.SignaturePolicies) != 2 {
		t.Errorf("valid signature amendment must survive, got %d", len(mat.SignaturePolicies))
	}
}

// ─────────────────────────────────────────────────────────────────────
// GenesisCosignSchemeTags — the canonical "cosign policy from bootstrap"
// helper shared by the auditor + network.
// ─────────────────────────────────────────────────────────────────────

func TestGenesisCosignSchemeTags_Declared(t *testing.T) {
	tags, err := GenesisCosignSchemeTags(sampleBootstrap(), [32]byte{})
	if err != nil {
		t.Fatalf("GenesisCosignSchemeTags: %v", err)
	}
	if len(tags) != 1 || tags[0] != 0x01 {
		t.Errorf("tags = %v, want [1]", tags)
	}
}

func TestGenesisCosignSchemeTags_BLSAdmitting(t *testing.T) {
	doc := sampleBootstrap()
	doc.GenesisSignaturePolicy.AllowedCosignSchemeTags = []uint8{0x01, 0x02}
	tags, err := GenesisCosignSchemeTags(doc, [32]byte{})
	if err != nil {
		t.Fatalf("GenesisCosignSchemeTags: %v", err)
	}
	if len(tags) != 2 || tags[0] != 0x01 || tags[1] != 0x02 {
		t.Errorf("tags = %v, want [1 2]", tags)
	}
}

func TestGenesisCosignSchemeTags_NoPolicy_ECDSADefault(t *testing.T) {
	// A bootstrap with no declared genesis signature policy returns nil (the
	// caller's ECDSA-only default) without invoking the walker.
	tags, err := GenesisCosignSchemeTags(network.BootstrapDocument{}, [32]byte{})
	if err != nil {
		t.Fatalf("GenesisCosignSchemeTags (no policy): %v", err)
	}
	if tags != nil {
		t.Errorf("no declared policy: want nil, got %v", tags)
	}
}
