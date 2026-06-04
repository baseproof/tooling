package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdkmon "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/crosslog"
)

func sigRec(seq uint64, schemes []uint16, tags []uint8, minSigs uint8) network.SignaturePolicyRecord {
	return network.SignaturePolicyRecord{
		EffectivePos: gpos(seq),
		Policy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  schemes,
			AllowedCosignSchemeTags: tags,
			MinSignaturesPerEntry:   minSigs,
		},
	}
}

func runSigPolicy(cfg SignaturePolicyComplianceConfig) []sdkmon.Alert {
	a, _ := CheckSignaturePolicyCompliance(context.Background(), cfg, time.Unix(1000, 0))
	return a
}

func TestSignaturePolicy_Compliant_NoAlerts(t *testing.T) {
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{
			sigRec(0, []uint16{envelope.SigAlgoECDSA, envelope.SigAlgoEd25519}, []uint8{0x01}, 1),
		},
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:court:a", 1, envelope.SigAlgoECDSA)},
		Heads:   []CosignedHeadObservation{{Position: gpos(10), SchemeTags: []uint8{0x01}}},
		AsOf:    gpos(100),
	}
	if a := runSigPolicy(cfg); len(a) != 0 {
		t.Fatalf("compliant inputs must raise no alerts, got %d: %+v", len(a), a)
	}
}

func TestSignaturePolicy_NonAllowedScheme_Critical(t *testing.T) {
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{sigRec(0, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 1)},
		// MLDSA65 (0x07) is not in the allow-list.
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:court:a", 1, envelope.SigAlgoMLDSA65)},
		AsOf:    gpos(100),
	}
	a := runSigPolicy(cfg)
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("non-allowed scheme must raise exactly one Critical, got %d: %+v", countSeverity(a, sdkmon.Critical), a)
	}
}

func TestSignaturePolicy_SubThresholdSignatureCount_Critical(t *testing.T) {
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{sigRec(0, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 2)},
		// One signature, policy requires 2.
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:court:a", 1, envelope.SigAlgoECDSA)},
		AsOf:    gpos(100),
	}
	if countSeverity(runSigPolicy(cfg), sdkmon.Critical) != 1 {
		t.Fatal("sub-threshold signature count must raise one Critical")
	}
}

func TestSignaturePolicy_NonAllowedCosignTag_Critical(t *testing.T) {
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{sigRec(0, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 1)},
		// Head carries a BLS (0x02) cosignature; policy admits only ECDSA (0x01).
		Heads: []CosignedHeadObservation{{Position: gpos(10), SchemeTags: []uint8{0x01, 0x02}}},
		AsOf:  gpos(100),
	}
	if countSeverity(runSigPolicy(cfg), sdkmon.Critical) != 1 {
		t.Fatal("non-allowed cosign scheme tag must raise one Critical")
	}
}

func TestSignaturePolicy_UnsatisfiableHybrid_Warning(t *testing.T) {
	after := int64(123456)
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{{
			EffectivePos: gpos(0),
			Policy: network.SignaturePolicy{
				AllowedEntrySigSchemes:  []uint16{envelope.SigAlgoECDSA, envelope.SigAlgoEd25519}, // no PQ scheme
				AllowedCosignSchemeTags: []uint8{0x01},
				MinSignaturesPerEntry:   1,
				RequireHybridAfter:      &after,
			},
		}},
		AsOf: gpos(100),
	}
	a := runSigPolicy(cfg)
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("unsatisfiable hybrid mandate must raise exactly one Warning, got %+v", a)
	}
}

func TestSignaturePolicy_HybridWithPQScheme_NoWarning(t *testing.T) {
	after := int64(123456)
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{{
			EffectivePos: gpos(0),
			Policy: network.SignaturePolicy{
				AllowedEntrySigSchemes:  []uint16{envelope.SigAlgoECDSA, envelope.SigAlgoMLDSA65}, // has PQ
				AllowedCosignSchemeTags: []uint8{0x01},
				MinSignaturesPerEntry:   1,
				RequireHybridAfter:      &after,
			},
		}},
		AsOf: gpos(100),
	}
	if a := runSigPolicy(cfg); len(a) != 0 {
		t.Fatalf("a satisfiable hybrid mandate must raise no alerts, got %+v", a)
	}
}

func TestSignaturePolicy_UnsortedChain_Critical(t *testing.T) {
	cfg := SignaturePolicyComplianceConfig{
		// Out of order: seq 100 before seq 0. ResolveSignaturePolicyAt rejects it.
		Records: network.SignaturePolicyByPosition{
			sigRec(100, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 1),
			sigRec(0, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 1),
		},
		AsOf: gpos(200),
	}
	a := runSigPolicy(cfg)
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("unsorted chain must raise one Critical (chain integrity), got %+v", a)
	}
}

func TestSignaturePolicy_EmptyRecords_NoOp(t *testing.T) {
	if a := runSigPolicy(SignaturePolicyComplianceConfig{AsOf: gpos(1)}); a != nil {
		t.Fatalf("empty records (unwired) must no-op, got %+v", a)
	}
}

// An entry (or head) BEFORE the genesis record resolves to "none in effect";
// that is an infrastructure/projection fault, surfaced per-subject as a Warning
// (not a Critical policy violation) and a nil entry is skipped.
func TestSignaturePolicy_SubjectBeforeGenesis_Warning(t *testing.T) {
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{sigRec(10, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 1)},
		Entries: []crosslog.EntryAtPosition{
			{Position: gpos(0), Entry: nil},                     // nil entry → skipped
			mkEntry(5, "did:court:a", 1, envelope.SigAlgoECDSA), // before genesis(seq 10) → Warning
		},
		Heads: []CosignedHeadObservation{{Position: gpos(5), SchemeTags: []uint8{0x01}}}, // before genesis → Warning
		AsOf:  gpos(100),
	}
	a := runSigPolicy(cfg)
	if countSeverity(a, sdkmon.Warning) != 2 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("entry+head before genesis must each Warn (2 total), got %+v", a)
	}
}

// A bundle larger than the uint8 threshold domain must not wrap and falsely trip
// the sub-threshold alert (uint8Count clamps at 255).
func TestSignaturePolicy_OversizeBundle_NoFalseSubThreshold(t *testing.T) {
	algos := make([]uint16, 300)
	for i := range algos {
		algos[i] = envelope.SigAlgoECDSA
	}
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{sigRec(0, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 64)},
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:court:a", 1, algos...)},
		AsOf:    gpos(100),
	}
	if a := runSigPolicy(cfg); len(a) != 0 {
		t.Fatalf("300 signatures (≥ threshold 64) must not trip a sub-threshold alert, got %+v", a)
	}
}

// The per-entry check resolves the policy at EACH entry's own position, so an
// amendment that widens the allow-list does NOT retroactively bless an entry
// admitted earlier under the narrower genesis policy.
func TestSignaturePolicy_PerEntryResolvedAtOwnPosition(t *testing.T) {
	cfg := SignaturePolicyComplianceConfig{
		Records: network.SignaturePolicyByPosition{
			sigRec(0, []uint16{envelope.SigAlgoECDSA}, []uint8{0x01}, 1),                           // genesis: ECDSA only
			sigRec(50, []uint16{envelope.SigAlgoECDSA, envelope.SigAlgoEd25519}, []uint8{0x01}, 1), // widened at seq 50
		},
		Entries: []crosslog.EntryAtPosition{
			mkEntry(10, "did:court:a", 1, envelope.SigAlgoEd25519), // BEFORE widening → violation
			mkEntry(60, "did:court:b", 1, envelope.SigAlgoEd25519), // AFTER widening  → OK
		},
		AsOf: gpos(100),
	}
	a := runSigPolicy(cfg)
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("only the pre-amendment Ed25519 entry should be Critical, got %d: %+v",
			countSeverity(a, sdkmon.Critical), a)
	}
}
