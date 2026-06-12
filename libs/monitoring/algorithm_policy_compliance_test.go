package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
	sdkmon "github.com/baseproof/baseproof/monitoring"

	"github.com/baseproof/tooling/libs/crosslog"
)

func ar(id uint16, st authz.AlgorithmLifecycleState) authz.AlgorithmRecord {
	return authz.AlgorithmRecord{AlgoID: id, LifecycleState: st}
}

func algoRec(seq uint64, recs ...authz.AlgorithmRecord) authz.AlgorithmPolicyRecord {
	return authz.AlgorithmPolicyRecord{EffectivePos: gpos(seq), Policy: authz.AlgorithmPolicy{Algorithms: recs}}
}

func runAlgoPolicy(cfg AlgorithmPolicyComplianceConfig) []sdkmon.Alert {
	a, _ := CheckAlgorithmPolicyCompliance(context.Background(), cfg, time.Unix(1000, 0))
	return a
}

func TestAlgorithmPolicy_Compliant_NoAlerts(t *testing.T) {
	cfg := AlgorithmPolicyComplianceConfig{
		Records: authz.AlgorithmPolicyByPosition{algoRec(0, ar(envelope.SigAlgoECDSA, authz.AlgorithmActive))},
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:org:a", 1, envelope.SigAlgoECDSA)},
		AsOf:    gpos(100),
	}
	if a := runAlgoPolicy(cfg); len(a) != 0 {
		t.Fatalf("compliant inputs must raise no alerts, got %+v", a)
	}
}

// The headline finding: an amendment chain that rolls a lifecycle BACKWARD
// (deprecated → active) is rejected by ResolveAlgorithmPolicyAt; the monitor
// surfaces that as Critical.
func TestAlgorithmPolicy_LifecycleRollback_Critical(t *testing.T) {
	cfg := AlgorithmPolicyComplianceConfig{
		Records: authz.AlgorithmPolicyByPosition{
			algoRec(0, ar(envelope.SigAlgoECDSA, authz.AlgorithmActive)),
			algoRec(50, ar(envelope.SigAlgoECDSA, authz.AlgorithmDeprecated)),
			algoRec(100, ar(envelope.SigAlgoECDSA, authz.AlgorithmActive)), // rollback!
		},
		AsOf: gpos(200),
	}
	a := runAlgoPolicy(cfg)
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("lifecycle rollback must raise one Critical, got %+v", a)
	}
}

func TestAlgorithmPolicy_ForbiddenAlgorithmAdmitted_Critical(t *testing.T) {
	cfg := AlgorithmPolicyComplianceConfig{
		Records: authz.AlgorithmPolicyByPosition{
			algoRec(0, ar(envelope.SigAlgoECDSA, authz.AlgorithmActive)),
			algoRec(50, ar(envelope.SigAlgoECDSA, authz.AlgorithmForbidden)), // legal retirement
		},
		// Entry at seq 60 signed with the now-forbidden algorithm.
		Entries: []crosslog.EntryAtPosition{mkEntry(60, "did:org:a", 1, envelope.SigAlgoECDSA)},
		AsOf:    gpos(100),
	}
	a := runAlgoPolicy(cfg)
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("entry signed with a forbidden algorithm must raise one Critical, got %+v", a)
	}
}

func TestAlgorithmPolicy_AbsentAlgorithmAdmitted_Critical(t *testing.T) {
	cfg := AlgorithmPolicyComplianceConfig{
		Records: authz.AlgorithmPolicyByPosition{algoRec(0, ar(envelope.SigAlgoECDSA, authz.AlgorithmActive))},
		// SLH-DSA (0x09) is not in the policy at all → not permitted.
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:org:a", 1, envelope.SigAlgoSLHDSA128s)},
		AsOf:    gpos(100),
	}
	if countSeverity(runAlgoPolicy(cfg), sdkmon.Critical) != 1 {
		t.Fatal("entry signed with an absent algorithm must raise one Critical")
	}
}

// A DEPRECATED algorithm still permits verification (active or deprecated), so
// an entry signed under it is NOT a violation.
func TestAlgorithmPolicy_DeprecatedStillPermitted_NoAlert(t *testing.T) {
	cfg := AlgorithmPolicyComplianceConfig{
		Records: authz.AlgorithmPolicyByPosition{
			algoRec(0, ar(envelope.SigAlgoECDSA, authz.AlgorithmActive)),
			algoRec(50, ar(envelope.SigAlgoECDSA, authz.AlgorithmDeprecated)),
		},
		Entries: []crosslog.EntryAtPosition{mkEntry(60, "did:org:a", 1, envelope.SigAlgoECDSA)},
		AsOf:    gpos(100),
	}
	if a := runAlgoPolicy(cfg); len(a) != 0 {
		t.Fatalf("deprecated algorithm still permits verification — no alert expected, got %+v", a)
	}
}

// An entry before the genesis record resolves to "none in effect" → Warning
// (infrastructure fault), and a nil entry is skipped.
func TestAlgorithmPolicy_EntryBeforeGenesis_Warning(t *testing.T) {
	cfg := AlgorithmPolicyComplianceConfig{
		Records: authz.AlgorithmPolicyByPosition{algoRec(10, ar(envelope.SigAlgoECDSA, authz.AlgorithmActive))},
		Entries: []crosslog.EntryAtPosition{
			{Position: gpos(0), Entry: nil},                     // skipped
			mkEntry(5, "did:org:a", 1, envelope.SigAlgoECDSA), // before genesis(seq 10) → Warning
		},
		AsOf: gpos(100),
	}
	a := runAlgoPolicy(cfg)
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("entry before genesis must Warn, got %+v", a)
	}
}

func TestAlgorithmPolicy_EmptyRecords_NoOp(t *testing.T) {
	if a := runAlgoPolicy(AlgorithmPolicyComplianceConfig{AsOf: gpos(1)}); a != nil {
		t.Fatalf("empty records (unwired) must no-op, got %+v", a)
	}
}
