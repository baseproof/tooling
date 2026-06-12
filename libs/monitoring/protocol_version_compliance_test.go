package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/authz"
	sdkmon "github.com/baseproof/baseproof/monitoring"

	"github.com/baseproof/tooling/libs/crosslog"
)

func pvr(v uint16, st authz.ProtocolVersionAdmissionState) authz.ProtocolVersionRecord {
	return authz.ProtocolVersionRecord{Version: v, AdmittedFor: st}
}

func protoRec(seq uint64, recs ...authz.ProtocolVersionRecord) authz.ProtocolVersionAdmissionRecord {
	return authz.ProtocolVersionAdmissionRecord{
		EffectivePos: gpos(seq),
		Policy:       authz.ProtocolVersionAdmissionPolicy{AdmittedVersions: recs},
	}
}

func runProtoPolicy(cfg ProtocolVersionComplianceConfig) []sdkmon.Alert {
	a, _ := CheckProtocolVersionCompliance(context.Background(), cfg, time.Unix(1000, 0))
	return a
}

func TestProtocolVersion_Compliant_NoAlerts(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{protoRec(0, pvr(1, authz.ProtocolVersionReadWrite))},
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:org:a", 1)},
		AsOf:    gpos(100),
	}
	if a := runProtoPolicy(cfg); len(a) != 0 {
		t.Fatalf("compliant inputs must raise no alerts, got %+v", a)
	}
}

// forbidden → read_write re-grants both capabilities — an un-retirement.
func TestProtocolVersion_UnForbid_Critical(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(0, pvr(1, authz.ProtocolVersionForbidden)),
			protoRec(50, pvr(1, authz.ProtocolVersionReadWrite)),
		},
		AsOf: gpos(100),
	}
	if countSeverity(runProtoPolicy(cfg), sdkmon.Critical) != 1 {
		t.Fatal("un-forbidding a protocol version must raise one Critical")
	}
}

// read_only → read_write re-grants the write capability.
func TestProtocolVersion_ReadOnlyToReadWrite_Critical(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(0, pvr(1, authz.ProtocolVersionReadWrite)),
			protoRec(50, pvr(1, authz.ProtocolVersionReadOnly)),   // legal: caps shrink
			protoRec(100, pvr(1, authz.ProtocolVersionReadWrite)), // illegal: write re-granted
		},
		AsOf: gpos(200),
	}
	if countSeverity(runProtoPolicy(cfg), sdkmon.Critical) != 1 {
		t.Fatal("re-granting write (read_only → read_write) must raise one Critical")
	}
}

// A monotone retirement (read_write → read_only → forbidden) only narrows
// capabilities and is legal end to end.
func TestProtocolVersion_LegalRetirement_NoAlert(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(0, pvr(1, authz.ProtocolVersionReadWrite)),
			protoRec(50, pvr(1, authz.ProtocolVersionReadOnly)),
			protoRec(100, pvr(1, authz.ProtocolVersionForbidden)),
		},
		Entries: []crosslog.EntryAtPosition{mkEntry(10, "did:org:a", 1)}, // write while read_write — fine
		AsOf:    gpos(200),
	}
	if a := runProtoPolicy(cfg); len(a) != 0 {
		t.Fatalf("a monotone retirement must raise no alerts, got %+v", a)
	}
}

func TestProtocolVersion_EntryUnderNonWriteAdmittedVersion_Critical(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(0, pvr(1, authz.ProtocolVersionReadWrite)),
			protoRec(50, pvr(1, authz.ProtocolVersionReadOnly)), // writes no longer admitted from here
		},
		// Entry at seq 60 writes under v1, which is read_only at seq 60.
		Entries: []crosslog.EntryAtPosition{mkEntry(60, "did:org:a", 1)},
		AsOf:    gpos(100),
	}
	if countSeverity(runProtoPolicy(cfg), sdkmon.Critical) != 1 {
		t.Fatal("a write under a non-write-admitted version must raise one Critical")
	}
}

// A version appearing for the FIRST time in an amendment can take any initial
// state — there is no prior state to narrow from.
func TestProtocolVersion_NewVersionAppears_Legal(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(0, pvr(1, authz.ProtocolVersionReadWrite)),
			protoRec(50, pvr(1, authz.ProtocolVersionReadWrite), pvr(2, authz.ProtocolVersionWriteOnly)),
		},
		AsOf: gpos(100),
	}
	if a := runProtoPolicy(cfg); len(a) != 0 {
		t.Fatalf("a newly-introduced version is legal, got %+v", a)
	}
}

// An entry before the genesis record resolves to "none in effect" → Warning,
// and a nil entry is skipped.
func TestProtocolVersion_EntryBeforeGenesis_Warning(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{protoRec(10, pvr(1, authz.ProtocolVersionReadWrite))},
		Entries: []crosslog.EntryAtPosition{
			{Position: gpos(0), Entry: nil}, // skipped
			mkEntry(5, "did:org:a", 1),    // before genesis(seq 10) → Warning
		},
		AsOf: gpos(100),
	}
	a := runProtoPolicy(cfg)
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("entry before genesis must Warn, got %+v", a)
	}
}

// capsOf maps an unknown/zero admission state to no capabilities (defensive
// fail-safe). A transition FROM a known writeable state TO an unknown state only
// shrinks capabilities, so it is legal and raises nothing — proving the fail-safe
// direction (an unknown state is treated as least-capable, never re-granting).
func TestProtocolVersion_UnknownStateIsLeastCapable(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(0, pvr(1, authz.ProtocolVersionReadWrite)),
			protoRec(50, pvr(1, authz.ProtocolVersionAdmissionState("quarantined"))), // unknown → caps {}
		},
		AsOf: gpos(100),
	}
	if a := runProtoPolicy(cfg); len(a) != 0 {
		t.Fatalf("transition to an unknown (least-capable) state only narrows caps — no alert, got %+v", a)
	}
}

func TestProtocolVersion_UnsortedChain_Critical(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(100, pvr(1, authz.ProtocolVersionReadWrite)),
			protoRec(0, pvr(1, authz.ProtocolVersionReadWrite)),
		},
		AsOf: gpos(200),
	}
	if countSeverity(runProtoPolicy(cfg), sdkmon.Critical) != 1 {
		t.Fatal("unsorted protocol-version chain must raise one Critical (chain integrity)")
	}
}

// write_only → forbidden narrows capabilities ({W} → {}), a legal retirement;
// it exercises the write_only capability mapping in a shared-version transition.
func TestProtocolVersion_WriteOnlyRetirement_NoAlert(t *testing.T) {
	cfg := ProtocolVersionComplianceConfig{
		Records: authz.ProtocolVersionAdmissionByPosition{
			protoRec(0, pvr(1, authz.ProtocolVersionWriteOnly)),
			protoRec(50, pvr(1, authz.ProtocolVersionForbidden)),
		},
		AsOf: gpos(100),
	}
	if a := runProtoPolicy(cfg); len(a) != 0 {
		t.Fatalf("write_only → forbidden is a legal retirement, got %+v", a)
	}
}

func TestProtocolVersion_EmptyRecords_NoOp(t *testing.T) {
	if a := runProtoPolicy(ProtocolVersionComplianceConfig{AsOf: gpos(1)}); a != nil {
		t.Fatalf("empty records (unwired) must no-op, got %+v", a)
	}
}
