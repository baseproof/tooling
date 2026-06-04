package monitoring

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"
)

// =========================================================================
// HealthGrade constants and String()
// =========================================================================

func TestHealthGrade_OK_String(t *testing.T) {
	if GradeOK.String() != "OK" {
		t.Errorf("GradeOK.String() = %q", GradeOK.String())
	}
}

func TestHealthGrade_Info_String(t *testing.T) {
	if GradeInfo.String() != "INFO" {
		t.Errorf("GradeInfo.String() = %q", GradeInfo.String())
	}
}

func TestHealthGrade_Warning_String(t *testing.T) {
	if GradeWarning.String() != "WARNING" {
		t.Errorf("GradeWarning.String() = %q", GradeWarning.String())
	}
}

func TestHealthGrade_Critical_String(t *testing.T) {
	if GradeCritical.String() != "CRITICAL" {
		t.Errorf("GradeCritical.String() = %q", GradeCritical.String())
	}
}

func TestHealthGrade_Ordering(t *testing.T) {
	if GradeOK >= GradeInfo || GradeInfo >= GradeWarning || GradeWarning >= GradeCritical {
		t.Error("grades must be ordered OK < Info < Warning < Critical")
	}
}

// =========================================================================
// classifyGrade
// =========================================================================

func TestClassifyGrade_AllZero_OK(t *testing.T) {
	if g := classifyGrade(0, 0, 0); g != GradeOK {
		t.Errorf("got %v, want OK", g)
	}
}

func TestClassifyGrade_Critical(t *testing.T) {
	if g := classifyGrade(1, 0, 0); g != GradeCritical {
		t.Errorf("got %v, want Critical", g)
	}
}

func TestClassifyGrade_Warning(t *testing.T) {
	if g := classifyGrade(0, 1, 0); g != GradeWarning {
		t.Errorf("got %v, want Warning", g)
	}
}

func TestClassifyGrade_Info(t *testing.T) {
	if g := classifyGrade(0, 0, 1); g != GradeInfo {
		t.Errorf("got %v, want Info", g)
	}
}

func TestClassifyGrade_CriticalTrumpsWarning(t *testing.T) {
	if g := classifyGrade(1, 5, 10); g != GradeCritical {
		t.Errorf("critical should trump all, got %v", g)
	}
}

// =========================================================================
// classifyNetworkGrade
// =========================================================================

func TestClassifyNetworkGrade_AllHealthy(t *testing.T) {
	if g := classifyNetworkGrade(0, 0); g != GradeOK {
		t.Errorf("got %v, want OK", g)
	}
}

func TestClassifyNetworkGrade_SomeCritical(t *testing.T) {
	if g := classifyNetworkGrade(1, 0); g != GradeCritical {
		t.Errorf("got %v, want Critical", g)
	}
}

func TestClassifyNetworkGrade_SomeWarning(t *testing.T) {
	if g := classifyNetworkGrade(0, 2); g != GradeWarning {
		t.Errorf("got %v, want Warning", g)
	}
}

// =========================================================================
// classifyAnchorGap
// =========================================================================

func TestClassifyAnchorGap_BelowThreshold(t *testing.T) {
	cfg := AnchorFreshnessConfig{
		WarningThreshold:  90 * time.Minute,
		CriticalThreshold: 3 * time.Hour,
	}
	sev, _ := classifyAnchorGap(30*time.Minute, cfg)
	if sev != 0 {
		t.Errorf("30m gap should be OK, got severity %d", sev)
	}
}

func TestClassifyAnchorGap_Warning(t *testing.T) {
	cfg := AnchorFreshnessConfig{
		WarningThreshold:  90 * time.Minute,
		CriticalThreshold: 3 * time.Hour,
	}
	sev, _ := classifyAnchorGap(2*time.Hour, cfg)
	if sev != monitoring.Warning {
		t.Errorf("2h gap should be Warning, got %d", sev)
	}
}

func TestClassifyAnchorGap_Critical(t *testing.T) {
	cfg := AnchorFreshnessConfig{
		WarningThreshold:  90 * time.Minute,
		CriticalThreshold: 3 * time.Hour,
	}
	sev, _ := classifyAnchorGap(4*time.Hour, cfg)
	if sev != monitoring.Critical {
		t.Errorf("4h gap should be Critical, got %d", sev)
	}
}

func TestClassifyAnchorGap_ZeroThresholds(t *testing.T) {
	cfg := AnchorFreshnessConfig{} // zero thresholds
	sev, _ := classifyAnchorGap(999*time.Hour, cfg)
	if sev != 0 {
		t.Error("zero thresholds should never fire")
	}
}

// =========================================================================
// BuildDashboard
// =========================================================================

func TestBuildDashboard_Empty(t *testing.T) {
	nh := BuildDashboard(nil, time.Now())
	if nh == nil {
		t.Fatal("dashboard must not be nil")
	}
	if nh.TotalCourts != 0 {
		t.Errorf("TotalCourts = %d", nh.TotalCourts)
	}
	if nh.Grade != GradeOK {
		t.Errorf("empty = %v, want OK", nh.Grade)
	}
}

func TestBuildDashboard_OneHealthyCourt(t *testing.T) {
	input := map[string][]MonitorResult{
		"did:web:davidson": {},
	}
	nh := BuildDashboard(input, time.Now())
	if nh.TotalCourts != 1 {
		t.Errorf("TotalCourts = %d", nh.TotalCourts)
	}
	if nh.Grade != GradeOK {
		t.Errorf("grade = %v, want OK", nh.Grade)
	}
	if len(nh.Courts) != 1 || nh.Courts[0].Grade != GradeOK {
		t.Error("court should be OK")
	}
}

func TestBuildDashboard_CriticalCourt(t *testing.T) {
	input := map[string][]MonitorResult{
		"did:web:davidson": {
			{
				Monitor: "judicial.delegation_health",
				Alerts: []monitoring.Alert{
					{Severity: monitoring.Critical, Message: "non-live signer active"},
				},
			},
		},
	}
	nh := BuildDashboard(input, time.Now())
	if nh.Grade != GradeCritical {
		t.Errorf("network grade = %v, want Critical", nh.Grade)
	}
	if nh.CriticalCourts != 1 {
		t.Errorf("CriticalCourts = %d", nh.CriticalCourts)
	}
}

func TestBuildDashboard_SortsCriticalFirst(t *testing.T) {
	input := map[string][]MonitorResult{
		"did:web:healthy": {},
		"did:web:broken": {
			{
				Monitor: "test",
				Alerts:  []monitoring.Alert{{Severity: monitoring.Critical}},
			},
		},
	}
	nh := BuildDashboard(input, time.Now())
	if len(nh.Courts) != 2 {
		t.Fatalf("courts = %d", len(nh.Courts))
	}
	if nh.Courts[0].Grade != GradeCritical {
		t.Error("critical court should sort first")
	}
}

func TestBuildDashboard_AlertsByMonitor(t *testing.T) {
	input := map[string][]MonitorResult{
		"did:web:court": {
			{Monitor: "mon_a", Alerts: []monitoring.Alert{{Severity: monitoring.Warning}}},
			{Monitor: "mon_b", Alerts: []monitoring.Alert{{Severity: monitoring.Warning}, {Severity: monitoring.Info}}},
		},
	}
	nh := BuildDashboard(input, time.Now())
	court := nh.Courts[0]
	if court.AlertsByMonitor["mon_a"] != 1 {
		t.Errorf("mon_a = %d", court.AlertsByMonitor["mon_a"])
	}
	if court.AlertsByMonitor["mon_b"] != 2 {
		t.Errorf("mon_b = %d", court.AlertsByMonitor["mon_b"])
	}
}

// =========================================================================
// CheckShardHealth
// =========================================================================

func TestCheckShardHealth_EmptyShards(t *testing.T) {
	alerts, err := CheckShardHealth(ShardHealthConfig{}, time.Now())
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("empty shards should produce no alerts, got %d", len(alerts))
	}
}

// =========================================================================
// decodeCapsule
// =========================================================================

func TestDecodeCapsule_EmptyString(t *testing.T) {
	c, err := decodeCapsule("")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if c != nil {
		t.Error("empty string should return nil capsule")
	}
}

func TestDecodeCapsule_TooShort(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	_, err := decodeCapsule(short)
	if err == nil {
		t.Fatal("expected error for short capsule")
	}
}

func TestDecodeCapsule_InvalidBase64(t *testing.T) {
	_, err := decodeCapsule("!!!not-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// =========================================================================
// errorString
// =========================================================================

func TestErrorString_Nil(t *testing.T) {
	if s := errorString(nil); s != "" {
		t.Errorf("got %q, want empty", s)
	}
}

func TestErrorString_NonNil(t *testing.T) {
	if s := errorString(fmt.Errorf("test")); s != "test" {
		t.Errorf("got %q, want test", s)
	}
}

// =========================================================================
// makeComplianceAlert
// =========================================================================

func TestMakeComplianceAlert_Fields(t *testing.T) {
	alert := makeComplianceAlert(
		monitoring.Critical,
		"premature",
		types.LogPosition{LogDID: "did:web:test", Sequence: 42},
		"did:web:judge",
		"test message",
		map[string]any{"extra": "data"},
		time.Now(),
	)
	if alert.Monitor != MonitorSealingCompliance {
		t.Errorf("Monitor = %v", alert.Monitor)
	}
	if alert.Severity != monitoring.Critical {
		t.Errorf("Severity = %v", alert.Severity)
	}
	if alert.Details["kind"] != "premature" {
		t.Errorf("kind = %v", alert.Details["kind"])
	}
	if alert.Details["extra"] != "data" {
		t.Error("extra details not merged")
	}
	if alert.Details["signer"] != "did:web:judge" {
		t.Error("signer not set")
	}
}

// =========================================================================
// Config structs: verify all fields accessible
// =========================================================================

func TestAnchorFreshnessConfig_Fields(t *testing.T) {
	cfg := AnchorFreshnessConfig{
		LocalLogDID:          "did:web:local",
		ParentLogDID:         "did:web:parent",
		AnchorIntervalTarget: time.Hour,
		WarningThreshold:     90 * time.Minute,
		CriticalThreshold:    3 * time.Hour,
		LedgerSignerDID:      "did:web:ledger",
	}
	if cfg.LocalLogDID == "" {
		t.Error("LocalLogDID required")
	}
}

func TestDelegationHealthConfig_Fields(t *testing.T) {
	cfg := DelegationHealthConfig{
		LocalLogDID:    "did:web:local",
		ScanLookback:   500,
		ScanStartSeq:   0,
		OfficersLogDID: "did:web:officers",
	}
	if cfg.ScanLookback != 500 {
		t.Errorf("ScanLookback = %d", cfg.ScanLookback)
	}
}

func TestSealingComplianceConfig_Fields(t *testing.T) {
	cfg := SealingComplianceConfig{
		LocalLogDID:  "did:web:local",
		ScanStartSeq: 0,
		ScanCount:    500,
		OverdueSlack: time.Hour,
	}
	if cfg.OverdueSlack != time.Hour {
		t.Errorf("OverdueSlack = %v", cfg.OverdueSlack)
	}
}

func TestGrantComplianceConfig_Fields(t *testing.T) {
	cfg := GrantComplianceConfig{
		LocalLogDID:       "did:web:local",
		ScanStartSeq:      0,
		ScanCount:         500,
		AttesterSignerDID: "did:web:attester",
	}
	if cfg.AttesterSignerDID != "did:web:attester" {
		t.Error("AttesterSignerDID")
	}
}

func TestMirrorConsistencyConfig_Fields(t *testing.T) {
	cfg := MirrorConsistencyConfig{
		OfficersLogDID:  "did:web:officers",
		CasesLogDID:     "did:web:cases",
		MirrorSignerDID: "did:web:mirror",
	}
	if cfg.MirrorSignerDID != "did:web:mirror" {
		t.Error("MirrorSignerDID")
	}
}

func TestShardHealthConfig_Fields(t *testing.T) {
	cfg := ShardHealthConfig{
		FreezeThreshold: 1000000,
		WarnAtFraction:  0.8,
		LogDID:          "did:web:log",
	}
	if cfg.WarnAtFraction != 0.8 {
		t.Errorf("WarnAtFraction = %f", cfg.WarnAtFraction)
	}
}
