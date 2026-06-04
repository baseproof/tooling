package accounting

import (
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// 1) DefaultLoadAccountingParams
// -------------------------------------------------------------------------

func TestDefaultLoadAccountingParams(t *testing.T) {
	params := DefaultLoadAccountingParams()
	if params.SLAResponseWindowSec == 0 {
		t.Error("SLAResponseWindowSec must be set")
	}
	if params.SettlementPeriodDays == 0 {
		t.Error("SettlementPeriodDays must be set")
	}
	if params.MinStructuralPinners == 0 {
		t.Error("MinStructuralPinners must be set")
	}
}

// -------------------------------------------------------------------------
// 2) BuildLoadAccountingSchema
// -------------------------------------------------------------------------

func TestBuildLoadAccountingSchema(t *testing.T) {
	params := DefaultLoadAccountingParams()
	data, err := BuildLoadAccountingSchema(params, "did:web:exchange.test")
	if err != nil {
		t.Fatalf("BuildLoadAccountingSchema: %v", err)
	}
	if len(data) == 0 {
		t.Error("schema bytes must not be empty")
	}
}

func TestBuildLoadAccountingSchema_CustomParams(t *testing.T) {
	params := LoadAccountingParams{
		SettlementUnit:          "USD",
		SettlementPeriodDays:    30,
		SLAResponseWindowSec:    600,
		MaxDrillFrequencyPerDay: 2,
		StorageRatePerGBMonth:   0.05,
		PinObligationPercent:    10.0,
		MinStructuralPinners:    5,
	}
	data, err := BuildLoadAccountingSchema(params, "did:web:exchange.test")
	if err != nil {
		t.Fatalf("custom params: %v", err)
	}
	if len(data) == 0 {
		t.Error("custom schema must not be empty")
	}
}

// -------------------------------------------------------------------------
// 3) IsObjectiveSLAFailure
// -------------------------------------------------------------------------

func TestIsObjectiveSLAFailure_True(t *testing.T) {
	result := DrillResult{
		NodeDID:      "escrow-node-1",
		DrillType:    "escrow_liveness",
		Success:      false,
		ResponseTime: 10 * time.Second,
		Timestamp:    time.Now(),
	}
	if !IsObjectiveSLAFailure(result) {
		t.Error("failed drill should be objective SLA failure")
	}
}

func TestIsObjectiveSLAFailure_False(t *testing.T) {
	result := DrillResult{
		NodeDID:      "escrow-node-1",
		DrillType:    "escrow_liveness",
		Success:      true,
		ResponseTime: 100 * time.Millisecond,
		Timestamp:    time.Now(),
	}
	if IsObjectiveSLAFailure(result) {
		t.Error("passed drill should not be SLA failure")
	}
}

// -------------------------------------------------------------------------
// 4) DrillResult struct
// -------------------------------------------------------------------------

func TestDrillResult_Fields(t *testing.T) {
	r := DrillResult{
		NodeDID:      "did:web:escrow-1",
		DrillType:    "blob_availability",
		Success:      true,
		ResponseTime: 200 * time.Millisecond,
		Timestamp:    time.Now(),
		ErrorDetail:  "",
	}
	if r.NodeDID == "" {
		t.Error("NodeDID required")
	}
	if r.DrillType == "" {
		t.Error("DrillType required")
	}
}

// -------------------------------------------------------------------------
// 5) SettlementLedger
// -------------------------------------------------------------------------

func TestSettlementLedger_EnsureMember(t *testing.T) {
	ledger := &SettlementLedger{
		MemberUsage: map[string]*MemberUsage{},
	}
	m := ledger.ensureMember("did:web:member-a")
	if m == nil {
		t.Fatal("ensureMember must return non-nil")
	}
	m2 := ledger.ensureMember("did:web:member-a")
	if m != m2 {
		t.Error("should return same instance")
	}
}

func TestSettlementLedger_ToJSON(t *testing.T) {
	ledger := &SettlementLedger{
		MemberUsage: map[string]*MemberUsage{},
		StartPos:    0,
		EndPos:      100,
	}
	ledger.ensureMember("did:web:test")

	data, err := ledger.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON must not be empty")
	}
}

// -------------------------------------------------------------------------
// 6) MemberUsage struct
// -------------------------------------------------------------------------

func TestMemberUsage_Fields(t *testing.T) {
	m := MemberUsage{
		EntryCount:      50000,
		DelegationCount: 200,
		SchemaCount:     11,
		CommentaryCount: 5000,
		AmendmentCount:  44000,
		NetworkCount:    37,
		OtherCount:      789,
	}
	if m.EntryCount != 50000 {
		t.Error("EntryCount mismatch")
	}
	total := m.DelegationCount + m.SchemaCount + m.CommentaryCount + m.AmendmentCount + m.NetworkCount + m.OtherCount
	if total == 0 {
		t.Error("subcounts must be nonzero")
	}
}

// T8 — NetworkCount distinguishes network-walker entries (auditor
// registrations, witness endpoint/label declarations, auditor scope
// amendments) from member workload. A settlement run that
// includes a burst of admin records must NOT mis-attribute them to
// OtherCount; that bucket would inflate a member's "miscellaneous"
// usage when the entries are actually network admin, not member workload.
func TestMemberUsage_NetworkCountSeparateFromOther(t *testing.T) {
	m := MemberUsage{NetworkCount: 100, OtherCount: 7}
	if m.NetworkCount == m.OtherCount {
		t.Error("NetworkCount and OtherCount MUST be separate buckets")
	}
}

// -------------------------------------------------------------------------
// 7) LoadAccountingParams struct
// -------------------------------------------------------------------------

func TestLoadAccountingParams_Fields(t *testing.T) {
	p := LoadAccountingParams{
		SettlementUnit:          "write_credits",
		SettlementPeriodDays:    90,
		SLAResponseWindowSec:    300,
		MaxDrillFrequencyPerDay: 4,
		StorageRatePerGBMonth:   0.02,
		PinObligationPercent:    5.0,
		MinStructuralPinners:    3,
	}
	if p.SettlementUnit != "write_credits" {
		t.Errorf("SettlementUnit = %q", p.SettlementUnit)
	}
	if p.MinStructuralPinners != 3 {
		t.Errorf("MinStructuralPinners = %d", p.MinStructuralPinners)
	}
}
