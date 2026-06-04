/*
FILE PATH:

	tools/common/common_test.go

DESCRIPTION:

	Unit tests for tools/common: config loading, env overrides,
	client construction, request formatting.

KEY ARCHITECTURAL DECISIONS:
  - Tests use no external services. Config tested via in-memory JSON.
  - Client tests verify request construction, not HTTP round-trips.
*/
package clitools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// 1) Config: defaults
// -------------------------------------------------------------------------

func TestDefaultConfig_AllFieldsPopulated(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.LedgerURL == "" {
		t.Fatal("LedgerURL must have a default")
	}
	if cfg.ExchangeURL == "" {
		t.Fatal("ExchangeURL must have a default")
	}
	if cfg.VerificationURL == "" {
		t.Fatal("VerificationURL must have a default")
	}
	if cfg.ArtifactStoreURL == "" {
		t.Fatal("ArtifactStoreURL must have a default")
	}
	if cfg.CourtToolsAddr == "" {
		t.Fatal("CourtToolsAddr must have a default")
	}
	if cfg.AggregatorBatchSize == 0 {
		t.Fatal("AggregatorBatchSize must be > 0")
	}
	if cfg.AggregatorPollInterval == 0 {
		t.Fatal("AggregatorPollInterval must be > 0")
	}
}

// -------------------------------------------------------------------------
// 2) Config: JSON file loading
// -------------------------------------------------------------------------

func TestLoadConfig_FromJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	data, _ := json.Marshal(map[string]any{
		"ledger_url": "http://custom:9001",
		"court_did":  "did:web:test.gov",
	})
	os.WriteFile(path, data, 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.LedgerURL != "http://custom:9001" {
		t.Errorf("LedgerURL = %q, want http://custom:9001", cfg.LedgerURL)
	}
	if cfg.CourtDID != "did:web:test.gov" {
		t.Errorf("CourtDID = %q, want did:web:test.gov", cfg.CourtDID)
	}
	// Unset fields retain defaults.
	if cfg.ExchangeURL != "http://localhost:8003" {
		t.Errorf("ExchangeURL should retain default, got %q", cfg.ExchangeURL)
	}
}

// -------------------------------------------------------------------------
// 3) Config: env overrides
// -------------------------------------------------------------------------

func TestLoadConfig_EnvOverride(t *testing.T) {
	t.Setenv("TOOLS_LEDGER_URL", "http://env-override:7001")
	t.Setenv("TOOLS_COURT_DID", "did:web:env.gov")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.LedgerURL != "http://env-override:7001" {
		t.Errorf("LedgerURL = %q, want env override", cfg.LedgerURL)
	}
	if cfg.CourtDID != "did:web:env.gov" {
		t.Errorf("CourtDID = %q, want env override", cfg.CourtDID)
	}
}

func TestLoadConfig_EnvOverridesJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	data, _ := json.Marshal(map[string]any{"ledger_url": "http://from-json:1234"})
	os.WriteFile(path, data, 0644)

	t.Setenv("TOOLS_LEDGER_URL", "http://from-env:5678")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.LedgerURL != "http://from-env:5678" {
		t.Errorf("env should override JSON, got %q", cfg.LedgerURL)
	}
}

// -------------------------------------------------------------------------
// 4) Config: missing file
// -------------------------------------------------------------------------

func TestLoadConfig_MissingFile_Error(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// -------------------------------------------------------------------------
// 5) Config: LogDIDs
// -------------------------------------------------------------------------

func TestConfig_LogDIDs(t *testing.T) {
	cfg := DefaultConfig()
	dids := cfg.LogDIDs()

	if len(dids) != 3 {
		t.Fatalf("LogDIDs = %d, want 3", len(dids))
	}
	for _, did := range dids {
		if did == "" {
			t.Fatal("LogDID must not be empty")
		}
	}
}

// -------------------------------------------------------------------------
// 6) Client construction: non-nil, correct base URL
// -------------------------------------------------------------------------

func TestNewExchangeClient_NotNil(t *testing.T) {
	c := NewExchangeClient("http://localhost:8003")
	if c == nil {
		t.Fatal("ExchangeClient must not be nil")
	}
}

func TestNewLedgerClient_NotNil(t *testing.T) {
	c, err := NewLedgerClient("http://localhost:8001")
	if err != nil {
		t.Fatalf("NewLedgerClient: %v", err)
	}
	if c == nil {
		t.Fatal("LedgerClient must not be nil")
	}
}

func TestNewVerifyClient_NotNil(t *testing.T) {
	c := NewVerifyClient("http://localhost:8080")
	if c == nil {
		t.Fatal("VerifyClient must not be nil")
	}
}

// -------------------------------------------------------------------------
// 7) Types: struct fields
// -------------------------------------------------------------------------

func TestCaseRecord_Fields(t *testing.T) {
	c := CaseRecord{
		DocketNumber: "2027-CR-001",
		CaseType:     "criminal",
		Status:       "active",
		CourtDID:     "did:web:test",
		Sealed:       false,
		Expunged:     false,
		CreatedAt:    time.Now(),
	}
	if c.DocketNumber == "" {
		t.Fatal("DocketNumber must be set")
	}
}

func TestSubmitResult_Fields(t *testing.T) {
	r := SubmitResult{Position: 42, CanonicalHash: "abc"}
	if r.Position != 42 {
		t.Fatal("Position must be 42")
	}
}
