package main

import "testing"

// TestLoadConfig_LedgerEnvWinsOverBaseproof pins the drop-in contract: the read
// front reads the writer's LEDGER_* names (so the stack passes ONE env set), with
// BASEPROOF_* only as a back-compat fallback.
func TestLoadConfig_LedgerEnvWinsOverBaseproof(t *testing.T) {
	t.Setenv("LEDGER_LOG_DID", "did:ledger")
	t.Setenv("BASEPROOF_LOG_DID", "did:baseproof")
	t.Setenv("LEDGER_DATABASE_URL", "postgres://x:x@127.0.0.1:1/x?sslmode=disable")
	t.Setenv("BASEPROOF_POSTGRES_DSN", "postgres://live/db")
	t.Setenv("LEDGER_ADDR", ":9090")
	t.Setenv("LEDGER_TESSERA_STORAGE_DIR", "/var/lib/ledger/tessera")
	t.Setenv("LEDGER_TLS_CERT_FILE", "/run/certs/server.crt")
	t.Setenv("LEDGER_TLS_KEY_FILE", "/run/certs/server.key")

	cfg := loadConfig()
	if cfg.LogDID != "did:ledger" {
		t.Errorf("LogDID = %q, want did:ledger (LEDGER_ over BASEPROOF_)", cfg.LogDID)
	}
	if cfg.PostgresDSN != "postgres://x:x@127.0.0.1:1/x?sslmode=disable" {
		t.Errorf("PostgresDSN = %q, want the LEDGER_DATABASE_URL value", cfg.PostgresDSN)
	}
	if cfg.ServerAddr != ":9090" {
		t.Errorf("ServerAddr = %q, want :9090", cfg.ServerAddr)
	}
	if cfg.TesseraStorageDir != "/var/lib/ledger/tessera" {
		t.Errorf("TesseraStorageDir = %q, want /var/lib/ledger/tessera", cfg.TesseraStorageDir)
	}
	if cfg.TLSCertFile != "/run/certs/server.crt" || cfg.TLSKeyFile != "/run/certs/server.key" {
		t.Errorf("TLS = (%q,%q), want the LEDGER_TLS_* values", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

// TestLoadConfig_BaseproofFallbackAndPlainHTTP confirms back-compat (BASEPROOF_*
// still honored) and that absent TLS material leaves the read front on plain HTTP.
func TestLoadConfig_BaseproofFallbackAndPlainHTTP(t *testing.T) {
	t.Setenv("BASEPROOF_LOG_DID", "did:legacy")
	t.Setenv("BASEPROOF_SERVER_ADDR", ":7000")

	cfg := loadConfig()
	if cfg.LogDID != "did:legacy" {
		t.Errorf("LogDID = %q, want did:legacy (BASEPROOF_ fallback)", cfg.LogDID)
	}
	if cfg.ServerAddr != ":7000" {
		t.Errorf("ServerAddr = %q, want :7000 (BASEPROOF_ fallback)", cfg.ServerAddr)
	}
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		t.Errorf("TLS = (%q,%q), want both empty (plain HTTP default)", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}
