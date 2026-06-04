package clitools

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
)

// sdklogClientTLSConfig aliases the SDK type so consumers of the Config
// helpers don't need to import the SDK directly when they only call
// the (Ledger|Exchange|Verification)TLS() accessors.
type sdklogClientTLSConfig = sdklog.ClientTLSConfig

// Config holds all tools configuration. Loaded from JSON, overridable via env.
type Config struct {
	// Upstream services (domain layer — tools have no privilege over these).
	LedgerURL        string `json:"ledger_url"`
	ArtifactStoreURL string `json:"artifact_store_url"`
	ExchangeURL      string `json:"exchange_url"`
	VerificationURL  string `json:"verification_url"`

	// Court identity.
	CourtDID       string `json:"court_did"`
	OfficersLogDID string `json:"officers_log"`
	CasesLogDID    string `json:"cases_log"`
	PartiesLogDID  string `json:"parties_log"`

	// Postgres (tools-local, NOT shared with domain).
	DatabaseURL string `json:"database_url"`

	// Server addresses.
	CourtToolsAddr    string `json:"court_tools_addr"`
	ProviderToolsAddr string `json:"provider_tools_addr"`

	// Aggregator settings.
	AggregatorPollInterval time.Duration `json:"aggregator_poll_interval"`
	AggregatorBatchSize    int           `json:"aggregator_batch_size"`

	// Auth.
	CourtSSOIssuer       string `json:"court_sso_issuer"`
	ProviderAPIKeyHeader string `json:"provider_api_key_header"`

	// mTLS material for outbound calls. When the *CertFile and
	// *KeyFile pair for a target is set, the matching tool
	// constructor (NewMTLSLedgerClient / NewMTLSExchangeClient /
	// NewMTLSVerifyClient) is wired; otherwise the non-mTLS
	// constructor is used. The *CAFile pins server verification
	// to the configured CA bundle; empty falls back to the system
	// pool. The *ServerName overrides SNI for IP-addressed
	// endpoints; empty infers from URL host.
	LedgerClientCertFile string `json:"ledger_client_cert_file"`
	LedgerClientKeyFile  string `json:"ledger_client_key_file"`
	LedgerCAFile         string `json:"ledger_ca_file"`
	LedgerServerName     string `json:"ledger_server_name"`

	// LedgerAllowSelfSigned opens the ledger leg to server-verify-only HTTPS:
	// with no client cert, verify the ledger's privately-signed/self-signed cert
	// against LedgerCAFile (REQUIRED) and present no client cert. This is the
	// zero-trust read/scan posture — the ledger gates writes on in-body crypto,
	// not transport identity. Verification stays on (never InsecureSkipVerify);
	// a missing LedgerCAFile is startup-fatal in LoadConfig.
	LedgerAllowSelfSigned bool `json:"ledger_allow_self_signed"`

	ExchangeClientCertFile string `json:"exchange_client_cert_file"`
	ExchangeClientKeyFile  string `json:"exchange_client_key_file"`
	ExchangeCAFile         string `json:"exchange_ca_file"`
	ExchangeServerName     string `json:"exchange_server_name"`

	VerificationClientCertFile string `json:"verification_client_cert_file"`
	VerificationClientKeyFile  string `json:"verification_client_key_file"`
	VerificationCAFile         string `json:"verification_ca_file"`
	VerificationServerName     string `json:"verification_server_name"`

	// Artifact-store mTLS. Mirrors the Ledger/Exchange/Verification
	// triples — the artifact store is a separate service that may
	// enforce mTLS independently of the ledger. Empty cert+key →
	// plaintext client (the legacy posture); both set → mTLS via
	// NewMTLSContentStore. Half-config (cert XOR key) is startup-fatal
	// in NewContentStore.
	ArtifactStoreClientCertFile string `json:"artifact_store_client_cert_file"`
	ArtifactStoreClientKeyFile  string `json:"artifact_store_client_key_file"`
	ArtifactStoreCAFile         string `json:"artifact_store_ca_file"`
	ArtifactStoreServerName     string `json:"artifact_store_server_name"`
}

// DefaultConfig returns a Config with sane defaults.
func DefaultConfig() Config {
	return Config{
		LedgerURL:              "http://localhost:8001",
		ArtifactStoreURL:       "http://localhost:8002",
		ExchangeURL:            "http://localhost:8003",
		VerificationURL:        "http://localhost:8080",
		CourtDID:               "did:web:courts.localhost",
		OfficersLogDID:         "did:web:courts.localhost:officers",
		CasesLogDID:            "did:web:courts.localhost:cases",
		PartiesLogDID:          "did:web:courts.localhost:parties",
		DatabaseURL:            "postgres://localhost:5432/court_tools?sslmode=disable",
		CourtToolsAddr:         ":8090",
		ProviderToolsAddr:      ":8091",
		AggregatorPollInterval: 5 * time.Second,
		AggregatorBatchSize:    100,
		ProviderAPIKeyHeader:   "X-API-Key",
	}
}

// LoadConfig reads a JSON config file and applies environment overrides.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("config: read %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	// Environment overrides take precedence.
	envOverride(&cfg.LedgerURL, "TOOLS_LEDGER_URL")
	envOverride(&cfg.ArtifactStoreURL, "TOOLS_ARTIFACT_STORE_URL")
	envOverride(&cfg.ExchangeURL, "TOOLS_EXCHANGE_URL")
	envOverride(&cfg.VerificationURL, "TOOLS_VERIFICATION_URL")
	envOverride(&cfg.CourtDID, "TOOLS_COURT_DID")
	envOverride(&cfg.OfficersLogDID, "TOOLS_OFFICERS_LOG")
	envOverride(&cfg.CasesLogDID, "TOOLS_CASES_LOG")
	envOverride(&cfg.PartiesLogDID, "TOOLS_PARTIES_LOG")
	envOverride(&cfg.DatabaseURL, "TOOLS_DATABASE_URL")
	envOverride(&cfg.CourtToolsAddr, "TOOLS_COURT_ADDR")
	envOverride(&cfg.ProviderToolsAddr, "TOOLS_PROVIDER_ADDR")

	envOverride(&cfg.LedgerClientCertFile, "TOOLS_LEDGER_CLIENT_CERT_FILE")
	envOverride(&cfg.LedgerClientKeyFile, "TOOLS_LEDGER_CLIENT_KEY_FILE")
	envOverride(&cfg.LedgerCAFile, "TOOLS_LEDGER_CA_FILE")
	envOverride(&cfg.LedgerServerName, "TOOLS_LEDGER_SERVER_NAME")
	envOverrideBool(&cfg.LedgerAllowSelfSigned, "TOOLS_LEDGER_ALLOW_SELF_SIGNED")

	envOverride(&cfg.ExchangeClientCertFile, "TOOLS_EXCHANGE_CLIENT_CERT_FILE")
	envOverride(&cfg.ExchangeClientKeyFile, "TOOLS_EXCHANGE_CLIENT_KEY_FILE")
	envOverride(&cfg.ExchangeCAFile, "TOOLS_EXCHANGE_CA_FILE")
	envOverride(&cfg.ExchangeServerName, "TOOLS_EXCHANGE_SERVER_NAME")

	envOverride(&cfg.ArtifactStoreClientCertFile, "TOOLS_ARTIFACT_STORE_CLIENT_CERT_FILE")
	envOverride(&cfg.ArtifactStoreClientKeyFile, "TOOLS_ARTIFACT_STORE_CLIENT_KEY_FILE")
	envOverride(&cfg.ArtifactStoreCAFile, "TOOLS_ARTIFACT_STORE_CA_FILE")
	envOverride(&cfg.ArtifactStoreServerName, "TOOLS_ARTIFACT_STORE_SERVER_NAME")

	envOverride(&cfg.VerificationClientCertFile, "TOOLS_VERIFICATION_CLIENT_CERT_FILE")
	envOverride(&cfg.VerificationClientKeyFile, "TOOLS_VERIFICATION_CLIENT_KEY_FILE")
	envOverride(&cfg.VerificationCAFile, "TOOLS_VERIFICATION_CA_FILE")
	envOverride(&cfg.VerificationServerName, "TOOLS_VERIFICATION_SERVER_NAME")

	// A self-signed ledger assertion with nothing to pin it to can never verify
	// safely — fail closed rather than silently demote to system roots.
	if cfg.LedgerAllowSelfSigned && cfg.LedgerCAFile == "" {
		return cfg, fmt.Errorf("config: TOOLS_LEDGER_ALLOW_SELF_SIGNED set but TOOLS_LEDGER_CA_FILE empty (a self-signed ledger cert must be pinned to a CA; verification is never skipped)")
	}

	return cfg, nil
}

// LedgerTLS returns the SDK ClientTLSConfig for the ledger endpoint.
// Use the returned struct with NewMTLSLedgerClient. When the cert/key
// pair is unset, the returned struct is the zero value — the caller
// is expected to choose the non-mTLS constructor in that case.
func (c Config) LedgerTLS() sdklogClientTLSConfig {
	return sdklogClientTLSConfig{
		ClientCertFile: c.LedgerClientCertFile,
		ClientKeyFile:  c.LedgerClientKeyFile,
		RootCAFile:     c.LedgerCAFile,
		ServerName:     c.LedgerServerName,
	}
}

// ExchangeTLS returns the SDK ClientTLSConfig for the exchange endpoint.
func (c Config) ExchangeTLS() sdklogClientTLSConfig {
	return sdklogClientTLSConfig{
		ClientCertFile: c.ExchangeClientCertFile,
		ClientKeyFile:  c.ExchangeClientKeyFile,
		RootCAFile:     c.ExchangeCAFile,
		ServerName:     c.ExchangeServerName,
	}
}

// VerificationTLS returns the SDK ClientTLSConfig for the verification endpoint.
func (c Config) VerificationTLS() sdklogClientTLSConfig {
	return sdklogClientTLSConfig{
		ClientCertFile: c.VerificationClientCertFile,
		ClientKeyFile:  c.VerificationClientKeyFile,
		RootCAFile:     c.VerificationCAFile,
		ServerName:     c.VerificationServerName,
	}
}

// ArtifactStoreTLS returns the SDK ClientTLSConfig for the artifact-store endpoint.
func (c Config) ArtifactStoreTLS() sdklogClientTLSConfig {
	return sdklogClientTLSConfig{
		ClientCertFile: c.ArtifactStoreClientCertFile,
		ClientKeyFile:  c.ArtifactStoreClientKeyFile,
		RootCAFile:     c.ArtifactStoreCAFile,
		ServerName:     c.ArtifactStoreServerName,
	}
}

// LedgerMTLSConfigured reports whether the ledger cert+key pair is
// populated. Used by main.go wiring to decide between NewLedgerClient
// (no mTLS) and NewMTLSLedgerClient (mTLS).
func (c Config) LedgerMTLSConfigured() bool {
	return c.LedgerClientCertFile != "" && c.LedgerClientKeyFile != ""
}

// LedgerServerVerifyConfigured reports whether the ledger leg should use the
// open-HTTPS server-verify posture: NOT mTLS-configured, but a CA is pinned (or
// self-signed is explicitly allowed). Used by main.go wiring to choose
// NewServerVerifyLedgerClient over the plaintext NewLedgerClient so a pinned CA
// is honored even with no client cert.
func (c Config) LedgerServerVerifyConfigured() bool {
	return !c.LedgerMTLSConfigured() && (c.LedgerAllowSelfSigned || c.LedgerCAFile != "")
}

// ExchangeMTLSConfigured reports whether the exchange cert+key pair is populated.
func (c Config) ExchangeMTLSConfigured() bool {
	return c.ExchangeClientCertFile != "" && c.ExchangeClientKeyFile != ""
}

// VerificationMTLSConfigured reports whether the verification cert+key pair is populated.
func (c Config) VerificationMTLSConfigured() bool {
	return c.VerificationClientCertFile != "" && c.VerificationClientKeyFile != ""
}

// ArtifactStoreMTLSConfigured reports whether the artifact-store cert+key pair
// is populated. Used by main.go wiring to decide between NewContentStore
// (plaintext) and NewMTLSContentStore (mTLS).
func (c Config) ArtifactStoreMTLSConfigured() bool {
	return c.ArtifactStoreClientCertFile != "" && c.ArtifactStoreClientKeyFile != ""
}

func envOverride(target *string, key string) {
	if v := os.Getenv(key); v != "" {
		*target = v
	}
}

// envOverrideBool sets *target when key is present and truthy (1/true/yes/on,
// any case). An unset or empty var leaves *target unchanged.
func envOverrideBool(target *bool, key string) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		*target = true
	}
}

// LogDIDs returns all three log DIDs for iteration.
func (c Config) LogDIDs() []string {
	return []string{c.OfficersLogDID, c.CasesLogDID, c.PartiesLogDID}
}
