/*
FILE PATH: cmd/ledger/ethereum_rpc.go

DESCRIPTION:

	Ledger-side configuration and construction for the SDK's
	EthereumRPCClient. Used to enable EIP-1271 (smart-contract-wallet)
	signature verification end-to-end. When EIP-1271 is enabled the
	ledger constructs an HTTP JSON-RPC client at startup and passes
	it to did.DefaultVerifierRegistryWithRPC; when disabled the
	ledger runs in EOA-only mode (the existing behavior, no network
	surface added).

KEY ARCHITECTURAL DECISIONS:
  - Strict three-tier env-var contract:
    LEDGER_ETH_RPC_ENABLED (true/false; default false)
    LEDGER_ETH_RPC_ENDPOINT (https URL; required when enabled)
    LEDGER_ETH_RPC_TIMEOUT_MS (int ms; default 5000)
    LEDGER_ETH_RPC_ALLOW_HTTP (true/false; default false)
    "enabled" is the master switch — flipping it on without
    LEDGER_ETH_RPC_ENDPOINT is a startup error, not a silent
    degrade-to-disabled.
  - HTTPS-only by default. http:// endpoints are rejected at startup
    unless LEDGER_ETH_RPC_ALLOW_HTTP=true is set explicitly. This
    is the same default the SDK's NewHTTPEthereumRPC enforces; the
    ledger surfaces the gate at config-load time so misconfigured
    deployments fail fast (not after the first EIP-1271 traffic).
  - Production endpoints (Alchemy, Infura, QuickNode) embed an API
    key in the URL path. The ledger NEVER logs the endpoint; the
    SDK's NewHTTPEthereumRPC redacts it from error messages too.
    Ledgers audit the configured endpoint via secret-management,
    not stdout.

OVERVIEW:

	EthereumRPCConfig — the parsed env-var config
	LoadEthereumRPCConfig — populate from environment
	BuildEthereumRPCClient — construct *HTTPEthereumRPC; returns
	                             (nil, nil) when disabled, (rpc, nil)
	                             on success, (nil, err) on misconfig

KEY DEPENDENCIES:
  - github.com/baseproof/baseproof/crypto/signatures:
    EthereumRPCClient + HTTPEthereumRPC + options.
*/
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	sdkcryptosigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// defaultEthereumRPCTimeoutMS is the default per-request timeout in
// milliseconds when LEDGER_ETH_RPC_TIMEOUT_MS is unset. 5000ms is
// the SDK default and a reasonable middle ground for live signature
// verification against any major provider.
const defaultEthereumRPCTimeoutMS = 5000

// -------------------------------------------------------------------------------------------------
// 2) Config
// -------------------------------------------------------------------------------------------------

// EthereumRPCConfig is the parsed environment-variable configuration
// for the ledger's EthereumRPCClient construction at startup.
//
// Disabled-by-default: a freshly-deployed ledger with NO eth-RPC
// env vars set runs in EOA-only mode and pulls zero network surface.
type EthereumRPCConfig struct {
	// Enabled is the master switch. When false (the default), the
	// ledger does NOT construct an EthereumRPCClient and EIP-1271
	// verification is unsupported. Production deployments that
	// accept smart-contract-wallet signers MUST set this to true.
	Enabled bool

	// Endpoint is the JSON-RPC endpoint URL. Required when Enabled
	// is true. https:// is required unless AllowInsecureHTTP is set.
	Endpoint string

	// Timeout is the per-request timeout. Applies to the full
	// JSON-RPC request lifecycle (dial + write + read). Default:
	// 5 seconds.
	Timeout time.Duration

	// AllowInsecureHTTP opts in to http:// endpoints. Local-dev
	// only. Production MUST keep this false.
	AllowInsecureHTTP bool
}

// -------------------------------------------------------------------------------------------------
// 3) Errors
// -------------------------------------------------------------------------------------------------

// ErrEthereumRPCEndpointRequired is returned when
// LEDGER_ETH_RPC_ENABLED=true but LEDGER_ETH_RPC_ENDPOINT is
// empty. Ledgers that want EIP-1271 must supply an endpoint.
var ErrEthereumRPCEndpointRequired = errors.New(
	"LEDGER_ETH_RPC_ENABLED=true requires LEDGER_ETH_RPC_ENDPOINT (a JSON-RPC URL)")

// ErrEthereumRPCInsecureEndpoint is returned when an http:// endpoint
// is configured without LEDGER_ETH_RPC_ALLOW_HTTP=true. The SDK
// would reject this in NewHTTPEthereumRPC; we surface it earlier so
// startup fails fast with a clear ledger-facing error.
var ErrEthereumRPCInsecureEndpoint = errors.New(
	"LEDGER_ETH_RPC_ENDPOINT is http:// but LEDGER_ETH_RPC_ALLOW_HTTP is not true (set ALLOW_HTTP=true for local-dev only; production MUST use https://)")

// -------------------------------------------------------------------------------------------------
// 4) LoadEthereumRPCConfig — env → struct
// -------------------------------------------------------------------------------------------------

// LoadEthereumRPCConfig reads the four LEDGER_ETH_RPC_* env vars
// and returns a populated EthereumRPCConfig. Validation of
// "endpoint required when enabled" and "https-or-explicit-opt-in"
// happens here so misconfiguration aborts startup before any
// further ledger wiring occurs.
//
// Returns:
//   - the populated config and nil on success.
//   - the zero-valued config and a typed error on misconfig.
func LoadEthereumRPCConfig() (EthereumRPCConfig, error) {
	cfg := EthereumRPCConfig{
		Enabled:           os.Getenv("LEDGER_ETH_RPC_ENABLED") == "true",
		Endpoint:          os.Getenv("LEDGER_ETH_RPC_ENDPOINT"),
		AllowInsecureHTTP: os.Getenv("LEDGER_ETH_RPC_ALLOW_HTTP") == "true",
		Timeout: time.Duration(envIntOr(
			"LEDGER_ETH_RPC_TIMEOUT_MS", defaultEthereumRPCTimeoutMS)) * time.Millisecond,
	}
	if !cfg.Enabled {
		// Disabled mode. Endpoint/Timeout/AllowInsecureHTTP are
		// ignored; the ledger runs EOA-only.
		return cfg, nil
	}
	if cfg.Endpoint == "" {
		return EthereumRPCConfig{}, ErrEthereumRPCEndpointRequired
	}
	if strings.HasPrefix(strings.ToLower(cfg.Endpoint), "http://") && !cfg.AllowInsecureHTTP {
		return EthereumRPCConfig{}, ErrEthereumRPCInsecureEndpoint
	}
	return cfg, nil
}

// -------------------------------------------------------------------------------------------------
// 5) BuildEthereumRPCClient — config → client
// -------------------------------------------------------------------------------------------------

// BuildEthereumRPCClient constructs the SDK's HTTPEthereumRPC from
// the parsed config. Returns:
//   - (nil, nil)  when cfg.Enabled == false (disabled mode is the
//     default and is NOT an error).
//   - (rpc, nil)  on successful construction.
//   - (nil, err)  on SDK-side construction failure (e.g., the SDK
//     applies its own URL-scheme check redundantly).
//
// The ledger passes the returned client to
// did.DefaultVerifierRegistryWithRPC. The function never logs the
// endpoint URL — ledgers audit it via secret-management.
func BuildEthereumRPCClient(cfg EthereumRPCConfig) (sdkcryptosigs.EthereumRPCClient, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []sdkcryptosigs.HTTPRPCOption{
		sdkcryptosigs.WithTimeout(cfg.Timeout),
	}
	if cfg.AllowInsecureHTTP {
		opts = append(opts, sdkcryptosigs.WithAllowInsecureHTTP(true))
	}
	rpc, err := sdkcryptosigs.NewHTTPEthereumRPC(cfg.Endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("ethereum rpc client: %w", err)
	}
	return rpc, nil
}

// -------------------------------------------------------------------------------------------------
// 6) EIP-1271 (smart-contract-wallet) verification — Tier 2 (v1.37.0)
// -------------------------------------------------------------------------------------------------

// EIP1271Config drives PKHVerifierOptions construction. Disabled-by-
// default; when enabled the ledger admits smart-contract-wallet
// signatures (Safe, Argent, Coinbase Smart Wallet) at the did:pkh
// admission path.
//
// COST POSTURE — operators MUST read before enabling:
//
//   - At default-off the ledger makes zero Ethereum RPC calls.
//   - When enabled, each cold EIP-1271 verification costs ~60-120
//     Compute Units across K executors. At realistic court-system
//     volumes (100-200 TPS average, ~5% EIP-1271 share, K=2),
//     monthly cost on a Tier-1 provider is ~$50-300 with the SDK's
//     EIP1271BatchCache active.
//   - For sustained 1000+ TPS with high EIP-1271 share, consider
//     self-hosted RPC (~$200-500/month flat) over per-CU billing.
//   - The SDK requires K >= 2 by design (Byzantine-rogue protection
//     against any single RPC provider). Single-endpoint
//     deployments cannot enable EIP-1271; operators must supply
//     at least two independent executor endpoints.
type EIP1271Config struct {
	// Enabled is the master switch. False (the default) means EIP-1271
	// is disabled and PKHVerifierOptions is the zero value (EOA-only).
	Enabled bool

	// Executors are the K-of-N executor endpoints consulted per
	// verification. Required when Enabled is true; must be >= QuorumK
	// in length. Each endpoint is a separate JSON-RPC URL with its
	// own ID for receipt auditing.
	Executors []EIP1271Executor

	// QuorumK is the minimum executor agreement count. SDK requires
	// QuorumK >= 2. When unset, defaults to 2.
	QuorumK uint8

	// ChainID is the CAIP-2 / EIP-155 chain identifier (1 = mainnet,
	// 137 = polygon, etc.). Required when Enabled is true.
	ChainID uint64

	// BlockNumber is the static block number EIP-1271 verifications
	// pin to. Required when Enabled is true. v1.37.0 ships only the
	// StaticBlockProvider option; production deployments wanting
	// head-tracking will swap in a dynamic provider via a future
	// release (or wire one externally).
	BlockNumber uint64

	// BlockHash is the 32-byte hash of the block at BlockNumber.
	// Required when Enabled is true. Hex-encoded with optional
	// "0x" prefix in the env var; parsed at config-load time.
	BlockHash [32]byte
}

// EIP1271Executor is one (id, endpoint) tuple used to construct an
// ExecutorClient on the SDK's PKHVerifier.
type EIP1271Executor struct {
	// ID is the human-readable executor identifier embedded in the
	// per-executor receipt. Operators choose something stable per
	// provider (e.g., "alchemy", "infura", "self-hosted-1").
	ID string

	// Endpoint is the JSON-RPC URL. Same scheme rules as
	// LEDGER_ETH_RPC_ENDPOINT (https required unless ALLOW_HTTP
	// opt-in).
	Endpoint string
}

// ErrEIP1271RequiresExecutors is returned when LEDGER_EIP1271_ENABLED=true
// but fewer than two executor endpoints are configured. The SDK requires
// K >= 2 for EIP-1271 verification; single-endpoint configurations
// cannot satisfy this contract.
var ErrEIP1271RequiresExecutors = errors.New(
	"LEDGER_EIP1271_ENABLED=true requires LEDGER_EIP1271_EXECUTORS to list at least 2 endpoints (SDK requires K-of-N quorum, K >= 2)")

// ErrEIP1271RequiresChainID is returned when LEDGER_EIP1271_ENABLED=true
// but LEDGER_EIP1271_CHAIN_ID is unset or zero.
var ErrEIP1271RequiresChainID = errors.New(
	"LEDGER_EIP1271_ENABLED=true requires LEDGER_EIP1271_CHAIN_ID (e.g., 1 for Ethereum mainnet)")

// ErrEIP1271RequiresBlockPin is returned when LEDGER_EIP1271_ENABLED=true
// but LEDGER_EIP1271_BLOCK_NUMBER / LEDGER_EIP1271_BLOCK_HASH are unset.
// The SDK's PKHVerifierOptions requires a BlockProvider; for v1.37.0 Tier
// 2 first-ship we use StaticBlockProvider, which operators populate
// explicitly. A future release adds a dynamic head-pinning provider; for
// now operators supply a recent finalized block at deploy time. Suitable
// for staged rollout; production-grade deployments should track head with
// an external sidecar updating these env vars on a cadence.
var ErrEIP1271RequiresBlockPin = errors.New(
	"LEDGER_EIP1271_ENABLED=true requires LEDGER_EIP1271_BLOCK_NUMBER + LEDGER_EIP1271_BLOCK_HASH (StaticBlockProvider; see runbook)")

// LoadEIP1271Config reads the LEDGER_EIP1271_* env vars and returns
// the parsed config. Returns the zero EIP1271Config (Enabled=false)
// when LEDGER_EIP1271_ENABLED is unset or != "true".
//
// LEDGER_EIP1271_EXECUTORS format: comma-separated "id=endpoint"
// pairs, e.g.: "alchemy=https://eth-mainnet.alchemy.com/v2/KEY,infura=https://mainnet.infura.io/v3/KEY"
func LoadEIP1271Config() (EIP1271Config, error) {
	if os.Getenv("LEDGER_EIP1271_ENABLED") != "true" {
		return EIP1271Config{}, nil
	}
	executorsRaw := strings.TrimSpace(os.Getenv("LEDGER_EIP1271_EXECUTORS"))
	if executorsRaw == "" {
		return EIP1271Config{}, ErrEIP1271RequiresExecutors
	}
	parts := strings.Split(executorsRaw, ",")
	if len(parts) < 2 {
		return EIP1271Config{}, ErrEIP1271RequiresExecutors
	}
	executors := make([]EIP1271Executor, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		eqIdx := strings.IndexByte(p, '=')
		if eqIdx <= 0 || eqIdx == len(p)-1 {
			return EIP1271Config{}, fmt.Errorf(
				"LEDGER_EIP1271_EXECUTORS entry %q is not in 'id=endpoint' form", p)
		}
		executors = append(executors, EIP1271Executor{
			ID:       strings.TrimSpace(p[:eqIdx]),
			Endpoint: strings.TrimSpace(p[eqIdx+1:]),
		})
	}
	chainID := uint64(envIntOr("LEDGER_EIP1271_CHAIN_ID", 0))
	if chainID == 0 {
		return EIP1271Config{}, ErrEIP1271RequiresChainID
	}
	quorumK := uint8(envIntOr("LEDGER_EIP1271_QUORUM_K", 2))
	if quorumK < 2 {
		quorumK = 2
	}

	blockNumber := uint64(envIntOr("LEDGER_EIP1271_BLOCK_NUMBER", 0))
	blockHashHex := strings.TrimPrefix(
		strings.TrimSpace(os.Getenv("LEDGER_EIP1271_BLOCK_HASH")), "0x")
	if blockNumber == 0 || blockHashHex == "" {
		return EIP1271Config{}, ErrEIP1271RequiresBlockPin
	}
	if len(blockHashHex) != 64 {
		return EIP1271Config{}, fmt.Errorf(
			"LEDGER_EIP1271_BLOCK_HASH must be 32 bytes hex (64 chars), got %d", len(blockHashHex))
	}
	var blockHash [32]byte
	hashBytes, err := hex.DecodeString(blockHashHex)
	if err != nil {
		return EIP1271Config{}, fmt.Errorf(
			"LEDGER_EIP1271_BLOCK_HASH hex decode: %w", err)
	}
	copy(blockHash[:], hashBytes)

	return EIP1271Config{
		Enabled:     true,
		Executors:   executors,
		QuorumK:     quorumK,
		ChainID:     chainID,
		BlockNumber: blockNumber,
		BlockHash:   blockHash,
	}, nil
}

// BuildPKHVerifierOptions constructs the SDK's PKHVerifierOptions
// from a parsed EIP1271Config. Returns:
//   - sdkdid.PKHVerifierOptions{} (zero value) when cfg.Enabled is
//     false — semantically "EOA-only mode, no EIP-1271 verification".
//   - A fully populated PKHVerifierOptions when cfg.Enabled is true,
//     with each ExecutorClient constructed from its own
//     HTTPEthereumRPC client (independent per-executor transports
//     to avoid single-point-of-failure when one provider degrades).
//   - An error if any executor endpoint fails the SDK's URL/scheme
//     validation, or if BlockProvider construction fails.
//
// CALLERS: cmd/ledger/main.go after LoadEIP1271Config. The returned
// options are stored on deps.PKHVerifierOptions and consumed by
// wire.go when constructing did.DefaultVerifierRegistry.
func BuildPKHVerifierOptions(
	cfg EIP1271Config,
	timeout time.Duration,
	allowInsecureHTTP bool,
) (sdkdid.PKHVerifierOptions, error) {
	if !cfg.Enabled {
		return sdkdid.PKHVerifierOptions{}, nil
	}

	// Build one EthereumRPCClient per executor — independent
	// transports so a single provider outage doesn't cascade across
	// the quorum.
	executorClients := make([]sdkdid.ExecutorClient, 0, len(cfg.Executors))
	for _, ex := range cfg.Executors {
		opts := []sdkcryptosigs.HTTPRPCOption{
			sdkcryptosigs.WithTimeout(timeout),
		}
		if allowInsecureHTTP {
			opts = append(opts, sdkcryptosigs.WithAllowInsecureHTTP(true))
		}
		rpc, err := sdkcryptosigs.NewHTTPEthereumRPC(ex.Endpoint, opts...)
		if err != nil {
			return sdkdid.PKHVerifierOptions{}, fmt.Errorf(
				"build executor %q rpc: %w", ex.ID, err)
		}
		executorClients = append(executorClients, sdkdid.ExecutorClient{
			ID:  ex.ID,
			RPC: rpc,
		})
	}

	// v1.37.0 Tier 2: StaticBlockProvider only. The SDK does not
	// yet ship a head-pinning provider, and a production-grade one
	// requires reorg-safe confirmation-depth handling. For first-
	// ship the operator supplies a recent finalized block at deploy
	// time (LEDGER_EIP1271_BLOCK_NUMBER + LEDGER_EIP1271_BLOCK_HASH).
	// Staged-rollout deployments can update the block pin out-of-band
	// via env var refresh + binary restart; production-grade dynamic
	// pinning lands in a follow-up release.
	blockProvider := sdkdid.StaticBlockProvider{
		BlockNumber: cfg.BlockNumber,
		BlockHash:   cfg.BlockHash,
	}

	return sdkdid.PKHVerifierOptions{
		ChainID:       cfg.ChainID,
		Executors:     executorClients,
		QuorumK:       cfg.QuorumK,
		BlockProvider: blockProvider,
	}, nil
}
