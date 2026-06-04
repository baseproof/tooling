/*
FILE PATH: libs/auditing/didregistry/registry.go

DESCRIPTION:

	NewStandard returns the canonical baseproof DID VerifierRegistry
	used by every tools-side consumer (auditor, gossip ingest
	pipelines, cross-log verification). It registers did:key, did:web,
	AND did:pkh — so the registry verifies the FULL entry-signature
	algorithm space the SDK supports, with no method silently
	unhandled:

	  - did:key / did:web → ECDSA-secp256k1, Ed25519, ML-DSA-65,
	    ML-DSA-87, SLH-DSA-128s (the v1.37 PQ dispatch).
	  - did:pkh → EIP-191, EIP-712 (EOA, pure-CPU) always; EIP-1271
	    (smart-contract wallets) when Config.PKH carries RPC executors.

	A method that is NOT registered is a SILENT failure: the registry
	rejects the event with "method not registered: <m>", which the
	caller cannot distinguish from an invalid signature — so an
	otherwise-valid did:pkh (Ethereum court key) or PQ did:web event
	is dropped as if forged. Registering every method the SDK can
	verify is what makes "support all algorithms / do not fail
	silently" true at this seam.

CONFIG SHAPE

	Config carries what's needed to construct all three verifiers:
	an outbound *http.Client (for did:web resolution), an optional
	cache TTL, and an optional PKHVerifierOptions. The HTTP client is
	REQUIRED — same fail-closed posture the v1.34 SDK adopted. nil
	panics at boot.

	did:pkh EIP-1271 is OPT-IN: the zero Config.PKH is EOA-only, and
	an inbound EIP-1271 signature then surfaces did.ErrAlgorithmNotSupported
	LOUDLY (a specific, actionable error — not a silent drop). A
	deployment with Ethereum RPC sets Config.PKH (ChainID + Executors
	+ QuorumK + BlockProvider) to enable on-chain EIP-1271 verification.
*/
package didregistry

import (
	"fmt"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/did"
)

// DefaultCacheTTL is the cache TTL applied to the did:web
// resolver when Config.CacheTTL is zero. 5 minutes is the SDK
// did/CachingResolver convention used elsewhere in tools.
const DefaultCacheTTL = 5 * time.Minute

// Config configures NewStandard.
type Config struct {
	// HTTPClient is the outbound transport for did:web resolution.
	// REQUIRED. Production wiring passes the boot-hoisted mTLS
	// client (e.g., outbound.HoistFromEnv result, or
	// sdklog.DefaultClient(timeout, tlsCfg)). nil panics at boot —
	// the v1.34 fail-closed contract applies here.
	HTTPClient *http.Client

	// CacheTTL bounds did:web Document caching. Zero defaults to
	// DefaultCacheTTL. Set explicitly when the deployment has a
	// known rotation cadence (e.g., 30s in test, 1h in prod).
	CacheTTL time.Duration

	// PKH configures the did:pkh verifier. The ZERO value is
	// EOA-only mode: EIP-191 + EIP-712 verify (pure CPU, no RPC),
	// and EIP-1271 surfaces did.ErrAlgorithmNotSupported LOUDLY
	// rather than being silently unverifiable. Set ChainID +
	// Executors + QuorumK + BlockProvider to enable on-chain
	// EIP-1271 (smart-contract-wallet) verification.
	PKH did.PKHVerifierOptions
}

// NewStandard returns the canonical *did.VerifierRegistry covering the
// full entry-signature algorithm space: did:key + did:web (ECDSA,
// Ed25519, ML-DSA-65/87, SLH-DSA-128s) and did:pkh (EIP-191/712 always;
// EIP-1271 when Config.PKH carries RPC executors). No verifiable method
// is left unregistered — an unsupported algorithm fails with a specific
// error, never a silent drop.
//
// Panics on nil cfg.HTTPClient (boot-time invariant; matches the
// v1.34 SDK constructor posture).
func NewStandard(cfg Config) (*did.VerifierRegistry, error) {
	if cfg.HTTPClient == nil {
		panic("auditing/didregistry: Config.HTTPClient required " +
			"(plaintext acceptable for dev; SDK v1.34+ rejects nil)")
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}

	// did:web — caching resolver around the SDK's HTTP-backed
	// did:web fetcher. The cache TTL bounds DID Document staleness;
	// rotations require waiting up to TTL before a new key is
	// observed.
	webResolver, err := did.NewWebDIDResolver(did.WebDIDResolverConfig{
		Client: cfg.HTTPClient,
	})
	if err != nil {
		return nil, fmt.Errorf("auditing/didregistry: web resolver: %w", err)
	}
	cachedResolver := did.NewCachingResolver(webResolver, ttl)

	// did:pkh — EOA (EIP-191/712) by default; full EIP-1271 when
	// cfg.PKH carries executors. The zero PKHVerifierOptions cannot be
	// misconfigured (EOA-only); EIP-1271 then fails loud.
	pkh, err := did.NewPKHVerifier(cfg.PKH)
	if err != nil {
		return nil, fmt.Errorf("auditing/didregistry: pkh verifier: %w", err)
	}

	registry := did.NewVerifierRegistry()
	if err := registry.Register("key", did.NewKeyVerifier()); err != nil {
		return nil, fmt.Errorf("auditing/didregistry: register did:key: %w", err)
	}
	if err := registry.Register("web", did.NewWebVerifier(cachedResolver)); err != nil {
		return nil, fmt.Errorf("auditing/didregistry: register did:web: %w", err)
	}
	if err := registry.Register("pkh", pkh); err != nil {
		return nil, fmt.Errorf("auditing/didregistry: register did:pkh: %w", err)
	}
	return registry, nil
}
