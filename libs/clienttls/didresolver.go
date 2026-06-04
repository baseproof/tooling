/*
FILE PATH: libs/clienttls/didresolver.go

T10 — caching, mTLS-pinned DIDResolver wrapper for plugging into
*discover.DefaultAuthoritativeResolver.DIDFallback.

# WHY THIS EXISTS

Every consumer that wires the v1.32.0 DefaultAuthoritativeResolver
needs a `did.DIDResolver` to populate the DIDFallback field for
advisory cross-check (FallbackAdvisory policy) or resolution
fallthrough (FallbackPermitted policy). Without a centralised
constructor, each consumer's main.go hand-wires:

	cachedResolver := did.NewCachingResolver(
	    did.NewWebDIDResolver(did.WebDIDResolverConfig{Client: mTLSClient}),
	    5*time.Minute,
	)

The hand-wiring has three failure modes that have already
happened in this codebase: forgetting the caching wrapper
(every Resolve hits the network), forgetting the mTLS client
(plaintext did:web fetches), or passing a nil client (constructor
returns ErrInvalidConfig at runtime).

This file is the one-line correct wiring:

	resolver, err := clienttls.BuildDIDResolverWithMTLS(out.Client, 5*time.Minute)

The resolver returned is composition-ready for
DefaultAuthoritativeResolver.DIDFallback.

# RELATIONSHIP TO libs/outbound

libs/outbound.HoistFromEnv builds the *http.Client at boot from
the binary's env-driven mTLS material. The same client is the
correct input here — every did:web fetch goes through the same
mTLS posture as gossip pulls, horizon audits, etc. ONE outbound
posture per binary.

# CACHE TTL

Default 5 minutes when ttl <= 0. did:web documents change on
human/operational timescales (rotation of a service endpoint,
addition of a verification method); 5 minutes is the operating
sweet spot the SDK's CachingResolver uses internally.

Callers can override with a longer TTL for high-volume
deployments where the did:web origin is rate-limited, or a
shorter TTL for environments where DID document drift is
expected at high cadence.
*/
package clienttls

import (
	"fmt"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/did"
)

// DefaultDIDResolverCacheTTL is the cache lifetime applied when
// the caller passes ttl <= 0 to BuildDIDResolverWithMTLS. Matches
// the SDK's CachingResolver internal default (see
// did/resolver.go:NewCachingResolver).
const DefaultDIDResolverCacheTTL = 5 * time.Minute

// BuildDIDResolverWithMTLS returns a caching, mTLS-pinned
// did.DIDResolver ready for plugging into
// *discover.DefaultAuthoritativeResolver.DIDFallback.
//
// client MUST be the binary's hoisted outbound *http.Client (built
// once at boot via libs/outbound.HoistFromEnv). A nil client is
// rejected — a plaintext did:web fallback is the exact failure
// mode the v1.32.0 advisory cross-check exists to detect; building
// it ourselves with a nil client would silently undermine that.
//
// cacheTTL governs how long a resolved DID document is reused
// before a fresh fetch. cacheTTL <= 0 defaults to
// DefaultDIDResolverCacheTTL.
//
// Returns ErrInvalidClient when client is nil; the SDK's
// did.WebDIDResolverConfig validation error otherwise.
func BuildDIDResolverWithMTLS(client *http.Client, cacheTTL time.Duration) (did.DIDResolver, error) {
	if client == nil {
		return nil, fmt.Errorf("clienttls: BuildDIDResolverWithMTLS: nil *http.Client " +
			"(thread the binary's hoisted outbound client; build it via libs/outbound.HoistFromEnv " +
			"— a plaintext fallback here undermines the v1.32.0 advisory cross-check posture)")
	}
	if cacheTTL <= 0 {
		cacheTTL = DefaultDIDResolverCacheTTL
	}
	webResolver, err := did.NewWebDIDResolver(did.WebDIDResolverConfig{
		Client: client,
	})
	if err != nil {
		return nil, fmt.Errorf("clienttls: web did resolver: %w", err)
	}
	return did.NewCachingResolver(webResolver, cacheTTL), nil
}
