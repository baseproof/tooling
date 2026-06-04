/*
FILE PATH: libs/clitools/content_store.go

Artifact-store ContentStore constructors for the tool binaries
(court-tools, provider-tools, future networks). Mirrors the
NewLedgerClient / NewMTLSLedgerClient / NewExchangeClient pattern in
this package — one optional-mTLS constructor pair per upstream
service, configured from Config + env vars.

Without these helpers, every tool binary that talks to the artifact
store ends up building a raw &http.Client{Timeout: 30*time.Second}
and constructing storage.NewHTTPContentStore inline — which is the
exact "silent plaintext" anti-pattern v1.27.x removed at the SDK
level. The court-tools and provider-tools main.go files both did
exactly this before this file existed (see the JN audit, Gap 9).

Single entry point: NewContentStore(cfg) chooses MTLS vs plaintext
based on cfg.ArtifactStoreMTLSConfigured(). Half-config (cert XOR
key) is startup-fatal via reliability.NewMTLSClient's error path.
*/
package clitools

import (
	"fmt"
	"net/http"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/libs/httpmw/reliability"
)

// defaultArtifactStoreTimeout caps every artifact-store round-trip.
// Pushes (entry encryption + upload) and fetches (encrypted body
// download) are larger than typical RPC; the default is wider than
// LedgerClient's 15s.
const defaultArtifactStoreTimeout = 30 * time.Second

// NewContentStore returns the artifact-store ContentStore configured for
// cfg. Single entry point — branches internally on
// cfg.ArtifactStoreMTLSConfigured() so callers don't have to repeat the
// MTLSConfigured / NewMTLS / New pattern at every call site. Returns
// (nil, error) on either:
//   - storage construction failure (BaseURL empty after cfg defaults)
//   - mTLS material load failure when MTLSConfigured() is true
//
// Callers MUST surface the error — the legacy plaintext-fallback path
// is gone. v1.27.x: no silent demotion.
func NewContentStore(cfg Config) (storage.ContentStore, error) {
	if cfg.ArtifactStoreMTLSConfigured() {
		return NewMTLSContentStore(cfg)
	}
	return storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
		BaseURL: cfg.ArtifactStoreURL,
		Client:  sdklog.DefaultClient(defaultArtifactStoreTimeout, nil),
	})
}

// NewMTLSContentStore is the production constructor: same SDK
// HTTPContentStore but with a client certificate presented on every
// connection so the artifact store can identify the caller
// cryptographically.
//
// Returns (nil, err) on any TLS-material failure (missing cert/key,
// unreadable CA, mismatched keypair). Callers MUST fail startup; this
// function refuses to silently fall back to plaintext — the v1.27.x
// "no silent demotion" rule applied at the helper layer.
func NewMTLSContentStore(cfg Config) (storage.ContentStore, error) {
	client, err := reliability.NewMTLSClient(
		reliability.ClientConfig{Timeout: defaultArtifactStoreTimeout},
		cfg.ArtifactStoreTLS(),
	)
	if err != nil {
		return nil, fmt.Errorf("clitools: artifact-store mTLS client: %w", err)
	}
	return storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
		BaseURL: cfg.ArtifactStoreURL,
		Client:  client,
	})
}

// NewContentStoreWithClient is the escape hatch for callers that already
// have a fully-constructed *http.Client (typically the binary's hoisted
// outbound client built via clienttls.BuildFromEnv at boot). Bypasses the
// Config-driven branching above. Returns the standard storage.HTTPContentStore
// construction error on failure.
func NewContentStoreWithClient(cfg Config, client *http.Client) (storage.ContentStore, error) {
	if client == nil {
		return nil, fmt.Errorf("clitools: NewContentStoreWithClient: nil client (build via clienttls.BuildFromEnv or pass NewContentStore(cfg))")
	}
	return storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
		BaseURL: cfg.ArtifactStoreURL,
		Client:  client,
	})
}
