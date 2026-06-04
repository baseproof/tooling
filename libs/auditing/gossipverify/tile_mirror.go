// FILE PATH: libs/auditing/gossipverify/tile_mirror.go
//
// DESCRIPTION:
//
//	HTTPTileMirrors resolves a source-log DID to a Static-CT tile fetcher
//	pointed at that log's tile mirror, satisfying TileFetcherSource for the
//	gossip verifier's ClassMerkle (cross-log inclusion) path.
//
//	ZERO-TRUST NOTE: a tile mirror need not be trusted. A cross-log inclusion
//	proof is RFC 6962-verified against the TRUSTED source head's RootHash (from
//	the TrustedHeadStore, advanced only by verified CosignedTreeHeads); a mirror
//	serving wrong tiles yields a proof that fails the root check. The mirror is
//	a data source; the head is the trust anchor. Mirrors are still operator-
//	pinned (allowlist) to bound where the binary issues fetches.
//
//	v1.27.x outbound-client contract (v1.29.1): NewHTTPTileMirrors REQUIRES a
//	non-nil *http.Client. The legacy "nil ⇒ http.DefaultClient" path (inherited
//	from the upstream tessera fetcher) is gone — silently falling back to a
//	plaintext default client at a libs/ boundary is exactly the v1.27.x anti-
//	pattern. Callers MUST thread the binary's hoisted outbound client (see
//	libs/outbound.HoistFromEnv). The detector catches the regression: every
//	error path wraps ErrTileMirror so callers can errors.Is against one anchor.
package gossipverify

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	tessera "github.com/transparency-dev/tessera/client"
)

// ErrTileMirror is the sentinel wrapped by every NewHTTPTileMirrors error.
// Callers use errors.Is(err, ErrTileMirror) to recognize tile-mirror
// construction failures regardless of the specific failure mode (missing
// client, empty DID, empty URL, unparseable URL, fetcher-construction
// failure).
var ErrTileMirror = errors.New("verification/tile_mirror")

// newTileFetcher is the seam through which NewHTTPTileMirrors invokes
// tessera.NewHTTPFetcher. The upstream constructor's current implementation
// has no error path (it just normalizes a trailing slash), but its declared
// signature reserves the right to fail. We retain the error branch in
// NewHTTPTileMirrors as defensive against upstream evolution and override
// this var from tile_mirror_test.go to drive that branch's coverage.
//
// Production code never assigns to this var; the override is test-only.
var newTileFetcher = tessera.NewHTTPFetcher

// HTTPTileMirrors maps source-log DID → Static-CT tile fetcher. Immutable after
// construction; safe for concurrent use.
type HTTPTileMirrors struct {
	fetchers map[string]tessera.TileFetcherFunc
}

// NewHTTPTileMirrors builds a resolver from a source-log-DID → tile-root-URL
// map. Each URL is wrapped in the SDK's tessera HTTPFetcher; its ReadTile method
// is the TileFetcherFunc. An empty map yields a resolver that resolves nothing
// (every merkle finding then fails-closed).
//
// hc is REQUIRED: thread the binary's hoisted outbound *http.Client (see
// libs/outbound.HoistFromEnv or libs/clienttls.BuildFromEnv) so cross-log tile
// fetches share the operator-chosen mTLS posture. A nil hc is a startup-fatal
// error — upstream tessera.NewHTTPFetcher silently falls back to
// http.DefaultClient on nil, which is exactly the silent-plaintext anti-pattern
// the v1.27.x outbound-client contract removes. We validate at the libs/
// boundary so the SDK's leniency cannot leak into our consumers.
//
// Every error wraps ErrTileMirror; callers can errors.Is against it.
func NewHTTPTileMirrors(mirrors map[string]string, hc *http.Client) (*HTTPTileMirrors, error) {
	if hc == nil {
		return nil, fmt.Errorf(
			"%w: nil *http.Client (thread the binary's hoisted outbound client; "+
				"see libs/outbound.HoistFromEnv or libs/clienttls.BuildFromEnv)",
			ErrTileMirror)
	}
	out := make(map[string]tessera.TileFetcherFunc, len(mirrors))
	for logDID, rawURL := range mirrors {
		if logDID == "" {
			return nil, fmt.Errorf("%w: empty log DID", ErrTileMirror)
		}
		if rawURL == "" {
			return nil, fmt.Errorf("%w: empty tile URL for %q", ErrTileMirror, logDID)
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("%w: parse URL for %q: %v", ErrTileMirror, logDID, err)
		}
		f, err := newTileFetcher(u, hc)
		if err != nil {
			return nil, fmt.Errorf("%w: fetcher for %q: %v", ErrTileMirror, logDID, err)
		}
		out[logDID] = f.ReadTile
	}
	return &HTTPTileMirrors{fetchers: out}, nil
}

// FetcherFor returns the tile fetcher for sourceLogDID, or (nil, false) if no
// mirror is configured for it.
func (m *HTTPTileMirrors) FetcherFor(sourceLogDID string) (tessera.TileFetcherFunc, bool) {
	f, ok := m.fetchers[sourceLogDID]
	return f, ok
}
