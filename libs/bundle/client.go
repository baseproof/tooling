/*
FILE PATH: libs/bundle/client.go

HTTP fetch from /v1/bundle/{seq} with mirror failover. The
client's only job is to MOVE BYTES — it does not verify; the
caller passes the returned *bundle.Bundle to VerifyBundle for
that.

# WIRE SHAPE

The ledger's GET /v1/bundle/{seq}?smt_key=hex returns the
JCS-canonical bytes of the SDK's bundle.Bundle. This client:

 1. GETs the bundle from baseURL+/v1/bundle/{seq}?smt_key=<hex>
 2. LimitReads the body to MaxBundleBytes (DoS guard).
 3. Decodes via sdkbundle.Decode (strict — DisallowUnknownFields).
 4. Returns *sdkbundle.Bundle for the caller to verify.

# MIRROR FAILOVER

Production bundle fetches go through a MirrorEndpointList — an
ordered list of (URL, source) tuples. The client tries each in
order; the first that returns a syntactically valid bundle wins.

  - Transport errors (timeout, connection refused) → fail over
    to the next mirror.
  - 4xx errors (404, 403) → fail over (the bundle might exist
    on another mirror but be missing here).
  - Decode errors (malformed JSON, unknown fields) → fail over
    (a malformed bundle from one mirror does not abort the walk).
  - 5xx errors → fail over.

A mirror that returns a syntactically valid bundle is TRUSTED to
have served the right bytes; the SDK's VerifyBundle is what
catches a malicious mirror serving a forged bundle. The fetcher
is INTENTIONALLY lax — it returns SOMETHING and lets the verifier
decide if it's authentic.

# DoS GUARDS

  - MaxBundleBytes caps each response body. The SDK doesn't
    define a maximum bundle size; this client picks 8 MiB as
    "generous for any single-entry bundle, hostile if exceeded"
    (a typical bundle is ~10 KB; 8 MiB would carry ~10K SMT
    proof siblings — far beyond any real tree depth).
  - HTTPClient timeout caps each per-mirror request (caller
    supplies the client; production wires the binary's outbound
    client with retry middleware).

# WHY NOT IN cmd/baseproof/ DIRECTLY

The CLI doesn't exist yet (cmd/baseproof/ is future Part-IV scope).
This package is the future-CLI-and-current-auditor SHARED layer.
A new audit job in services/auditor that fetches a peer's bundle
for spot-check verification consumes the same client; drift is
impossible.
*/
package bundle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
)

// MaxBundleBytes caps the HTTP response body when fetching a
// bundle. A typical bundle is ~10 KB; 8 MiB is hostile.
const MaxBundleBytes = 8 << 20

// ErrAllMirrorsFailed is returned by FetchBundleFromMirrors when
// every mirror in the supplied list failed (transport / 4xx /
// 5xx / decode). The caller's error wraps each mirror's specific
// failure for diagnostic logging.
var ErrAllMirrorsFailed = errors.New("bundle/client: all mirrors failed")

// ErrEmptyMirrorList is returned when FetchBundleFromMirrors is
// called with no mirrors. The caller is expected to supply at
// least one — the function does not fall back to a default URL.
var ErrEmptyMirrorList = errors.New("bundle/client: empty mirror list")

// ErrMissingSmtKey is returned when a fetch is attempted without
// a 32-byte SMT key (the ledger's /v1/bundle/{seq} endpoint
// requires smt_key=hex; the SDK's VerifyBundle requires a
// presence proof, which only exists at a specific key).
var ErrMissingSmtKey = errors.New("bundle/client: smt_key required (32 bytes)")

// MirrorEndpoint identifies one bundle-serving location. URL is
// the base URL (no trailing slash); Source is the operator DID or
// label identifying the mirror — used for diagnostic logging and
// to attribute mirror behaviour in operator alerts.
//
// Matches the wire shape of log/discover.MirrorEntry plus a
// pre-resolved URL field; production wiring projects the
// discover.MirrorManifest into this slice once at boot.
type MirrorEndpoint struct {
	URL    string
	Source string
}

// FetchBundleFromMirrors GETs /v1/bundle/{seq}?smt_key=<hex> from
// each mirror in order, returning the first successfully-decoded
// bundle. The function performs NO cryptographic verification;
// the caller passes the returned *Bundle to VerifyBundle.
//
// Behaviour:
//
//   - Empty mirror list → ErrEmptyMirrorList.
//   - smtKey [32]byte == zero → ErrMissingSmtKey (the ledger's
//     endpoint requires a 32-byte key, and a zero key is almost
//     certainly a caller bug rather than a deliberate query).
//   - Each mirror tried in order; the first decoded success wins.
//   - Per-mirror failures collected and joined into a single
//     error via errors.Join for diagnostic surfacing.
//   - ctx cancellation aborts the walk (returns ctx.Err()).
//
// client supplies the *http.Client. Production wires the binary's
// outbound client (mTLS-aware, retry-middleware'd via
// libs/outbound). Tests can wire a plain client.
func FetchBundleFromMirrors(
	ctx context.Context,
	client *http.Client,
	mirrors []MirrorEndpoint,
	seq uint64,
	smtKey [32]byte,
) (*sdkbundle.Bundle, error) {
	if client == nil {
		return nil, fmt.Errorf("bundle/client: nil http.Client")
	}
	if len(mirrors) == 0 {
		return nil, ErrEmptyMirrorList
	}
	if smtKey == ([32]byte{}) {
		return nil, ErrMissingSmtKey
	}

	var perMirrorErrs []error
	for _, m := range mirrors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		bundle, err := fetchOneMirror(ctx, client, m, seq, smtKey)
		if err == nil {
			return bundle, nil
		}
		perMirrorErrs = append(perMirrorErrs,
			fmt.Errorf("mirror %q (%s): %w", m.URL, m.Source, err))
	}
	return nil, errors.Join(append([]error{ErrAllMirrorsFailed}, perMirrorErrs...)...)
}

// FetchBundle is the single-URL convenience over
// FetchBundleFromMirrors. Useful when the caller has already
// resolved to one URL (e.g., a direct cap-grant against a known
// ledger) and doesn't need the mirror-failover semantics.
func FetchBundle(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	seq uint64,
	smtKey [32]byte,
) (*sdkbundle.Bundle, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("bundle/client: empty baseURL")
	}
	return FetchBundleFromMirrors(ctx, client,
		[]MirrorEndpoint{{URL: baseURL, Source: "direct"}}, seq, smtKey)
}

// fetchOneMirror is the per-mirror fetch + decode path. Returns
// the decoded bundle or a wrapped error describing whichever
// stage failed (transport, status, body-read, decode).
func fetchOneMirror(
	ctx context.Context,
	client *http.Client,
	m MirrorEndpoint,
	seq uint64,
	smtKey [32]byte,
) (*sdkbundle.Bundle, error) {
	url := m.URL + "/v1/bundle/" + strconv.FormatUint(seq, 10) +
		"?smt_key=" + hex.EncodeToString(smtKey[:])

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", url, err)
	}
	if len(body) > MaxBundleBytes {
		return nil, fmt.Errorf("body from %s exceeds %d bytes (DoS guard)",
			url, MaxBundleBytes)
	}

	bundle, err := sdkbundle.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("decode bundle from %s: %w", url, err)
	}
	return bundle, nil
}
