/*
FILE PATH: anchor/resolved_submit.go

v1.32.0 SDK adoption — L5 backdoor closure: parent admission URL
resolved via the on-log FederationGraph instead of static config.

# THE BACKDOOR THIS CLOSES

Pre-v1.32.0 the publisher's parent-target flow (Part II.9
upward anchoring) consumed `cfg.ParentAdmissionURL string` from
LEDGER_PARENT_ADMISSION_URL — an operator-edit-and-reload away
from the same silent URL substitution attack L1 closed for
within-log witness discovery. Cross-log instead of within-log;
identical attack shape.

# THE WIRE

`SubmitToResolvedHTTPEndpoint` composes the existing
`SubmitToHTTPEndpoint` with an injected resolver function. At
each anchor publish:

 1. resolver(ctx, peerLogDID) returns the parent's current
    authoritative admission URL — from an on-log FederationGraph
    entry walked through the SDK's
    *discover.DefaultAuthoritativeResolver.ResolvePeer (which
    this matches via the URLResolver function signature).
 2. If resolver returns a non-empty URL: use it.
 3. If resolver returns ErrPeerUnknown or empty: fall through to
    fallbackURL (the legacy cfg.ParentAdmissionURL canary).
 4. Empty fallbackURL + resolver miss → publish errors and the
    publisher retries next tick.

URLs are NOT cached at this layer — every publish does a fresh
resolve. The cost is negligible (in-memory dispatch over pre-
fetched walker records) and the freshness floor matches the
cosigned head's advance cadence.
*/
package anchor

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/core/envelope"

	"github.com/baseproof/tooling/services/ledger/observability"
)

// PeerAdmissionURLResolver returns the parent log's current
// admission URL. Typically constructed in cmd/ledger/boot/wire
// as a thin closure over
// *discover.DefaultAuthoritativeResolver.ResolvePeer:
//
//	resolver := func(ctx context.Context, peerLogDID string) (string, error) {
//	    res, err := authResolver.ResolvePeer(ctx, peerLogDID, types.LogPosition{})
//	    if err != nil { return "", err }
//	    return res.URL, nil
//	}
//
// Returning an empty URL OR any error MUST cause the caller to
// fall through to the static fallback URL (LEDGER_PARENT_ADMISSION_URL
// canary) — the resolver is the authoritative source but the
// fallback preserves operability during the bootstrap window.
type PeerAdmissionURLResolver func(ctx context.Context, peerLogDID string) (string, error)

// SubmitToResolvedHTTPEndpoint composes a submit function that
// resolves the parent admission URL through PeerAdmissionURLResolver
// at each publish, falling back to fallbackURL when the resolver
// returns empty or errors.
//
// client may be nil — when nil, the helper builds an SDK-default
// HTTP client (sdklog.DefaultClient with 30s timeout). Production
// callers should supply an mTLS-aware client when the parent log
// enforces mTLS on its TLS listener.
//
// peerLogDID is the destination parent log's DID; used both for
// the resolver call and (when the resolved URL is logged) for
// audit observability.
//
// fallbackURL is the legacy LEDGER_PARENT_ADMISSION_URL — used
// when resolver is nil OR returns ("", err) / ("", nil). Empty
// fallbackURL + resolver miss → the returned function errors at
// call time (the publisher then logs + retries next tick).
//
// logger receives a per-publish slog.Info event tagged with the
// source ("on_log_resolver" or "config_canary_fallback") so
// operators can see — across the 15-network footprint — which
// publishes are still on the canary path.
func SubmitToResolvedHTTPEndpoint(
	client *http.Client,
	resolver PeerAdmissionURLResolver,
	peerLogDID string,
	fallbackURL string,
	logger *slog.Logger,
) func(entry *envelope.Entry) error {
	// V1.34 SDK CONTRACT — NO SILENT FALLBACK. client is REQUIRED;
	// nil at construction PANICS rather than silently falling back to
	// a plaintext default. See SubmitToHTTPEndpoint (publisher.go)
	// for the rationale — this function composes that one and inherits
	// the same security-posture contract.
	if client == nil {
		panic("anchor/SubmitToResolvedHTTPEndpoint: client required (the v1.34 SDK contract is no silent fallback to a plaintext default; wire d.OutboundHTTPClient at boot or pass an explicit *http.Client in tests)")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if peerLogDID == "" {
		// Programming error: a parent-target flow requires the
		// destination DID at construction time. Returning a
		// constant error at every call is the right failure mode
		// — the publisher's parent ticker will log + retry.
		return func(*envelope.Entry) error {
			return fmt.Errorf("anchor/SubmitToResolvedHTTPEndpoint: peerLogDID required")
		}
	}
	return func(entry *envelope.Entry) error {
		url, source := resolveEffectiveParentURL(resolver, peerLogDID, fallbackURL, logger)
		// Tier E observability — per-publish source signal. Operators
		// watching {source="config_canary_fallback", surface="parent"}
		// see exactly when the LEDGER_PARENT_ADMISSION_URL canary is
		// still in use across the federation footprint.
		observability.EndpointSource(source, "parent")
		if url == "" {
			return fmt.Errorf("anchor/SubmitToResolvedHTTPEndpoint: no admission URL for %s "+
				"(resolver returned empty AND fallback URL unset)", peerLogDID)
		}
		// Reuse the existing SubmitToHTTPEndpoint contract — same
		// envelope.Serialize → POST → 202 check. We construct it
		// per-call so the URL update is honored every publish; the
		// closure capture cost is negligible.
		submit := SubmitToHTTPEndpoint(client, url)
		if err := submit(entry); err != nil {
			logger.Warn("anchor.parent_target.publish_failed",
				"peer_log_did", peerLogDID,
				"url", url,
				"source", source,
				"error", err.Error(),
			)
			return err
		}
		logger.Info("anchor.parent_target.published",
			"peer_log_did", peerLogDID,
			"url", url,
			"source", source,
		)
		return nil
	}
}

// resolveEffectiveParentURL implements the v1.32.0 precedence
// order: on-log resolver wins; config-driven URL is the canary
// fallback. Returns (url, source-label).
//
// A resolver-call error or empty URL is NOT fatal: the publisher
// falls through to fallbackURL and logs a warn so operators can
// see the canary path active. Errors are NOT surfaced to the
// caller — the publish either succeeds against the on-log URL
// or the fallback URL or fails downstream with a structured
// error from SubmitToHTTPEndpoint.
func resolveEffectiveParentURL(
	resolver PeerAdmissionURLResolver,
	peerLogDID string,
	fallbackURL string,
	logger *slog.Logger,
) (string, string) {
	if resolver != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		url, err := resolver(ctx, peerLogDID)
		switch {
		case err != nil:
			logger.Warn("anchor/resolved_submit: on-log resolver failed; using LEDGER_PARENT_ADMISSION_URL canary fallback",
				"peer_log_did", peerLogDID,
				"error", err.Error(),
			)
		case url != "":
			return url, "on_log_resolver"
		default:
			logger.Warn("anchor/resolved_submit: on-log resolver returned empty; using LEDGER_PARENT_ADMISSION_URL canary fallback",
				"peer_log_did", peerLogDID,
			)
		}
	}
	if fallbackURL == "" {
		return "", "none"
	}
	return fallbackURL, "config_canary_fallback"
}
