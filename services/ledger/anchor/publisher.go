/*
FILE PATH: anchor/publisher.go

Periodic anchor entry publisher. Creates commentary entries containing tree
head references, submitting them to the parent log's admission API.
Anchors are standard entries — no special handling.

KEY ARCHITECTURAL DECISIONS:
  - Commentary entries: Target_Root=null, Authority_Path=null → zero SMT impact.
  - Destination-bound: anchor entries are published to THIS log,
    so Destination = LogDID. NewUnsignedEntry rejects empty destination at
    write time.
  - Domain Payload: source_log_did + the source log's FULL cosigned tree
    head, embedded as a gossip.WireCosignedTreeHeadBody (root_hash,
    smt_root, receipt_root, tree_size + the K-of-N witness cosignatures).
    The anchor is therefore a self-proving, offline-verifiable artifact:
    a reader reconstructs it with findings.CosignedTreeHeadFromWire and
    checks the quorum via Verify(set) without any callback to the source
    log. tree_head_ref (SHA-256 of the fetched body) is retained as a
    provenance witness, plus a timestamp.
  - Submits to the local ledger's admission pipeline via submitFn.
  - Configurable interval: default 1 hour.

SDK ALIGNMENT:
  - envelope.NewEntry(header, payload, signatures)        — fully signed
  - envelope.NewUnsignedEntry(header, payload)            — sign-then-attach
    The publisher's flow is "construct, then submit through admission",
    so it uses NewUnsignedEntry. Whatever path actually signs the
    commentary (ledger's admission pipeline, SubmitInProcess, or a future
    ledger-as-dealer signing surface) is responsible for populating
    entry.Signatures before envelope.Serialize is invoked. An entry
    without signatures fails entry.Validate() at admission, which is
    the correct failure mode for a misconfigured deployment.
*/
package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
)

// PublisherConfig configures the anchor publisher.
type PublisherConfig struct {
	LedgerDID string
	LogDID    string // destination-binding for self-published anchors.
	// NetworkID binds the anchored head's tree_head_ref digest to this network
	// (cosign.TreeHeadDigest). Required — a zero NetworkID is rejected.
	NetworkID     cosign.NetworkID
	Interval      time.Duration
	AnchorSources []AnchorSource

	// HTTPClient is the outbound client the publisher uses for the
	// peer-log /v1/tree/head fetch. Optional — when nil, the
	// constructor builds an SDK-default client (server-verify-only
	// TLS, Retry-After middleware). Set to an mTLS client (typically
	// composed from internal/clienttls) when the peer log enforces
	// mTLS on its TLS listener.
	HTTPClient *http.Client

	// ParentLogDID, ParentAdmissionURL, ParentAnchorInterval +
	// ParentSubmitFn together configure the PART II.9 parent-target
	// flow — periodic anchoring of THIS log's tree head onto a
	// PARENT log's admission API. Distinct from AnchorSources
	// (which anchors OTHER logs onto THIS one); this is the
	// federation-upward direction (plan §I.20a).
	//
	// All four fields must be set together OR all empty. Mixed
	// state (e.g., URL set, ParentSubmitFn nil) is a wiring bug —
	// NewPublisher returns nil + logs; Run no-ops the parent ticker.
	//
	// ParentLogDID is the parent log's DID — used as the anchor
	// entry's Destination so admission on the parent's side
	// accepts it.
	//
	// ParentAdmissionURL is the parent's /v1/entries endpoint —
	// served as a diagnostic string for the SDK anchor's
	// LedgerEndpoint field (the SDK uses this for fork-detection
	// binding hashes; see SDK plan §I.13).
	//
	// ParentAnchorInterval is the cadence for parent-target
	// publishing. Independent of Interval (the AnchorSources
	// cadence) so operators can run the two loops at different
	// rates. Defaults to Interval when zero.
	ParentLogDID string

	// ParentTargets is the MULTI-PARENT fan-out (PR-4d): one entry per
	// derived constitutional target (WHICH from the constitution, WHERE from
	// its declaration ∪ canary — deriveParentEndpoints). When non-empty it
	// REPLACES the single-parent fields below for publishing: every tick
	// anchors this log's head into EVERY target, each with its own submit +
	// optional confirm; one failing parent never starves the others (each
	// failure logs toward alarm and retries next tick). The legacy
	// single-parent fields remain for pre-targets constitutions.
	ParentTargets []ParentTarget

	// ConfirmParentAnchor is the optional READ-BACK (anchor/confirm.go):
	// after a successful parent submit, confirm the anchor actually landed
	// (by-source discovery -> parent read-back -> durable
	// anchor_confirmations row). Best-effort per tick: a failure is logged
	// as published-but-unconfirmed (the alarm direction) and retried on the
	// next publish — RecordFirstSeen is idempotent. Nil = no read-back
	// (tests / source-only publishers).
	ConfirmParentAnchor  func(ctx context.Context, head types.CosignedTreeHead) error
	ParentAdmissionURL   string
	ParentAnchorInterval time.Duration

	// ParentSubmitFn is the egress for parent anchors. Composed by
	// the wiring layer as SignAndSubmit(parentHTTPSubmit(URL)) so
	// the entry is signed by THIS ledger's keys before being POSTed
	// to the parent's /v1/entries. Required (non-nil) when
	// ParentLogDID + ParentAdmissionURL are set.
	ParentSubmitFn func(entry *envelope.Entry) error
}

// AnchorSource is a remote log to anchor.
type AnchorSource struct {
	LogDID      string
	EndpointURL string // Base URL with /v1/tree/head
}

// MerkleHeadProvider returns the current Merkle tree head.
type MerkleHeadProvider interface {
	Head() (types.TreeHead, error)
}

// CosignedHeadProvider returns the current COSIGNED tree head — the
// chronological + state-derivation roots together with the K-of-N
// witness cosignatures. Required for the Part II.9 parent-target
// flow: the SDK's anchor builder rejects a head with no signatures
// ("not gossip-publishable") because such an anchor is not
// self-proving and would force the parent's auditors to fetch our
// /v1/tree/head separately.
//
// nil head + nil error is a valid response — the log has no
// cosigned heads yet (genesis state before the first witness round
// completes); publishParentAnchor skips that tick.
type CosignedHeadProvider interface {
	LatestCosigned(ctx context.Context) (*types.CosignedTreeHead, error)
}

// ParentTarget is one derived publish destination in the multi-parent
// fan-out: a constitutional target's current location plus its egress.
type ParentTarget struct {
	// LogDID is the parent log (the anchor entry's Destination).
	LogDID string
	// AdmissionURL is the parent's /v1/entries endpoint (diagnostics; the
	// egress itself is SubmitFn).
	AdmissionURL string
	// SubmitFn is this target's egress. Required.
	SubmitFn func(entry *envelope.Entry) error
	// Confirm is this target's optional read-back (anchor/confirm.go).
	Confirm func(ctx context.Context, head types.CosignedTreeHead) error
}

// Publisher periodically anchors remote tree heads to the local log.
// When ParentLogDID + ParentAdmissionURL + ParentSubmitFn are wired,
// it additionally anchors THIS log's head on the parent (II.9).
type Publisher struct {
	cfg          PublisherConfig
	merkle       MerkleHeadProvider
	cosignedHead CosignedHeadProvider
	// submitFn submits a signed entry to the local admission pipeline.
	submitFn func(entry *envelope.Entry) error
	client   *http.Client
	logger   *slog.Logger
}

// parentEnabled reports whether the parent-target flow is fully
// wired (all three of ParentLogDID, ParentAdmissionURL,
// ParentSubmitFn set + a non-nil CosignedHeadProvider, since the
// SDK anchor builder rejects no-signature heads). Mixed state —
// only some fields set — is treated as a wiring bug and the
// parent ticker stays disabled; Run logs the partial-config
// diagnostic at startup so operators notice.
func (p *Publisher) parentEnabled() bool {
	if p.cosignedHead == nil {
		return false
	}
	if len(p.cfg.ParentTargets) > 0 {
		return true
	}
	return p.cfg.ParentLogDID != "" &&
		p.cfg.ParentAdmissionURL != "" &&
		p.cfg.ParentSubmitFn != nil
}

// NewPublisher creates an anchor publisher. LogDID in cfg MUST be non-empty —
// the SDK's NewUnsignedEntry will reject anchor commentary construction
// otherwise. cosignedHead is optional; nil disables the parent-target flow
// (II.9) regardless of the ParentLogDID/URL/SubmitFn fields.
//
// V1.34 SDK CONTRACT — NO SILENT FALLBACK. cfg.HTTPClient is REQUIRED;
// nil at construction PANICS rather than silently building a plaintext
// DefaultClient. The publisher's outbound is the federation's anchor
// fetch surface (publishOne → GET /v1/tree/head) — a misconfigured
// operator must not be able to fetch peer heads over plaintext without
// a loud signal. Production wiring threads d.OutboundHTTPClient (always
// non-nil at boot; see cmd/ledger/boot/wire/wire.go:185). Tests
// construct an explicit *http.Client (httptest.Server.Client(),
// &http.Client{}, or sdklog.DefaultClient(timeout, nil) — the choice
// is the caller's, never the library's).
func NewPublisher(
	cfg PublisherConfig,
	merkle MerkleHeadProvider,
	cosignedHead CosignedHeadProvider,
	submitFn func(entry *envelope.Entry) error,
	logger *slog.Logger,
) *Publisher {
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	if cfg.HTTPClient == nil {
		panic("anchor/NewPublisher: HTTPClient required (the v1.34 SDK contract is no silent fallback to a plaintext default; wire d.OutboundHTTPClient at boot or pass an explicit *http.Client in tests)")
	}
	return &Publisher{
		cfg:          cfg,
		merkle:       merkle,
		cosignedHead: cosignedHead,
		submitFn:     submitFn,
		client:       cfg.HTTPClient,
		logger:       logger,
	}
}

// Run starts the anchor publishing loop(s). Two independent
// tickers may run concurrently:
//
//  1. The AnchorSources ticker (existing) — for every configured
//     source log, fetches its head + builds a local anchor entry.
//  2. The ParentTarget ticker (II.9) — fetches THIS log's head +
//     publishes an anchor entry to the parent's admission API.
//
// Either loop is independently disabled by missing configuration.
// When BOTH are disabled, Run returns immediately. When both are
// active, they run in lock-step under the same context.
func (p *Publisher) Run(ctx context.Context) {
	srcConfigured := len(p.cfg.AnchorSources) > 0
	parentConfigured := p.parentEnabled()

	// Diagnose partial parent config: a non-empty ParentLogDID or
	// ParentAdmissionURL with the other field empty (or a nil
	// ParentSubmitFn) is a wiring bug — log it loudly so
	// operators notice instead of silently dropping the parent
	// anchor stream.
	if !parentConfigured && (p.cfg.ParentLogDID != "" || p.cfg.ParentAdmissionURL != "") {
		p.logger.Warn("anchor: parent-target config partial; parent ticker disabled",
			"parent_log_did", p.cfg.ParentLogDID,
			"parent_admission_url", p.cfg.ParentAdmissionURL,
			"parent_submit_fn_wired", p.cfg.ParentSubmitFn != nil)
	}

	if !srcConfigured && !parentConfigured {
		p.logger.Info("anchor: no sources + no parent target configured, exiting")
		return
	}

	// Per-loop tickers run only when their config is present so
	// nil-ticker selects on a closed channel never happen.
	var srcTickC, parentTickC <-chan time.Time
	if srcConfigured {
		t := time.NewTicker(p.cfg.Interval)
		defer t.Stop()
		srcTickC = t.C
	}
	if parentConfigured {
		interval := p.cfg.ParentAnchorInterval
		if interval <= 0 {
			interval = p.cfg.Interval
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		parentTickC = t.C
		p.logger.Info("anchor: parent-target enabled",
			"parent_log_did", p.cfg.ParentLogDID,
			"parent_admission_url", p.cfg.ParentAdmissionURL,
			"parent_anchor_interval", interval)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-srcTickC:
			p.publishAll(ctx)
		case <-parentTickC:
			if err := p.publishParentAnchor(ctx); err != nil {
				p.logger.Warn("anchor: parent publish failed",
					"parent_log_did", p.cfg.ParentLogDID,
					"error", err)
			}
		}
	}
}

func (p *Publisher) publishAll(ctx context.Context) {
	for _, source := range p.cfg.AnchorSources {
		if err := p.publishOne(ctx, source); err != nil {
			p.logger.Warn("anchor: publish failed",
				"source_log", source.LogDID, "error", err)
		}
	}
}

func (p *Publisher) publishOne(ctx context.Context, source AnchorSource) error {
	// Fetch remote tree head.
	req, err := http.NewRequestWithContext(ctx, "GET", source.EndpointURL+"/v1/tree/head", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch tree head: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch tree head: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Parse the peer's cosigned tree head. /v1/tree/head serves the
	// canonical gossip wire shape: all four cosigned roots (root_hash,
	// smt_root, receipt_root, tree_size) plus the K-of-N cosignatures
	// as {pub_key_id, scheme_tag, sig_bytes}. We embed the whole thing
	// so the anchor is a self-proving, offline-verifiable artifact: a
	// consumer (e.g. the Judicial Network's cross-log reconciler)
	// reconstructs the head via findings.CosignedTreeHeadFromWire and
	// verifies the witness quorum with Verify(set) entirely in memory —
	// it never has to call back to the source log, which may by then be
	// offline, rate-limited, or actively equivocating. Anchoring only
	// the roots (or, worse, an opaque SHA-256 of the body) would force
	// that callback and reduce the anchor to a freshness witness.
	var wireHead sdkgossip.WireCosignedTreeHead
	if uErr := json.Unmarshal(body, &wireHead); uErr != nil {
		return fmt.Errorf("decode tree head: %w", uErr)
	}
	if len(wireHead.Signatures) == 0 {
		return fmt.Errorf("peer tree head carries no cosignatures; refusing to anchor an unverifiable head")
	}

	// Reconstruct the typed head and build the anchor via the SDK — the single
	// owner of the BP-ENTRY-ANCHOR-COSIGNED-HEAD-V1 format (baseproof/anchor). The embedded
	// head stays self-proving (all four roots + K-of-N cosignatures); a
	// consumer verifies the quorum offline via anchor.VerifyCosignedAnchor and
	// checks a foreign inclusion against the verified head — no callback to the
	// source log, which may by then be offline or equivocating.
	finding, err := findings.CosignedTreeHeadFromWire(sdkgossip.WireCosignedTreeHeadBody{
		Head:           wireHead,
		LedgerEndpoint: source.EndpointURL,
	})
	if err != nil {
		return fmt.Errorf("reconstruct tree head: %w", err)
	}
	entry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID:      p.cfg.LedgerDID,
		Destination:    p.cfg.LogDID,
		SourceLogDID:   source.LogDID,
		Head:           finding.Head,
		LedgerEndpoint: source.EndpointURL,
		NetworkID:      p.cfg.NetworkID,
		// EventTime: SDK exchange/policy.CheckFreshness reads this via
		// time.UnixMicro; UnixMicro keeps self-anchors fresh.
		EventTime: time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		return fmt.Errorf("build anchor entry: %w", err)
	}

	// Submit through local admission pipeline.
	if p.submitFn != nil {
		if err := p.submitFn(entry); err != nil {
			return fmt.Errorf("submit anchor: %w", err)
		}
	}

	p.logger.Info("anchor published",
		"source_log", source.LogDID,
		"tree_size", wireHead.TreeSize,
		"cosignatures", len(wireHead.Signatures),
	)
	return nil
}

// publishParentAnchor fetches THIS log's current cosigned tree
// head, builds a CosignedAnchor entry referencing it, and submits
// via the ParentSubmitFn (which is composed by the wiring layer
// to sign + POST to the parent's admission URL). Part II.9 —
// federation-upward anchoring.
//
// The submission target is the parent's admission API; the entry's
// Destination is the parent log's DID so admission accepts it.
// SourceLogDID is THIS log's DID (we are the SOURCE being anchored
// onto the parent). The embedded head carries our K-of-N
// witness cosignatures so the anchor is self-proving — a parent-
// side auditor verifies the witness quorum offline without
// callback to our /v1/tree/head endpoint.
//
// A nil cosigned head (genesis / pre-first-witness-round) skips
// the tick — anchoring an unsigned head would fail the SDK's
// "not gossip-publishable" guard. The next tick re-tries.
//
// Errors are surfaced to the caller (Run logs them at Warn) so
// transient parent outages do NOT crash the loop.
func (p *Publisher) publishParentAnchor(ctx context.Context) error {
	head, err := p.cosignedHead.LatestCosigned(ctx)
	if err != nil {
		return fmt.Errorf("cosigned head: %w", err)
	}
	if head == nil {
		// No cosigned head yet — pre-first-witness-round. Skip.
		return nil
	}

	// Effective fan-out: the derived multi-parent list, or the legacy
	// single-parent fields synthesized as one target.
	targets := p.cfg.ParentTargets
	if len(targets) == 0 {
		targets = []ParentTarget{{
			LogDID:       p.cfg.ParentLogDID,
			AdmissionURL: p.cfg.ParentAdmissionURL,
			SubmitFn:     p.cfg.ParentSubmitFn,
			Confirm:      p.cfg.ConfirmParentAnchor,
		}}
	}

	var firstErr error
	for _, t := range targets {
		if err := p.publishToParent(ctx, t, head); err != nil {
			// One failing parent never starves the others: log toward
			// alarm, keep fanning out, retry everything next tick.
			p.logger.Warn("anchor: parent publish failed",
				"parent_log_did", t.LogDID, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// publishToParent anchors head into one parent: build → submit → (optional)
// read-back confirm.
func (p *Publisher) publishToParent(ctx context.Context, t ParentTarget, head *types.CosignedTreeHead) error {
	if t.SubmitFn == nil {
		return fmt.Errorf("parent %s: no submit egress wired", t.LogDID)
	}
	entry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID:      p.cfg.LedgerDID,
		Destination:    t.LogDID,
		SourceLogDID:   p.cfg.LogDID,
		Head:           *head,
		LedgerEndpoint: t.AdmissionURL,
		NetworkID:      p.cfg.NetworkID,
		EventTime:      time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		return fmt.Errorf("build parent anchor entry: %w", err)
	}
	if err := t.SubmitFn(entry); err != nil {
		return fmt.Errorf("submit parent anchor: %w", err)
	}
	p.logger.Info("parent anchor published",
		"parent_log_did", t.LogDID,
		"tree_size", head.TreeSize,
		"cosignatures", len(head.Signatures))

	// Read-back: close the 202-and-forget. Failure here is NOT a publish
	// failure — the anchor was submitted; it is published-but-unconfirmed,
	// logged toward alarm and retried next tick (first-seen is idempotent).
	if t.Confirm != nil {
		if cErr := t.Confirm(ctx, *head); cErr != nil {
			p.logger.Warn("anchor: parent anchor published but UNCONFIRMED",
				"parent_log_did", t.LogDID,
				"tree_size", head.TreeSize,
				"error", cErr)
		} else {
			p.logger.Info("anchor: parent anchor confirmed (read-back)",
				"parent_log_did", t.LogDID,
				"tree_size", head.TreeSize)
		}
	}
	return nil
}

// SubmitToHTTPEndpoint returns a submitFn that POSTs canonical
// bytes of a signed envelope.Entry to the supplied admission
// endpoint (/v1/entries). Used by the parent-target flow (II.9)
// to push to a foreign log's admission API; the local self-submit
// uses SubmitInProcess instead.
//
// client may be nil — when nil, the helper builds an SDK-default
// HTTP client (sdklog.DefaultClient with 30s timeout). Production
// callers should supply an mTLS-aware client when the parent log
// enforces mTLS on its TLS listener (typically composed from
// internal/clienttls — same posture as the AnchorSources fetch).
//
// endpoint must be the absolute /v1/entries URL of the target
// admission API (e.g., "https://parent.example/v1/entries").
// SubmitToHTTPEndpoint does NOT manipulate the path; the wiring
// layer passes the URL straight through. An empty endpoint at
// call time returns a fmt.Errorf — callers should validate at
// construction.
//
// V1.34 SDK CONTRACT — NO SILENT FALLBACK. client is REQUIRED; nil at
// construction time PANICS rather than silently falling back to a
// plaintext default. The anchor publish surface is the federation's
// most security-sensitive outbound — a misconfigured operator must
// not be able to publish anchors over plaintext without a loud
// signal. Production wiring threads d.OutboundHTTPClient (always
// non-nil; see cmd/ledger/boot/wire/wire.go:185). Tests construct an
// explicit *http.Client (an httptest.Server.Client(), &http.Client{},
// or sdklog.DefaultClient(timeout, nil) — the choice is the caller's,
// never the library's).
func SubmitToHTTPEndpoint(client *http.Client, endpoint string) func(entry *envelope.Entry) error {
	if client == nil {
		panic("anchor/SubmitToHTTPEndpoint: client required (the v1.34 SDK contract is no silent fallback to a plaintext default; wire d.OutboundHTTPClient at boot or pass an explicit *http.Client in tests)")
	}
	return func(entry *envelope.Entry) error {
		if endpoint == "" {
			return fmt.Errorf("anchor/SubmitToHTTPEndpoint: empty endpoint")
		}
		canonical, err := envelope.Serialize(entry)
		if err != nil {
			return fmt.Errorf("anchor/SubmitToHTTPEndpoint: serialize: %w", err)
		}
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(canonical))
		if err != nil {
			return fmt.Errorf("anchor/SubmitToHTTPEndpoint: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("anchor/SubmitToHTTPEndpoint: POST %s: %w", endpoint, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return fmt.Errorf("anchor/SubmitToHTTPEndpoint: %s returned %d: %s",
				endpoint, resp.StatusCode, body)
		}
		return nil
	}
}

// SubmitInProcess creates a submitFn that hands a signed envelope to
// the binary's own admission HTTP handler IN-PROCESS — no network, no
// scheme to get wrong, no TLS handshake. The previous loopback shape
// (POST http://localhost%s/v1/entries) was a latent bug under binary-
// terminated TLS: when LEDGER_TLS_CERT_FILE is set the listener serves
// HTTPS with RequireAndVerifyClientCert and refuses plain HTTP, so the
// self-submit silently fails. Going in-process eliminates the failure
// mode entirely: the same admission code path runs, but the bytes
// never leave the binary.
//
// handler is a deferred-resolution getter because the SubmissionHandler
// is built LATER in Wire() than the publisher/commitment-publisher that
// captures this submitFn. The getter closes over a slot on AppDeps;
// Wire's composeHandlers populates that slot before the first builder/
// anchor tick fires. A nil-returning getter at call time means the
// caller wired things in the wrong order — the closure surfaces a
// clear "submit handler not yet wired" error rather than a nil-deref.
//
// The entry MUST be signed before this function is called — admission
// rejects unsigned bytes regardless. Wrap with SignAndSubmit at the
// composition root to get a signed-and-submit pipeline.
func SubmitInProcess(handler func() http.Handler) func(entry *envelope.Entry) error {
	if handler == nil {
		// Programming error: a missing handler getter at construction
		// time can't be recovered from at call time. Panic loudly.
		panic("anchor.SubmitInProcess: handler getter must be non-nil")
	}
	return func(entry *envelope.Entry) error {
		h := handler()
		if h == nil {
			return fmt.Errorf("anchor: submit handler not yet wired (composition order bug)")
		}
		canonical, err := envelope.Serialize(entry)
		if err != nil {
			return fmt.Errorf("anchor: serialize: %w", err)
		}
		// Same wire as the external admission path — httptest.NewRequest
		// gives a *http.Request with Method/URL/Body that h.ServeHTTP
		// reads identically to a real inbound request. The recorder
		// captures status + body so we can surface admission errors.
		req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(canonical))
		req.Header.Set("Content-Type", "application/octet-stream")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			body, _ := io.ReadAll(io.LimitReader(rec.Body, 1024))
			return fmt.Errorf("anchor: in-process admission %d: %s", rec.Code, body)
		}
		return nil
	}
}

// SignAndSubmit wraps a submitFn (typically SubmitInProcess) with the
// per-entry ECDSA signing step. The returned function:
//
//  1. Verifies entry.Header.SignerDID matches signerDID — admission
//     would reject a mismatch on signature verify, so we fail fast
//     with a useful error here.
//  2. Computes sha256(envelope.SigningPayload(entry)).
//  3. Signs the hash with priv via signatures.SignEntry.
//  4. Populates entry.Signatures with one envelope.Signature whose
//     SignerDID matches Header.SignerDID and AlgoID is ECDSA.
//  5. Calls submit(entry).
//
// Used by the anchor and commitment publishers. Both call
// envelope.NewUnsignedEntry to build their entries; SignAndSubmit
// closes the contract so envelope.Serialize and admission are
// happy.
func SignAndSubmit(
	priv *ecdsa.PrivateKey,
	signerDID string,
	submit func(*envelope.Entry) error,
) func(*envelope.Entry) error {
	return func(entry *envelope.Entry) error {
		if entry.Header.SignerDID != signerDID {
			return fmt.Errorf(
				"anchor/SignAndSubmit: Header.SignerDID %q != signer DID %q (caller bug)",
				entry.Header.SignerDID, signerDID,
			)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(entry))
		sig, err := signatures.SignEntry(signingHash, priv)
		if err != nil {
			return fmt.Errorf("anchor/SignAndSubmit: SignEntry: %w", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: signerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		}}
		return submit(entry)
	}
}
