/*
FILE PATH: witnessclient/head_sync.go

K-of-N cosignature collection over the SDK's universal cosign wire
surface. Implements builder.WitnessCosigner.

# WHY THIS WRAPPER EXISTS

The SDK ships cosign.WitnessClient (per-endpoint HTTP client) and
cosign.WitnessCollector (K-of-N parallel collector with short-circuit
cancellation on the K-th valid signature). HeadSync glues those to:

  - The ledger's TreeHeadStore — persists the (head + per-witness
    signatures) tuple so downstream readers (api/, anchor publisher,
    audit consumers) see a single materialized record per signed
    head.
  - builder.WitnessCosigner — the builder loop calls
    RequestCosignatures(ctx, head) after each successful commit;
    this file maps that call into the universal cosign primitive.

# 429 / RATE-LIMIT BACKPRESSURE

Per-endpoint rate-limit rejections surface as cosign.ErrRateLimited;
RetryAfterFromError reads the parsed Retry-After. The collector
treats them as per-endpoint failures and continues fanning out to
the remaining endpoints — quorum still has K-1 other tries. The
collector returns ErrQuorumCollectionFailed only if the
unrecoverable failures (rate-limit + network + 5xx aggregate) leave
fewer than K endpoints capable of returning a valid signature.

The ledger-side action on rate-limit failure is to log and
continue; the next builder cycle re-requests cosignatures on a
larger tree head. This is correct because cosignatures are
per-head; the witness signing the next cycle's head is identical
work.

# 503 / Retry-After BACKPRESSURE

cosign.WithHTTPClient(sdklog.DefaultClient(timeout, nil)) layers
RetryAfterRoundTripper underneath; transient 503s with a
Retry-After header are transparently retried by the transport
before the cosign client sees them. The 429-rate-limit and
5xx-witness-failure paths above run only after the transport
retries are exhausted.
*/
package witnessclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/observability"
	"github.com/baseproof/tooling/services/ledger/store"
)

// WitnessEndpointResolver is the on-log witness-endpoint discovery
// surface the head-sync wiring depends on. Declared NARROW at the
// consumer (Go structural typing): only WitnessEndpoints is called
// from resolveEffectiveEndpoints, so that is the only method
// required of a satisfier.
//
// SATISFIERS (by structural typing — no explicit conformance needed):
//   - *discover.DefaultAuthoritativeResolver from
//     github.com/baseproof/baseproof/log/discover (production:
//     populated from on-log WitnessEndpointDeclarationV1 records).
//   - witness.StaticEndpoints from the SDK (test / simple-deployment).
//   - did.DIDEndpointAdapter from the SDK (did:web bootstrap path).
//   - Any test fake exposing the single method below.
//
// We deliberately do NOT alias the SDK's witness.EndpointResolver
// (which embeds sdklog.EndpointResolver and additionally requires a
// LedgerEndpoint method). The v1.32.0 audit confirmed
// "log.EndpointResolver — not referenced by ledger/ production
// files"; requiring LedgerEndpoint here would force every satisfier
// to expose a method the ledger does not call. The narrow shape
// matches the admission.SignaturePolicyAmendmentSource +
// gossipnet.AuditorRegistrySource +
// anchor.PeerAdmissionURLResolver pattern used elsewhere in this
// repo: minimal interface declared at the consumer.
//
// The legacy config-driven path (LEDGER_WITNESS_ENDPOINTS) is
// preserved as a canary fallback when the resolver returns no on-log
// declarations (bootstrap window before any
// WitnessEndpointDeclarationV1 entry has landed). After the first
// declaration is admitted + cosigned, the resolver becomes the
// authoritative source and the env var is dead config — operators
// should drop it from deployment manifests.
type WitnessEndpointResolver interface {
	WitnessEndpoints(ctx context.Context, logDID string) ([]string, error)
}

// CosignedHeadPublisher is the interface HeadSync calls after a
// successful K-of-N collection to fan out a KindCosignedTreeHead
// gossip event. nil is acceptable — when no publisher is wired,
// HeadSync skips the publish step.
type CosignedHeadPublisher interface {
	PublishCosignedHead(ctx context.Context, head types.CosignedTreeHead)
}

// HeadSyncConfig configures witness cosignature collection.
type HeadSyncConfig struct {
	// EndpointResolver is the on-log authoritative witness-endpoint
	// discovery surface (typically a *discover.DefaultAuthoritativeResolver
	// from the SDK). When non-nil and EndpointResolverLogDID is set,
	// NewHeadSync snapshots the witness URLs from the resolver at
	// construction time via EndpointResolver.WitnessEndpoints(ctx,
	// LogDID). Resolver-returned URLs WIN over WitnessEndpoints
	// (the legacy config-driven slice below).
	//
	// THIS CLOSES THE LAYER-2 SILENT-URL-SUBSTITUTION BACKDOOR for
	// witness discovery: pre-v1.32.0 the ledger trusted its own
	// deployment config (LEDGER_WITNESS_ENDPOINTS) for the URLs it
	// fanned cosignature requests to — an operator-edit-and-reload
	// away from the exact attack the SDK's
	// WitnessEndpointDeclarationV1 was designed to prevent. Post-
	// v1.32.0 the URLs come from on-log, network-signed,
	// cosigned-tree-head-anchored declarations.
	EndpointResolver WitnessEndpointResolver

	// EndpointResolverLogDID is the logDID passed to
	// EndpointResolver.WitnessEndpoints. Typically this binary's
	// own log DID (cmd/ledger wires it from cfg.LogDID). Empty
	// with a non-nil EndpointResolver is a CONSTRUCTION ERROR
	// (NewHeadSync refuses): discovery was requested and an empty
	// DID would silently disable it, degrading to the legacy
	// config canary — the silent-URL-substitution posture the
	// resolver exists to close.
	EndpointResolverLogDID string

	// EndpointResolverTimeout caps the resolver call at startup.
	// 0 ⇒ 5 seconds. A timeout is NOT a fatal error — the
	// constructor falls through to the WitnessEndpoints canary
	// fallback, logs a warn, and the ledger remains operable.
	EndpointResolverTimeout time.Duration

	// WitnessEndpoints is the LEGACY config-driven set of peer
	// witness base URLs. After v1.32.0 the authoritative source is
	// the EndpointResolver above; this slice is the CANARY FALLBACK
	// used when the resolver is nil OR returns an empty list (the
	// bootstrap window before any WitnessEndpointDeclarationV1
	// entry has been admitted + cosigned).
	//
	// Operators SHOULD drop LEDGER_WITNESS_ENDPOINTS from
	// deployment manifests once the network has published its
	// witness-endpoint declarations on-log. The fallback is
	// retained so a bootstrap-window outage doesn't strand the
	// ledger.
	WitnessEndpoints []string

	// QuorumK is the minimum number of valid signatures required
	// to consider a head "cosigned". 1 <= QuorumK <= N (where N is
	// len(WitnessEndpoints)). The collector short-circuits as soon
	// as the K-th valid signature arrives.
	QuorumK int

	// PerWitnessTimeout caps the per-endpoint HTTP request. The
	// collector's per-call ctx is whatever the builder loop passed
	// in; setting a per-witness timeout floors it so a single slow
	// peer cannot stall the cycle past PerWitnessTimeout regardless
	// of the parent ctx's deadline.
	PerWitnessTimeout time.Duration

	// NetworkID binds every cosign request to the deployment's
	// network. Witnesses for the same network share this value;
	// signatures produced under one NetworkID never satisfy quorum
	// under another.
	NetworkID cosign.NetworkID

	// GossipPublisher, when non-nil, is invoked after each
	// successful K-of-N collection with the assembled
	// CosignedTreeHead. The publisher is responsible for signing
	// the event as a KindCosignedTreeHead and broadcasting it to
	// peers via the gossip Sink. Optional; nil disables the
	// publish step (useful for read-only ledgers or trimmed
	// test rigs).
	GossipPublisher CosignedHeadPublisher

	// HTTPClient is the outbound client every cosign.WitnessClient
	// is built with. REQUIRED — nil is rejected at construction
	// (see baseproof v1.34 CHANGELOG: the SDK no longer manufactures
	// a plaintext default). Set to an mTLS client (typically built
	// from internal/clienttls) when the witnesses enforce mTLS on
	// their TLS listeners and this binary must present a client
	// cert. The supplied client's Timeout MUST already reflect
	// PerWitnessTimeout (or be larger) — the constructor does not
	// override the client's timeout. Production wiring uses
	// sdklog.DefaultClient(PerWitnessTimeout, tlsCfg) for the
	// RetryAfterRoundTripper posture.
	HTTPClient *http.Client
}

// HeadSync manages tree head cosignature collection.
// Implements builder.WitnessCosigner.
type HeadSync struct {
	cfg       HeadSyncConfig
	collector *cosign.WitnessCollector
	endpoints []string // parallel to collector's clients; for persistence labels
	store     *store.TreeHeadStore
	logger    *slog.Logger
	publisher CosignedHeadPublisher
}

// NewHeadSync constructs the head sync manager. Returns an error
// if the SDK collector rejects the witness configuration (zero
// NetworkID, K > N, K <= 0, empty endpoints, etc.).
//
// Endpoint precedence (v1.32.0):
//
//  1. cfg.EndpointResolver.WitnessEndpoints(ctx, cfg.EndpointResolverLogDID)
//     — the on-log, network-signed authoritative source. Used when
//     the resolver is configured AND returns a non-empty slice.
//  2. cfg.WitnessEndpoints — the legacy config-driven canary
//     fallback. Used when the resolver is nil OR returns empty
//     (bootstrap window).
//
// At least one of the two MUST produce a non-empty endpoint slice;
// otherwise the constructor returns an error rather than wiring a
// zero-quorum collector.
func NewHeadSync(cfg HeadSyncConfig, treeStore *store.TreeHeadStore, logger *slog.Logger) (*HeadSync, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.QuorumK <= 0 {
		return nil, fmt.Errorf("witness/head_sync: QuorumK must be > 0")
	}
	// A wired resolver with an empty log DID is a CONSTRUCTION error, not a
	// fallback: the operator asked for on-log endpoint discovery, and an empty
	// DID would silently disable it — degrading to the legacy config canary,
	// the exact silent-URL-substitution posture the resolver exists to close.
	// (The {source="config_canary_fallback", log_did=""} log line is this gap
	// surfacing at collect time; fail here instead, where it is fixable.)
	// A nil resolver with config endpoints remains a legitimate mode (tests,
	// bootstrap window).
	if cfg.EndpointResolver != nil && cfg.EndpointResolverLogDID == "" {
		return nil, fmt.Errorf("witness/head_sync: EndpointResolver is wired but EndpointResolverLogDID is empty — " +
			"on-log endpoint discovery would be silently disabled (config-canary fallback); " +
			"thread the ledger's log DID or remove the resolver")
	}
	if cfg.PerWitnessTimeout <= 0 {
		cfg.PerWitnessTimeout = 30 * time.Second
	}

	// Resolver-driven snapshot (L2 backdoor closure). The resolver
	// is consulted once at construction; subsequent rotations are
	// picked up at the next builder restart. A real-time refresh
	// hook is deferred — the cosign domain is rotation-anchored
	// (NetworkID), so a witness URL drift between rotations is
	// detected at the COSIGNATURE layer, not here.
	effectiveEndpoints, source, err := resolveEffectiveEndpoints(cfg, logger)
	if err != nil {
		return nil, err
	}
	cfg.WitnessEndpoints = effectiveEndpoints
	logger.Info("witness/head_sync: endpoint source",
		"source", source,
		"endpoint_count", len(effectiveEndpoints),
		"log_did", cfg.EndpointResolverLogDID,
	)
	// Tier E observability — operator-facing rollout signal. Once
	// {source="config_canary_fallback"} hits zero across a peer set,
	// LEDGER_WITNESS_ENDPOINTS can be dropped from the deployment.
	observability.EndpointSource(source, "witness")

	// SDK transport with RetryAfterRoundTripper for transparent
	// 503-Retry-After honoring. The 429-rate-limit case surfaces
	// as cosign.ErrRateLimited (handled per-call below); 503 is
	// retried inside the transport before the cosign client sees
	// it. The deployer wires an mTLS-equipped client via
	// cfg.HTTPClient; we use it as-is.
	//
	// v1.34 contract: caller MUST supply HTTPClient. The boot wiring
	// always populates d.OutboundHTTPClient (see
	// cmd/ledger/boot/wire/wire.go); a nil here means a programming
	// error in a caller that constructed HeadSyncConfig{} by hand.
	// Fail-closed.
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("witness/head_sync: HTTPClient required (pass cfg.HTTPClient — the SDK no longer manufactures a plaintext default)")
	}
	httpClient := cfg.HTTPClient

	clients := make([]*cosign.WitnessClient, 0, len(cfg.WitnessEndpoints))
	for _, ep := range cfg.WitnessEndpoints {
		c, cErr := cosign.NewWitnessClient(ep, cfg.NetworkID,
			cosign.WithHTTPClient(httpClient))
		if cErr != nil {
			return nil, fmt.Errorf("witness/head_sync: build client %s: %w", ep, cErr)
		}
		clients = append(clients, c)
	}

	collector, err := cosign.NewWitnessCollector(clients, cfg.QuorumK)
	if err != nil {
		return nil, fmt.Errorf("witness/head_sync: build collector: %w", err)
	}

	return &HeadSync{
		cfg:       cfg,
		collector: collector,
		endpoints: append([]string{}, cfg.WitnessEndpoints...),
		store:     treeStore,
		logger:    logger,
		publisher: cfg.GossipPublisher,
	}, nil
}

// Collector exposes the underlying K-of-N collector so other
// services (escrow override endpoint, future rotation publisher)
// can submit alternate CosignPayload types — e.g.,
// cosign.EscrowOverridePayload or cosign.RotationPayload —
// against the same witness peer set without standing up a
// parallel client pool. The collector is purpose-agnostic: each
// Collect call's payload determines the cosign canonical bytes
// being signed.
func (hs *HeadSync) Collector() *cosign.WitnessCollector {
	if hs == nil {
		return nil
	}
	return hs.collector
}

// RequestCosignatures implements builder.WitnessCosigner.
// Collects K-of-N cosignatures via the SDK collector and persists
// the (head + per-witness signatures) tuple. Returns the assembled
// CosignedTreeHead so the builder can pass it to
// MerkleAppender.PublishCosignedCheckpoint after the atomic commit.
//
// CONTRACT (one statement, mirrored at the checkpoint loop's Step 8):
// on ANY error the PUBLISH aborts — the public CDN cosigned-checkpoint
// advances only on a successful K-of-N collect (Strict STH Finality,
// Alignment 2). The COMMIT is unaffected: it was durable before this
// was called. Only the TRANSIENT class (quorum unreachable) is
// retried, by the loop's HOLD on the next cycle; the two deterministic
// classes — builder.ErrNoCosigner (nothing wired) and a head that
// fails payload validation (wraps cosign.ErrInvalidPayload) — must
// never be retried, because re-asking cannot change the outcome.
//
// Idempotency: the SDK's UNIQUE constraint on
// tree_head_sigs(tree_size, signer) makes this safe under retry.
// A re-collect over the same head writes the same rows.
func (hs *HeadSync) RequestCosignatures(ctx context.Context, head types.TreeHead) (types.CosignedTreeHead, error) {
	if hs == nil || hs.collector == nil {
		// No collector wired (read-only ledger, trimmed test rig). A TYPED
		// condition — never a zero-valued head: the old sentinel encoded
		// "nothing to publish" on the exact type whose zero fields the SDK
		// rejects, which is how an invalid zero head could travel unnoticed.
		return types.CosignedTreeHead{}, builder.ErrNoCosigner
	}

	// Single 104-byte cosign payload (baseproof v1.9.x): the witness
	// signature binds RootHash, SMTRoot, AND ReceiptRoot atomically.
	// There is no V1/V2 toggle — every cosignature covers all three
	// roots, closing the receipt/state-map forgery vectors.
	payload := cosign.NewTreeHeadPayload(head)

	// "No invalid payload reaches collection" is enforced by the rule's owner:
	// the SDK's Collect (since v0.0.4-rc6) validates before any fan-out and
	// refuses with the typed cosign.ErrInvalidPayload — the deterministic
	// class the checkpoint loop FAULTS on instead of holding. (The temporary
	// rc5-era bridge guard that lived here is deleted; the unchanged seam
	// test still pins the refusal + zero fan-out, now proving the SDK gate.)
	result, err := hs.collector.Collect(ctx, payload)
	if err != nil {
		// The quorum-failure log is for the TRANSIENT class only — an invalid
		// payload is the caller's bug, not a witness outage, and logging it as
		// one would corrupt the operator-facing signal the SRE counter feeds.
		if !errors.Is(err, cosign.ErrInvalidPayload) {
			hs.logQuorumFailure(err, result, head)
		}
		return types.CosignedTreeHead{}, fmt.Errorf("witness/head_sync: collect: %w", err)
	}

	// Persist the head fact (idempotent) before any per-witness
	// signature so the FK on tree_head_sigs.tree_size is satisfied.
	// head.SMTRoot is bound into the witness-cosigned payload by
	// the SDK (baseproof v0.8.0+ types.TreeHead.SMTRoot); persist it
	// alongside RootHash so audit / equivocation comparison can
	// recompute the canonical bytes the witnesses signed.
	const hashAlgo = uint16(1) // SHA-256 — the deployment-lifetime default.
	if perr := hs.store.InsertHead(ctx, head.TreeSize, head.RootHash, head.SMTRoot, head.ReceiptRoot, hashAlgo); perr != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("witness/head_sync: persist head: %w", perr)
	}

	// Persist each per-witness signature. The signer label is the
	// endpoint URL of the witness that returned the signature; the
	// SDK collector preserves endpoint ordering in CollectionResult
	// when the K-th signature arrives, but the slice is K-of-N so
	// we look up the originating endpoint via the per-endpoint
	// outcome map.
	if perr := hs.persistSignatures(ctx, head, result, hashAlgo); perr != nil {
		return types.CosignedTreeHead{}, perr
	}

	hs.store.Invalidate()
	hs.logger.Info("cosigned tree head",
		"tree_size", head.TreeSize,
		"root_hash", fmt.Sprintf("%x", head.RootHash[:8]),
		"smt_root", fmt.Sprintf("%x", head.SMTRoot[:8]),
		"signatures", len(result.Signatures),
		"quorum_k", hs.cfg.QuorumK,
		"quorum_n", len(hs.endpoints),
	)

	cosignedHead := types.CosignedTreeHead{
		TreeHead:   head,
		Signatures: result.Signatures,
	}

	// Gossip publish (best-effort; never fails the commit path).
	// The same CosignedTreeHead value is returned to the caller for
	// the public-CDN PublishCosignedCheckpoint write — both
	// transports carry identical K-of-N evidence.
	if hs.publisher != nil {
		hs.publisher.PublishCosignedHead(ctx, cosignedHead)
	}
	return cosignedHead, nil
}

// persistSignatures inserts each collected signature into
// tree_head_sigs. Each row is (tree_size, hash_algo, signer,
// sig_algo, signature_bytes).
//
// The SDK collector's CollectionResult.Signatures slice contains the
// K successfully-collected signatures; PerEndpoint[i].Err == nil
// identifies which endpoints contributed. The signature payload is
// JSON-encoded for the row's `signature` BYTEA column — the SDK type
// fields are opaque to the ledger's persistence layer; downstream
// consumers parse it back via json.Unmarshal into
// types.WitnessSignature.
func (hs *HeadSync) persistSignatures(
	ctx context.Context,
	head types.TreeHead,
	result *cosign.CollectionResult,
	hashAlgo uint16,
) error {
	if result == nil {
		return nil
	}
	contributingEndpoints := make([]string, 0, len(result.Signatures))
	for i, ep := range result.PerEndpoint {
		if ep.Err == nil && i < len(hs.endpoints) {
			contributingEndpoints = append(contributingEndpoints, hs.endpoints[i])
		}
		if len(contributingEndpoints) >= len(result.Signatures) {
			break
		}
	}

	for i, sig := range result.Signatures {
		signer := fmt.Sprintf("witness:%d", i)
		if i < len(contributingEndpoints) {
			signer = contributingEndpoints[i]
		}
		raw, encErr := json.Marshal(sig)
		if encErr != nil {
			return fmt.Errorf("witness/head_sync: encode sig %s: %w", signer, encErr)
		}
		if perr := hs.store.InsertSig(ctx, head.TreeSize, hashAlgo,
			signer, uint16(sig.SchemeTag), raw); perr != nil {
			return fmt.Errorf("witness/head_sync: persist sig %s: %w", signer, perr)
		}
	}
	return nil
}

// resolveEffectiveEndpoints implements the v1.32.0 endpoint
// precedence order: on-log resolver wins; config-driven slice is the
// canary fallback. Returns the slice + a label identifying which
// source produced it (for boot-time observability) + any fatal
// construction error.
//
// A resolver-call timeout or error is NOT fatal: the constructor
// logs a warn and falls through to the config-driven slice. This is
// the safety valve during the bootstrap window when no
// WitnessEndpointDeclarationV1 entry has been admitted yet.
func resolveEffectiveEndpoints(cfg HeadSyncConfig, logger *slog.Logger) ([]string, string, error) {
	// Resolver path.
	if cfg.EndpointResolver != nil && cfg.EndpointResolverLogDID != "" {
		timeout := cfg.EndpointResolverTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		urls, err := cfg.EndpointResolver.WitnessEndpoints(ctx, cfg.EndpointResolverLogDID)
		switch {
		case err != nil:
			logger.Warn("witness/head_sync: on-log resolver failed; using LEDGER_WITNESS_ENDPOINTS canary fallback",
				"log_did", cfg.EndpointResolverLogDID,
				"error", err.Error(),
			)
		case len(urls) > 0:
			return append([]string{}, urls...), "on_log_resolver", nil
		default:
			logger.Warn("witness/head_sync: on-log resolver returned empty; using LEDGER_WITNESS_ENDPOINTS canary fallback",
				"log_did", cfg.EndpointResolverLogDID,
			)
		}
	}

	// Config-driven canary fallback.
	if len(cfg.WitnessEndpoints) == 0 {
		return nil, "", fmt.Errorf(
			"witness/head_sync: no witness endpoints available — resolver returned empty AND LEDGER_WITNESS_ENDPOINTS unset")
	}
	return append([]string{}, cfg.WitnessEndpoints...), "config_canary_fallback", nil
}

// logQuorumFailure emits a structured per-endpoint diagnostic when
// the SDK collector returns ErrQuorumCollectionFailed. ErrRateLimited
// causes are tagged separately so ledgers reading logs can
// distinguish "everyone's overloaded" from "everyone's broken".
func (hs *HeadSync) logQuorumFailure(err error, result *cosign.CollectionResult, head types.TreeHead) {
	if !errors.Is(err, cosign.ErrQuorumCollectionFailed) {
		return
	}
	if result == nil {
		return
	}
	rateLimited := 0
	otherFail := 0
	for _, ep := range result.PerEndpoint {
		if ep.Err == nil {
			continue
		}
		if errors.Is(ep.Err, cosign.ErrRateLimited) {
			rateLimited++
		} else {
			otherFail++
		}
	}
	hs.logger.Warn("witness quorum failed",
		"tree_size", head.TreeSize,
		"got_sigs", len(result.Signatures),
		"need_k", hs.cfg.QuorumK,
		"rate_limited", rateLimited,
		"other_failures", otherFail,
	)
}
