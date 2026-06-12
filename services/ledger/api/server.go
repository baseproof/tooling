/*
FILE PATH:

	api/server.go

DESCRIPTION:

	HTTP server initialization and route registration. Every
	Baseproof ledger endpoint lives under /v1/. Health checks at
	/healthz and /readyz. The server is constructed against an
	explicit Handlers struct (closure-fed dependencies, no
	globals) and exposes ListenAndServe / ListenAndServeTLS /
	Serve / Shutdown for the cmd/ledger orchestrator.

KEY ARCHITECTURAL DECISIONS:
  - net/http standard library only. No framework dependency —
    the handler surface is small and the routing is purely
    method+path so the stdlib mux is sufficient.
  - DoS-immune timeouts. ReadHeaderTimeout caps the headers-
    arrived window (Slowloris defense); IdleTimeout caps the
    keep-alive idle window (long-lived-connection defense).
    ReadTimeout/WriteTimeout cap the full-request lifetimes.
  - Body caps applied via http.MaxBytesReader on every route
    that reads a body. Routes that take no body (GET /healthz,
    GET /readyz, every read endpoint) need no cap. Bounded I/O
    is structural — the memory cost of a malicious peer is
    mathematically capped.
  - Per-request correlation ID middleware wraps the entire mux
    so every handler + every structured log line carries the
    same X-Request-ID for cross-component tracing.
  - Readiness flag is atomic for thread-safe shutdown signalling.
    Pre-drain handshake (flip readiness BEFORE Shutdown) is in
    cmd/ledger/main.go; this file's Shutdown method is the
    Shutdown-after-grace primitive.
  - Optional handlers (WitnessCosign, GossipPost/Feed, read
    endpoints, batch admission, tile-serving) are nil-guarded so
    cmd/ledger-reader and trimmed test harnesses can omit them
    without producing 500s through nil HandlerFuncs.

OVERVIEW:

	NewServer constructs the mux, registers routes (with
	SizeLimit + Auth middleware on write paths), and wraps the
	whole tree in WithRequestID. The resulting *http.Server is
	started by ListenAndServe / ListenAndServeTLS / Serve and
	drained by Shutdown.

KEY DEPENDENCIES:
  - api/middleware: SizeLimit, Auth, WithRequestID — orthogonal
    cross-cutting concerns.
  - sync/atomic: lock-free readiness signal so /readyz never
    contends with the rest of the request flow.
*/
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	sdklog "github.com/baseproof/baseproof/log"

	"github.com/baseproof/tooling/services/ledger/api/middleware"
)

// -------------------------------------------------------------------------------------------------
// 1) Server Configuration
// -------------------------------------------------------------------------------------------------

// ServerConfig configures the HTTP server.
//
// Every timeout MUST be non-zero in production. Zero means "no
// deadline" in net/http, which is a Slowloris vector. Use
// DefaultServerConfig() at boot and override individual fields
// only with cause.
type ServerConfig struct {
	Addr string

	// ReadTimeout caps the full request-read window: TLS
	// handshake + headers + body.
	ReadTimeout time.Duration

	// ReadHeaderTimeout caps the header-only window. Set tighter
	// than ReadTimeout so a client streaming a large body has the
	// full ReadTimeout budget; a client trickling headers is cut
	// off at ReadHeaderTimeout. This is the primary Slowloris
	// defense.
	ReadHeaderTimeout time.Duration

	// WriteTimeout caps the response-write window from end-of-
	// request-headers to end-of-response.
	WriteTimeout time.Duration

	// IdleTimeout caps the keep-alive idle window between requests
	// on the same connection. Bounds memory tied up by zombie
	// connections.
	IdleTimeout time.Duration

	// ShutdownTimeout is the budget Shutdown gets to drain in-
	// flight requests before forcibly closing.
	ShutdownTimeout time.Duration

	// MaxEntrySize is the per-entry body cap on POST /v1/entries.
	// The middleware wraps r.Body in http.MaxBytesReader at
	// MaxEntrySize+1024 so the entry plus a small framing budget
	// fits but a malicious peer's gigabyte body is rejected.
	MaxEntrySize int64

	// TLSCertFile / TLSKeyFile, when both non-empty, switch the
	// listener to ListenAndServeTLS. Administrator deployments that
	// front the binary with a TLS-terminating proxy leave both
	// empty and the server speaks plain HTTP. Standalone (VM /
	// bare-metal / sigsum-witness) deployments populate both.
	TLSCertFile string
	TLSKeyFile  string

	// ClientCAFile is the PEM bundle of CA certificates allowed to
	// sign client certs presented on the exchange→ledger hop. The
	// ledger's ZT posture requires every caller to authenticate at
	// the transport layer in addition to the in-body G5
	// WriteAuthorization signature; the in-body signature alone
	// would let any TLS client trigger the (non-trivial) secp256k1
	// verification work.
	//
	// REQUIRED when TLSCertFile / TLSKeyFile are set: the TLS
	// listener refuses to start without it. There is no
	// "optional" mTLS knob — production ledgers serving the JN
	// either run plaintext behind a TLS-terminating proxy that
	// enforces mTLS itself, OR they enforce mTLS at the binary.
	// They MUST NOT serve TLS without mTLS — that posture is a
	// silent regression from the network's zero-trust contract.
	ClientCAFile string
}

// DefaultServerConfig returns production-grade defaults. Every
// timeout is non-zero so the returned *http.Server has no
// Slowloris-shaped exposure even before per-route middleware.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:              ":8080",
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   30 * time.Second,
		MaxEntrySize:      1 << 20, // 1 MiB
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Server
// -------------------------------------------------------------------------------------------------

// Server is the ledger HTTP server.
type Server struct {
	httpServer *http.Server
	cfg        ServerConfig
	ready      atomic.Bool
	// writable gates the admission (write) endpoints. Set false by the
	// supervisor on a proven integrity divergence so the ledger DEGRADES to
	// read-only — client writes get 503, reads/proofs keep serving, the process
	// stays alive for operator reconciliation instead of crash-looping. No
	// client write can panic the app.
	writable atomic.Bool
	logger   *slog.Logger

	// readinessProbe, when non-nil, is consulted on /readyz in
	// addition to the s.ready atomic. Returning a non-nil error
	// surfaces 503 with the error message in the body so an
	// administrator can grep for the specific subsystem that flipped
	// readiness (e.g., "database unavailable: circuit breaker
	// open"). Set via SetReadinessProbe; cmd/ledger wires the DB
	// circuit breaker here.
	readinessProbe atomic.Pointer[func() error]
}

// Handlers holds all registered handler functions. Nil fields
// suppress route registration — fine for read-only ledgers
// (cmd/ledger-reader) and trimmed test harnesses.
type Handlers struct {
	// ── Admission (write) ──────────────────────────────────────
	Submission      http.HandlerFunc // POST /v1/entries — single-entry SCT
	BatchSubmission http.HandlerFunc // POST /v1/entries/batch — async batch SCT array

	// ── Tree heads + Merkle proofs ────────────────────────────────
	TreeHead        http.HandlerFunc
	TreeInclusion   http.HandlerFunc
	TreeConsistency http.HandlerFunc

	// ── SMT proofs ─────────────────────────────────────────
	SMTProof      http.HandlerFunc
	SMTBatchProof http.HandlerFunc
	SMTRoot       http.HandlerFunc

	// ── Receipt proof ──────────────────────────────────────
	// ReceiptProof — GET /v1/receipt/proof/{seq}. The entry's
	// receipt-inclusion proof (the third cosigned-root leg of a
	// v2 self-anchored proof), bound to the first cosigned
	// checkpoint covering the seq.
	ReceiptProof http.HandlerFunc

	// ── Burn status ────────────────────────────────────────
	// Burn — GET /v1/burn. The network's observed equivocation
	// (burn) status as a fetched fact, for the v2 proof's
	// burn_attestation. Reads gossip equivocation findings; never
	// a constant.
	Burn http.HandlerFunc

	// ── Index queries ───────────────────────────────────────
	CosignatureOf http.HandlerFunc
	TargetRoot    http.HandlerFunc
	SignerDID     http.HandlerFunc
	SchemaRef     http.HandlerFunc
	// DelegateDID — GET /v1/query/delegate_did/{did}. Returns
	// live entries whose Header.DelegateDID matches; consumers
	// (judicial-network, multi-network shims) build their own
	// projections off this read primitive.
	DelegateDID http.HandlerFunc
	Scan        http.HandlerFunc

	// ── Admission info ───────────────────────────────────────
	Difficulty      http.HandlerFunc // GET /v1/admission/difficulty
	AdmissionPolicy http.HandlerFunc // GET /v1/admission/policy
	MMD             http.HandlerFunc // GET /v1/admission/mmd

	// ── Gossip (optional) ──────────────────────────────────────
	GossipPost http.Handler
	GossipFeed http.Handler

	// EscrowOverride mounts at POST /v1/escrow-override.
	EscrowOverride http.HandlerFunc

	// Metrics mounts at GET /metrics.
	Metrics http.Handler

	// ── Read endpoints ───────────────────────────────────────
	EntryBySequence http.HandlerFunc
	EntryBatch      http.HandlerFunc
	EntryByHash     http.HandlerFunc
	EntryHashBatch  http.HandlerFunc // POST /v1/entries-hash/batch (Part II.3)
	EntryRaw        http.HandlerFunc
	SMTLeaf         http.HandlerFunc
	SMTLeafBatch    http.HandlerFunc
	CommitmentQuery http.HandlerFunc

	// CommitmentLookup serves
	//   GET /v1/commitments/by-split-id/{schema_id}/{hex}
	// the cryptographic-commitment lookup endpoint backed by the
	// pure-CQRS read-side projection (Badger 0x0C).
	CommitmentLookup http.HandlerFunc

	// ArtifactReserve serves POST /v1/artifacts/reserve — the RESERVE phase of the
	// artifact upload protocol (ledger#193): admit an artifact-genesis entry and
	// return an upload token. nil => route not mounted.
	ArtifactReserve http.HandlerFunc

	// ReservationFinish serves POST /v1/artifacts/{cid}/finish — the FINISH phase
	// of the artifact upload protocol (ledger#193). nil => route not mounted.
	ReservationFinish http.HandlerFunc

	// ── Static-CT tile serving (optional) ──────────────────────────
	// Checkpoint serves GET /checkpoint — the c2sp.org/tlog-tiles
	// signed checkpoint Tessera writes after each integration
	// cycle. Auditors fetch this to anchor inclusion proofs.
	Checkpoint http.HandlerFunc

	// Tile serves GET /tile/{level}/{rest...} — RFC c2sp.org/
	// tlog-tiles hash tiles. The handler dispatches internally
	// when {level} == "entries" to the entry-bundle path so the
	// stdlib mux's pattern coverage stays unambiguous.
	Tile http.HandlerFunc

	// Horizon serves GET /v1/tree/horizon — the latest published
	// witness-cosigned tree head (CosignedTreeHead: SMTRoot + K-of-N
	// signatures), served verbatim from the published checkpoint object.
	// The read-front anchor for as-of SMT proofs; clients re-verify the
	// quorum out-of-band. CDN-frontable.
	Horizon http.HandlerFunc

	// CheckpointArchive serves GET /v1/tree/checkpoint/{size} — the cosigned head
	// archived at a SPECIFIC tree size, served verbatim from the object store
	// (PG-free). The auditor's anchor for cold-seq inclusion. Mounted iff a
	// checkpoint-archive reader is configured.
	CheckpointArchive http.HandlerFunc

	// ── Public introspection endpoints (G5/G6 zero-trust shape) ─────
	// LogInfo serves GET /v1/log-info — public deployment posture
	// (LogDID, NetworkID, witness set, byte-store + tile backend,
	// gossip enabled, TLS enabled). Auditor-facing surface; pairs
	// with /checkpoint as the public-truth artifacts of this log.
	// Cache-Control: public, max-age=60.
	LogInfo http.HandlerFunc

	// Version serves GET /version — build provenance (version,
	// git commit, build time, SDK version pin). Public + cacheable.
	// Auditors verify "which binary served me this proof".
	// Cache-Control: public, max-age=3600.
	Version http.HandlerFunc

	// NetworkPeers serves GET /v1/network/peers — the federation
	// graph (Part II.10). Returns the current-state index of this
	// log's parent, siblings, root + historical parents. Consumed
	// by the SDK's log/discover.FetchFederationGraph (plan §I.20a).
	// Cache-Control: public, max-age=300.
	NetworkPeers http.HandlerFunc

	// NetworkBootstrap serves GET /v1/network/bootstrap — the
	// JCS-canonical BootstrapDocument bytes that hashed to produce
	// the NetworkID. Part II.1. Cache-Control: public,
	// max-age=31536000, immutable.
	NetworkBootstrap http.HandlerFunc

	// NetworkIdentity serves GET /v1/network/identity — the four
	// identifier forms derived from the BootstrapDocument
	// (network_id, network_uuid, network_did, bootstrap_hash).
	// Part II.1. Cache-Control: public, max-age=31536000,
	// immutable.
	NetworkIdentity http.HandlerFunc

	// NetworkMirrors serves GET /v1/network/mirrors — the
	// MirrorManifest enumerating mirror URLs serving this log's
	// content-addressed artifacts. Part II.1. Cache-Control:
	// public, max-age=300.
	NetworkMirrors http.HandlerFunc

	// WitnessesCurrent serves GET /v1/network/witnesses/current —
	// the currently-active witness set + set_hash + effective_seq.
	// Part II.1. Cache-Control: public, max-age=60.
	WitnessesCurrent http.HandlerFunc

	// WitnessesBySetHash serves
	// GET /v1/network/witnesses/{set_hash} — content-addressable
	// historical lookup. Part II.1. Cache-Control: public,
	// max-age=31536000, immutable.
	WitnessesBySetHash http.HandlerFunc

	// WitnessesAtSeq serves GET /v1/network/witnesses/at/{seq} —
	// time-travel by log tree size. Part II.1. Cache-Control:
	// public, max-age=31536000, immutable.
	WitnessesAtSeq http.HandlerFunc

	// NetworkAnchors serves GET /v1/network/anchors — the
	// AnchorChain enumerating parent logs onto which THIS log's
	// heads have been anchored. Part II.1. Cache-Control:
	// public, max-age=300.
	NetworkAnchors http.HandlerFunc

	// AnchorsBySource serves GET /v1/network/anchors/by-source/{log_did} —
	// one read-page of the cosigned-anchor entries the named CHILD log has
	// anchored into THIS log. DISCOVERY, NOT AUTHORITY: consumers re-verify
	// inclusion + parent quorum from the returned bytes; an anchor this
	// projection misses fails toward alarm, never false compliance.
	AnchorsBySource http.HandlerFunc

	// NetworkLabels serves GET /v1/network/labels — materialized
	// projection of on-log WitnessIdentityLabelV1 entries.
	// v1.32.0 SDK adoption. NOT AUTHORITATIVE; the on-log walk
	// via network.ResolveWitnessLabelAt is canonical. Cache-
	// Control: public, max-age=60.
	NetworkLabels http.HandlerFunc

	// NetworkAuditors serves GET /v1/network/auditors —
	// materialized projection of on-log AuditorRegistrationV1
	// entries. v1.32.0 SDK adoption. NOT AUTHORITATIVE; the on-
	// log walk via network.ResolveAuditorAt is canonical. Cache-
	// Control: public, max-age=60.
	NetworkAuditors http.HandlerFunc

	// NetworkWitnessEndpoints serves GET /v1/network/witness-
	// endpoints — materialized projection of on-log
	// WitnessEndpointDeclarationV1 entries. v1.32.0 SDK adoption.
	// NOT AUTHORITATIVE; the on-log walk via
	// network.ResolveWitnessEndpointsAt is canonical. Cache-
	// Control: public, max-age=60.
	NetworkWitnessEndpoints http.HandlerFunc

	// Bundle serves GET /v1/bundle/{seq}?smt_key=hex — the
	// baseproof-bundle/v1 wire format assembled from this binary's
	// in-process composition of BootstrapDocument + entry bytes +
	// CosignedTreeHead + InclusionProof + SMTProof +
	// WitnessSetHint. Part II.1. Cache-Control: public,
	// max-age=31536000, immutable (content-deterministic once
	// the cosigned head is published).
	Bundle http.HandlerFunc
}

// -------------------------------------------------------------------------------------------------
// 3) Construction
// -------------------------------------------------------------------------------------------------

// NewServer creates the HTTP server with all routes and middleware
// applied. Returns a non-nil *Server even when handlers is the
// zero value (every route is nil-guarded).
func NewServer(
	cfg ServerConfig,
	sessions middleware.SessionLookup,
	handlers Handlers,
	logger *slog.Logger,
) *Server {
	s := &Server{cfg: cfg, logger: logger}
	s.ready.Store(true)
	s.writable.Store(true) // writes enabled until a divergence degrades us

	mux := http.NewServeMux()

	// ── Health checks ────────────────────────────────────────────────────────
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !s.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("shutting down"))
			return
		}
		// Optional subsystem probe (e.g., DB circuit breaker).
		// When set + erroring, return 503 with the probe's
		// error message so administrators see the specific subsystem
		// that flipped readiness.
		if probe := s.readinessProbe.Load(); probe != nil && *probe != nil {
			if err := (*probe)(); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// ── Submission — full middleware chain (write-gated) ───────────────
	if handlers.Submission != nil {
		submissionChain := s.writeGate(middleware.SizeLimit(
			cfg.MaxEntrySize+1024,
			middleware.Auth(sessions, handlers.Submission),
		))
		mux.Handle("POST /v1/entries", submissionChain)
	}

	// ── Batch submission — async, returns SCTs (write-gated) ───────────
	if handlers.BatchSubmission != nil {
		batchChain := s.writeGate(middleware.SizeLimit(
			AbsoluteMaxBatchPayloadBytes+1024,
			middleware.Auth(sessions, handlers.BatchSubmission),
		))
		mux.Handle("POST /v1/entries/batch", batchChain)
	}

	if handlers.MMD != nil {
		mux.HandleFunc("GET /v1/admission/mmd", handlers.MMD)
	}

	// ── Tree head + proofs (read-only) ────────────────────────────────
	if handlers.TreeHead != nil {
		mux.HandleFunc("GET /v1/tree/head", handlers.TreeHead)
	}
	if handlers.TreeInclusion != nil {
		mux.HandleFunc("GET /v1/tree/inclusion/{seq}", handlers.TreeInclusion)
	}
	if handlers.TreeConsistency != nil {
		mux.HandleFunc("GET /v1/tree/consistency/{old}/{new}", handlers.TreeConsistency)
	}
	if handlers.Horizon != nil {
		mux.HandleFunc("GET /v1/tree/horizon", handlers.Horizon)
	}
	if handlers.CheckpointArchive != nil {
		mux.HandleFunc("GET /v1/tree/checkpoint/{size}", handlers.CheckpointArchive)
	}

	// ── SMT proofs (read-only) ────────────────────────────────────
	if handlers.SMTProof != nil {
		mux.HandleFunc("GET /v1/smt/proof/{key}", handlers.SMTProof)
	}
	if handlers.SMTBatchProof != nil {
		// Bounded — SMT batch proofs are JSON request/response.
		mux.Handle("POST /v1/smt/batch_proof",
			middleware.SizeLimit(MaxSMTBatchPayloadBytes+1024, http.HandlerFunc(handlers.SMTBatchProof)))
	}
	if handlers.SMTRoot != nil {
		mux.HandleFunc("GET /v1/smt/root", handlers.SMTRoot)
	}

	// ── Receipt proof (read-only) ─────────────────────────────────
	if handlers.ReceiptProof != nil {
		mux.HandleFunc("GET /v1/receipt/proof/{seq}", handlers.ReceiptProof)
	}

	// ── Burn status (read-only) ───────────────────────────────────
	if handlers.Burn != nil {
		mux.HandleFunc("GET /v1/burn", handlers.Burn)
	}

	// ── Query endpoints (read-only) ─────────────────────────────────
	if handlers.CosignatureOf != nil {
		mux.HandleFunc("GET /v1/query/cosignature_of/{pos}", handlers.CosignatureOf)
	}
	if handlers.TargetRoot != nil {
		mux.HandleFunc("GET /v1/query/target_root/{pos}", handlers.TargetRoot)
	}
	if handlers.SignerDID != nil {
		mux.HandleFunc("GET /v1/query/signer_did/{did}", handlers.SignerDID)
	}
	if handlers.SchemaRef != nil {
		mux.HandleFunc("GET /v1/query/schema_ref/{pos}", handlers.SchemaRef)
	}
	if handlers.DelegateDID != nil {
		mux.HandleFunc("GET /v1/query/delegate_did/{did}", handlers.DelegateDID)
	}
	if handlers.Scan != nil {
		mux.HandleFunc("GET /v1/query/scan", handlers.Scan)
	}

	if handlers.AdmissionPolicy != nil {
		mux.HandleFunc("GET /v1/admission/policy", handlers.AdmissionPolicy)
	}
	if handlers.Difficulty != nil {
		mux.HandleFunc("GET /v1/admission/difficulty", handlers.Difficulty)
	}

	// ── Gossip endpoints (optional) ─────────────────────────────────
	if handlers.GossipPost != nil {
		mux.Handle("POST /v1/gossip",
			middleware.SizeLimit(MaxGossipPostBytes+1024, handlers.GossipPost))
	}
	if handlers.GossipFeed != nil {
		mux.Handle("GET /v1/gossip/sth/latest", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/since", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/by-kind", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/event/{eventID}", handlers.GossipFeed)
		mux.Handle("GET /v1/gossip/by-binding/{hash}", handlers.GossipFeed)
	}
	if handlers.EscrowOverride != nil {
		mux.Handle("POST /v1/escrow-override",
			middleware.SizeLimit(MaxEscrowOverrideBytes+1024, http.HandlerFunc(handlers.EscrowOverride)))
	}

	if handlers.Metrics != nil {
		mux.Handle("GET /metrics", handlers.Metrics)
	}

	// ── Entry read endpoints (nil-guarded) ────────────────────────────
	if handlers.EntryBySequence != nil {
		mux.HandleFunc("GET /v1/entries/{sequence}", handlers.EntryBySequence)
	}
	if handlers.EntryBatch != nil {
		mux.HandleFunc("GET /v1/entries/batch", handlers.EntryBatch)
	}
	if handlers.EntryByHash != nil {
		mux.HandleFunc("GET /v1/entries-hash/{hashHex}", handlers.EntryByHash)
	}
	if handlers.EntryHashBatch != nil {
		mux.HandleFunc("POST /v1/entries-hash/batch", handlers.EntryHashBatch)
	}
	if handlers.EntryRaw != nil {
		mux.HandleFunc("GET /v1/entries/{sequence}/raw", handlers.EntryRaw)
	}

	if handlers.SMTLeaf != nil {
		mux.HandleFunc("GET /v1/smt/leaf/{key}", handlers.SMTLeaf)
	}
	if handlers.SMTLeafBatch != nil {
		mux.Handle("POST /v1/smt/leaves",
			middleware.SizeLimit(MaxSMTLeavesPayloadBytes+1024, http.HandlerFunc(handlers.SMTLeafBatch)))
	}

	if handlers.CommitmentQuery != nil {
		mux.HandleFunc("GET /v1/commitments", handlers.CommitmentQuery)
	}
	if handlers.CommitmentLookup != nil {
		mux.HandleFunc(
			"GET /v1/commitments/by-split-id/{schema_id}/{hex}",
			handlers.CommitmentLookup,
		)
	}
	if handlers.ArtifactReserve != nil {
		mux.HandleFunc("POST /v1/artifacts/reserve", handlers.ArtifactReserve)
	}
	if handlers.ReservationFinish != nil {
		mux.HandleFunc("POST /v1/artifacts/{cid}/finish", handlers.ReservationFinish)
	}

	// ── Static-CT tile serving (optional) ────────────────────────────
	// External auditors fetch the canonical c2sp.org/tlog-tiles
	// endpoints to reconstruct inclusion + consistency proofs
	// independently. Path-traversal defense lives inside the
	// handler (api/tile_handler.go).
	if handlers.Checkpoint != nil {
		mux.HandleFunc("GET /checkpoint", handlers.Checkpoint)
	}
	if handlers.Tile != nil {
		// Single dispatcher captures both /tile/{level}/{...} and
		// /tile/entries/{...}. The handler routes internally so we
		// avoid stdlib-mux specificity collisions.
		mux.HandleFunc("GET /tile/{level}/{rest...}", handlers.Tile)
	}

	// ── Public introspection (G5/G6 zero-trust shape) ────────────────
	// /version + /v1/log-info. Mounted nil-guarded; cmd/ledger
	// wires them at boot. Both PUBLIC + cacheable — the ledger is
	// zero-trust by design (L-1 dumb ledger, T-6 zero-trust dual
	// verification): anything an SRE needs to debug is also
	// something an auditor needs to verify. Operational-only
	// tunables (pool sizes, internal paths) are NOT exposed here;
	// they live in the boot banner log + pprof private listener.
	if handlers.Version != nil {
		mux.HandleFunc("GET /version", handlers.Version)
	}
	if handlers.LogInfo != nil {
		mux.HandleFunc("GET /v1/log-info", handlers.LogInfo)
	}
	if handlers.NetworkPeers != nil {
		mux.HandleFunc("GET /v1/network/peers", handlers.NetworkPeers)
	}
	if handlers.NetworkBootstrap != nil {
		mux.HandleFunc("GET /v1/network/bootstrap", handlers.NetworkBootstrap)
	}
	if handlers.NetworkIdentity != nil {
		mux.HandleFunc("GET /v1/network/identity", handlers.NetworkIdentity)
	}
	if handlers.NetworkMirrors != nil {
		mux.HandleFunc("GET /v1/network/mirrors", handlers.NetworkMirrors)
	}
	if handlers.WitnessesCurrent != nil {
		mux.HandleFunc("GET /v1/network/witnesses/current", handlers.WitnessesCurrent)
	}
	if handlers.WitnessesAtSeq != nil {
		// /at/{seq} MUST come BEFORE /{set_hash} in pattern
		// registration order? Go's net/http uses pattern specificity,
		// not registration order — /at/{seq} is strictly more
		// specific than /{set_hash} because "at" is a literal segment.
		// Safe to register either order.
		mux.HandleFunc("GET /v1/network/witnesses/at/{seq}", handlers.WitnessesAtSeq)
	}
	if handlers.WitnessesBySetHash != nil {
		mux.HandleFunc("GET /v1/network/witnesses/{set_hash}", handlers.WitnessesBySetHash)
	}
	if handlers.NetworkAnchors != nil {
		mux.HandleFunc("GET /v1/network/anchors", handlers.NetworkAnchors)
	}
	if handlers.AnchorsBySource != nil {
		mux.HandleFunc("GET /v1/network/anchors/by-source/{log_did}", handlers.AnchorsBySource)
	}
	if handlers.NetworkLabels != nil {
		mux.HandleFunc("GET /v1/network/labels", handlers.NetworkLabels)
	}
	if handlers.NetworkAuditors != nil {
		mux.HandleFunc("GET /v1/network/auditors", handlers.NetworkAuditors)
	}
	if handlers.NetworkWitnessEndpoints != nil {
		mux.HandleFunc("GET /v1/network/witness-endpoints", handlers.NetworkWitnessEndpoints)
	}
	if handlers.Bundle != nil {
		mux.HandleFunc("GET /v1/bundle/{seq}", handlers.Bundle)
	}

	// -------------------------------------------------------------------------------------------------
	// 4) Cross-cutting middleware
	// -------------------------------------------------------------------------------------------------
	//
	// Every request gets a correlation ID. Wraps the entire mux
	// (after route registration) so health checks, write paths,
	// and read paths all carry the same X-Request-ID surface.
	// OTel SERVER span wraps the mux directly: it EXTRACTS the caller's
	// traceparent (continuing one cross-component trace) and starts the
	// admission span that the handlers' wal.Submit captures into the WAL for the
	// async downstream stages to resume. Placed INSIDE WithRequestID so the mux
	// sets r.Pattern in place for the span's low-cardinality route name (outer
	// middleware that clones the request via WithContext would hide it).
	root := middleware.WithRequestID(sdklog.NewOTelHandler(mux))

	// D3 — Request duration histogram. Outermost wrap so
	// authn + every other middleware is included in the
	// measurement. route="*" — when callers want per-route
	// breakdown they can mount the middleware around a specific
	// handler; here we use a wildcard label rather than echoing
	// r.URL.Path (which would explode label cardinality).
	root = RequestDurationMiddleware("*", root)

	// -------------------------------------------------------------------------------------------------
	// 5) http.Server with DoS-immune timeouts
	// -------------------------------------------------------------------------------------------------

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           root,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, // Slowloris cap
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout, // keep-alive zombie cap
		BaseContext:       func(_ net.Listener) context.Context { return context.Background() },
		// TLSConfig is populated by ListenAndServeTLS on first call;
		// plain HTTP leaves it nil.
		TLSConfig: nil,
	}

	return s
}

// -------------------------------------------------------------------------------------------------
// 6) Lifecycle
// -------------------------------------------------------------------------------------------------

// ListenAndServe starts the HTTP server in plaintext mode.
// Blocks until error or shutdown.
//
// Production deployments that terminate TLS in a sidecar / proxy
// (most k8s deployments) call ListenAndServe. Deployments that
// terminate TLS in the binary call ListenAndServeTLS instead.
func (s *Server) ListenAndServe() error {
	s.logger.Info("HTTP server starting", "addr", s.httpServer.Addr, "tls", false)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// ListenAndServeTLS starts the HTTP server with TLS termination
// in the binary. cfg.TLSCertFile / cfg.TLSKeyFile MUST be non-
// empty; otherwise returns an immediate error.
//
// HTTP/2 is explicitly enabled by populating
// TLSConfig.NextProtos with "h2" + "http/1.1" before
// ListenAndServeTLS runs. http.Server's automatic-HTTP/2-over-TLS
// path is conditional on a nil-or-default NextProtos; setting it
// explicitly is the documented opt-in for predictable ALPN
// negotiation across deployment lanes (and lets administrators audit
// the wire-protocol surface in code, not in framework defaults).
func (s *Server) ListenAndServeTLS() error {
	if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
		return fmt.Errorf("api/server: ListenAndServeTLS requires TLSCertFile + TLSKeyFile")
	}
	tlsCfg, err := s.buildServerTLSConfig()
	if err != nil {
		return err
	}
	if s.httpServer.TLSConfig == nil {
		s.httpServer.TLSConfig = tlsCfg
	}
	s.logger.Info("HTTP server starting (TLS)",
		"addr", s.httpServer.Addr,
		"tls", true,
		"mtls", s.httpServer.TLSConfig.ClientAuth == tls.RequireAndVerifyClientCert,
		"alpn", s.httpServer.TLSConfig.NextProtos,
	)
	if err := s.httpServer.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// Serve starts the HTTP server on the given listener. The cmd/
// orchestrator uses this when wrapping the listener in
// netutil.LimitListener for a connection cap.
func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info("HTTP server starting", "addr", ln.Addr().String())
	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// ServeTLSWithListener starts the HTTP server with TLS termination
// on the supplied listener — typically a netutil.LimitListener
// wrapping the raw net.Listener so the connection cap applies to
// TLS-terminated traffic too.
//
// HTTP/2 is explicitly enabled by populating TLSConfig.NextProtos
// with "h2" + "http/1.1" before ServeTLS runs. http.Server's
// automatic-HTTP/2-over-TLS path is conditional on a nil-or-
// default NextProtos; setting it explicitly is the documented
// opt-in for predictable ALPN negotiation across deployment lanes
// (and lets administrators audit the wire-protocol surface in code,
// not in framework defaults).
func (s *Server) ServeTLSWithListener(ln net.Listener) error {
	if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
		return fmt.Errorf("api/server: ServeTLSWithListener requires TLSCertFile + TLSKeyFile")
	}
	tlsCfg, err := s.buildServerTLSConfig()
	if err != nil {
		return err
	}
	if s.httpServer.TLSConfig == nil {
		s.httpServer.TLSConfig = tlsCfg
	}
	s.logger.Info("HTTP server starting (TLS)",
		"addr", ln.Addr().String(),
		"tls", true,
		"mtls", s.httpServer.TLSConfig.ClientAuth == tls.RequireAndVerifyClientCert,
		"alpn", s.httpServer.TLSConfig.NextProtos,
	)
	if err := s.httpServer.ServeTLS(ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api/server: %w", err)
	}
	return nil
}

// buildServerTLSConfig constructs the *tls.Config for the ledger's
// TLS listener. MinVersion is pinned to TLS 1.3; ALPN is pinned to
// {h2, http/1.1} for predictable negotiation across deployment lanes.
//
// Zero-trust posture: the ledger is a PUBLIC transparency substrate.
//   - ClientCAFile EMPTY → open HTTPS (ClientAuth = NoClientCert). Reads
//     are open (transparency); writes are gated CRYPTOGRAPHICALLY by
//     admission + the in-body G5 WriteAuthorization signature, NOT by the
//     transport. This is the ZT default: trust per-operation cryptography,
//     not a network perimeter.
//   - ClientCAFile SET → opt-in mTLS (RequireAndVerifyClientCert) for a
//     deliberately gated edge. Not the ledger's own posture; provided for
//     deployments that front a non-public listener.
//
// Returns an error only if a configured ClientCAFile is unreadable or
// contains no parseable certificates.
func (s *Server) buildServerTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		ClientAuth: tls.NoClientCert,
	}
	if s.cfg.ClientCAFile == "" {
		return cfg, nil // open HTTPS — writes gated by crypto (admission + G5), reads open
	}
	caPEM, err := os.ReadFile(s.cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("api/server: read ClientCAFile %q: %w", s.cfg.ClientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("api/server: ClientCAFile %q contains no parseable certificates", s.cfg.ClientCAFile)
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = pool
	return cfg, nil
}

// SetReady controls the /readyz response. Pass false BEFORE
// Shutdown to flip readiness so load balancers remove the pod
// from rotation, then wait for the pre-drain grace period
// before calling Shutdown. Returns the previous value.
func (s *Server) SetReady(ready bool) bool {
	return s.ready.Swap(ready)
}

// SetWritable toggles the admission (write) gate. The supervisor calls
// SetWritable(false) on a proven integrity divergence: the ledger DEGRADES to
// read-only — POST /v1/entries(/batch) return 503, every read/proof endpoint
// keeps serving the last witness-cosigned state, and the process stays alive for
// operator reconciliation instead of crash-looping. Returns the previous value.
func (s *Server) SetWritable(writable bool) bool {
	prev := s.writable.Swap(writable)
	if !writable {
		s.logger.Error("ADMISSION DEGRADED: writes suspended (503); reads continue. " +
			"Trigger: integrity divergence. Operator must reconcile and restart.")
	}
	return prev
}

// writeGate wraps the admission (write) handlers and returns 503 while the
// ledger is degraded (read-only). Reads are never gated. This is the structural
// guarantee that no client write can drive the process down: a divergence flips
// writes off, it does not panic the binary.
func (s *Server) writeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.writable.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"ledger degraded: integrity divergence detected; ` +
				`writes suspended (read-only). Operator reconciliation required."}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SetReadinessProbe installs an optional subsystem-readiness
// probe consulted on every /readyz request. Returning nil keeps
// readiness OK; returning an error flips /readyz to 503 with
// the error message in the body. Pass nil to clear the probe.
//
// cmd/ledger wires the DB circuit breaker here so a tripped
// breaker pulls the pod from the load balancer until the breaker
// half-open probe succeeds.
func (s *Server) SetReadinessProbe(probe func() error) {
	if probe == nil {
		s.readinessProbe.Store(nil)
		return
	}
	s.readinessProbe.Store(&probe)
}

// Shutdown gracefully shuts down the server. Drains in-flight
// requests within ctx's deadline; forces close after.
func (s *Server) Shutdown(ctx context.Context) error {
	s.ready.Store(false)
	s.logger.Info("HTTP server shutting down")
	return s.httpServer.Shutdown(ctx)
}
