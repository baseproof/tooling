// Package deps holds AppDeps — the single struct that carries every
// allocated I/O handle and wired component across the ledger binary's
// three lifecycle phases (alloc, wire, teardown).
//
// FILE PATH:
//
//	cmd/ledger/boot/deps/deps.go
//
// DESCRIPTION:
//
//	One struct to keep the binary's runtime state together, plus a
//	tiny closer-stack that records, in registration order, every
//	resource opened by alloc.Allocate. The boot phases hand the same
//	*AppDeps pointer to each other:
//
//	  ┌── alloc ──┐    ┌── wire ──┐    ┌── teardown ──┐
//	  │ open      │ →  │ compose  │ →  │ run + close  │
//	  │ resources │    │ goroutine│    │ in spec      │
//	  │           │    │ graph    │    │ order        │
//	  └───────────┘    └──────────┘    └──────────────┘
//	         ↓ on err walks                    ↑
//	         closeStack reverse                shutdownChain.Add
//	         (boot-failure unwind)             reads closeStack
//
//	The split eliminates the sync.OnceFunc double-wrapping pattern
//	main.go used to need: closure-defers were panic-safety against
//	the interleaved boot+wiring path. Here, alloc owns its own
//	failure unwind (UnwindReverse), and teardown owns the clean
//	shutdown — the two paths are isolated by phase, so no closer
//	ever needs to defend against being called from two places.
//
// KEY ARCHITECTURAL DECISIONS:
//
//   - One AppDeps. Not feature-decomposed substructs. The whole
//     ledger has roughly 25 I/O handles + wired components; a
//     single struct is auditable in one read. Per-feature substructs
//     would tangle dependencies without making any cleaner.
//
//   - Closers tracked separately. closeStack is a small []namedCloser
//     so teardown can transcribe it into the lifecycle.ShutdownChain
//     in registration order. Adding a closer is the *only* thing
//     alloc does that survives into teardown.
//
//   - Goroutine lifecycles via ctx, not Close. The builder loop,
//     sequencer, shipper, anchor publisher, gossip anti-entropy
//     scanner — all cancel cleanly when the parent ctx fires. They
//     do NOT have Close methods to register; teardown's job is to
//     cancel ctx, then close I/O after goroutines have observed
//     the cancellation. The closeStack is for I/O only.
//
//   - No locking on closeStack. Alloc is single-goroutine (sequential
//     resource opens). Once alloc returns, callers MUST NOT mutate
//     closeStack — wire and teardown only read it. That's enforced
//     by convention (the slice is not exposed; only AppendCloser
//     and TakeClosers are public).
//
//   - AppDeps is concrete, not an interface. Test-doubling is via
//     constructing an AppDeps with fakes in its handle fields,
//     which works because the type is concrete and field access
//     is package-public to the boot subpackages.
package deps

import (
	"context"
	"crypto/ecdsa"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"

	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkcryptosigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	sdkschema "github.com/baseproof/baseproof/schema"
	"github.com/baseproof/baseproof/storage"

	"go.opentelemetry.io/otel/metric"

	"github.com/baseproof/tooling/services/ledger/anchor"
	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/api/middleware"
	"github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/gossipnet"
	"github.com/baseproof/tooling/services/ledger/gossipstore"
	"github.com/baseproof/tooling/services/ledger/lifecycle"
	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/reservation"
	"github.com/baseproof/tooling/services/ledger/sequencer"
	"github.com/baseproof/tooling/services/ledger/shipper"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/tessera"
	"github.com/baseproof/tooling/services/ledger/wal"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// NamedCloser is one entry in the closeStack: a Close function plus
// the spec-order name + per-component timeout the lifecycle.
// ShutdownChain consumes when teardown registers it.
type NamedCloser struct {
	Name    string
	Timeout time.Duration
	Close   func(ctx context.Context) error
}

// AppDeps is the binary's runtime state. Every field is populated by
// alloc.Allocate (resource handles) or wire.Wire (composed
// components). teardown.Register reads from it; main reads from it
// to access the running HTTP server + goroutine join channels.
type AppDeps struct {
	// ── Logger + cancellation ─────────────────────────────────────
	// The process-wide logger. Set by main before any boot phase
	// runs. Each phase reads from it; never reassigned.
	Logger *slog.Logger

	// Fatal is the supervisor's panic-surfacing channel. Background
	// goroutines wired in Phase B send to it on unrecoverable
	// errors; main reads from it in the supervisor select.
	Fatal chan error

	// ── Phase A: I/O handles ──────────────────────────────────────
	// These have a Close method. Each open registers a NamedCloser
	// onto closeStack so Phase C can register it with the
	// ShutdownChain in spec order.

	PgPool          *store.Pool
	WALDB           *badger.DB
	WALCommitter    *wal.Committer
	ByteStore       bytestore.Backend
	TesseraEmbedded *tessera.EmbeddedAppender
	TileBackend     *tessera.POSIXTileBackend
	TileReader      *tessera.TileReader
	Antispam        *tposixantispam.AntispamStorage
	GossipStore     *gossipstore.BadgerStore // nil when gossip disabled
	// BuilderLock is owned exclusively by alloc — the closer
	// captures the local handle directly. Not held on AppDeps
	// because no other phase reads it.
	DBBreaker *store.Breaker

	// ── Phase A: identities + signers (no Close; cross all phases) ─

	// LedgerSignerPriv is the secp256k1 ECDSA key the ledger uses to
	// sign its own commentary entries. LedgerDID is the did:key:z…
	// derived from its public key; it equals cfg.LedgerDID at the
	// composition root.
	LedgerSignerPriv *ecdsa.PrivateKey
	LedgerDID        string
	// TesseraSigner is consumed by tessera.NewEmbeddedAppender at
	// construction; the appender holds the only reference. Not
	// held on AppDeps because no other phase reads it.

	// NetworkID echoes cfg.NetworkID for downstream consumers
	// (gossip wiring, cosign client) without re-reading config.
	NetworkID cosign.NetworkID

	// ── Phase A: telemetry handles ────────────────────────────────

	// MeterProvider + GossipMeter are nil when LEDGER_METRICS_ENABLE
	// is false. MetricsHandler is nil under the same condition.
	MeterProvider  metric.MeterProvider
	GossipMeter    metric.Meter
	MetricsHandler http.Handler

	// ── Phase B: wired components ─────────────────────────────────

	EntryStore     *store.EntryStore
	CreditStore    *store.CreditStore
	CommitStore    *store.CommitmentStore
	LeafStore      *store.PostgresLeafStore
	NodeStore      *store.TailedNodeStore // de-polluted: tiles + in-memory tail, NOT jellyfish_nodes
	TreeHeadStore  *store.TreeHeadStore
	SMTRootState   *store.SMTRootStateStore
	DiffController *middleware.DifficultyController
	BuilderLoop    *builder.BuilderLoop
	Sequencer      *sequencer.Sequencer
	Shipper        *shipper.Shipper
	// RecentEntryCache is the in-process recent-entry cache (F1) shared
	// by the sequencer (post-commit Put) and every PostgresEntryFetcher
	// reader (builder + API handlers). Allocated once at Wire(), nil-safe
	// (nil disables the fast lane; the durable PG+bytestore path is
	// always correct). Sized via Config.RecentEntryCacheSize.
	RecentEntryCache store.RecentEntryCache

	// RecentEntryCacheMetrics is the OTel-callback registration for the
	// F1 cache instruments. Closed during teardown to unregister the
	// callback — prevents leaked callbacks under hot-reload paths that
	// recycle the meter provider. nil when metrics are disabled OR the
	// cache itself is disabled.
	RecentEntryCacheMetrics io.Closer
	AnchorPublisher         *anchor.Publisher
	GossipBundle            *gossipnet.Bundle       // nil when gossip disabled
	GossipPublisher         *gossipnet.STHPublisher // nil when gossip disabled

	// QuorumManager is the single source of truth for the active
	// witness key set, seeded once at wire time (PG-latest-or-genesis)
	// and shared by all three cosignature consumers: the admission
	// BLS-quorum verifier, the equivocation monitor (readers, via
	// Current) and the RotationHandler (writer, via Update). The
	// shared atomic.Pointer is what makes a witness rotation visible to
	// every consumer at once — no stale boot-time copies. nil when the
	// genesis witness set + NetworkID prerequisites aren't met.
	QuorumManager *quorum.Manager

	// WitnessSchemeTag is the active witness signature scheme recorded
	// alongside QuorumManager's seed set (1=ECDSA). Handed to the
	// RotationHandler so its emitted rotation events carry the right
	// scheme.
	WitnessSchemeTag byte

	// RotationHandler processes witness-set rotations: cryptographic
	// Verify against the current set → DB persistence → atomic swap of
	// QuorumManager → broadcast the KindWitnessRotation gossip event
	// (closes baseproof v0.6.0 Asymmetric Witness-Set Rotation gap). nil
	// when the genesis witness set + NetworkID + GossipStore
	// prerequisites aren't met; the handler is otherwise instantiated
	// and ready for callers (rotation-initiating admin paths) to invoke.
	RotationHandler *witnessclient.RotationHandler

	// BurnProcessor is the single chokepoint for the network-burn ceremony
	// door (POST /v1/network/burn): quorum-verify under the current set →
	// on-log append → flip the declared-burn state GET /v1/burn serves. nil
	// when the sequencing pipeline is unwired (the door is then unmounted,
	// matching RotationHandler's fail-closed posture). tooling#110.
	BurnProcessor *witnessclient.BurnProcessor

	// WitnessEndpointResolver is the on-log authoritative
	// witness-endpoint discovery surface used by wireWitnessCosigner
	// to drop the LEDGER_WITNESS_ENDPOINTS backdoor — typically a
	// *discover.DefaultAuthoritativeResolver from the SDK. When nil,
	// the witness cosigner falls back to LEDGER_WITNESS_ENDPOINTS
	// (the legacy canary path).
	//
	// v1.32.0 SDK adoption: this field is the wire-up for SDK plan
	// item L1 (close the silent-URL-substitution backdoor on witness
	// discovery). cmd/ledger/boot/wire constructs the resolver in
	// wireWitnessEndpointResolver (gossip.go) at the same boot beat
	// as the SignaturePolicy + AdmissionPolicy resolvers — all three
	// share the on-log-walker pattern (see
	// admission/onlog_signature_policy.go).
	WitnessEndpointResolver witnessclient.WitnessEndpointResolver

	// AuditorRegistryRecords is the on-log AuditorRegistrationV1
	// record slice used by the inbound gossip auditor-scope gate
	// (gossipnet/auditor_scope_gate.go) — populated at boot from a
	// QueryAPI scan and refreshed at the same TTL cadence as
	// SignaturePolicy. Empty slice ⇒ scope gating denies every
	// finding, which is the high-assurance default; operators
	// onboarding auditors MUST publish AuditorRegistrationV1
	// entries on-log before findings will be ingested.
	//
	// v1.32.0 SDK adoption: this field is the wire-up for SDK plan
	// item L2 (close the auditor-scope backdoor on inbound gossip
	// findings).
	AuditorRegistrySource func(ctx context.Context) ([]network.AuditorRegistrationRecord, error)

	// AuditorAmendmentSource returns the on-log
	// AuditorScopeAmendmentV1 records the AuditorScopeGate merges with
	// the registration stream when resolving an auditor's effective
	// scope at a position. v1.33.0 (Gap 2): networks publish
	// lightweight Scope changes without re-issuing a full
	// AuditorRegistration. Wired in cmd/ledger/boot/wire/wire.go from
	// the same *discover.DefaultAuthoritativeResolver instance that
	// backs AuditorRegistrySource. nil ⇒ "no amendment schema bound"
	// — the gate treats the amendment stream as empty.
	AuditorAmendmentSource func(ctx context.Context) ([]network.AuditorScopeAmendmentRecord, error)

	// PeerAdmissionURLResolver returns the parent log's current
	// admission URL via on-log FederationGraph lookup — typically
	// a thin closure over
	// *discover.DefaultAuthoritativeResolver.ResolvePeer (the SDK
	// log/discover.AuthoritativeResolver method). Wired in
	// cmd/ledger/boot/wire/wire.go at the same boot beat as
	// WitnessEndpointResolver; the same *DefaultAuthoritativeResolver
	// instance backs both fields.
	//
	// v1.32.0 SDK adoption: this field is the wire-up for SDK plan
	// item L5 (close the parent-admission-URL backdoor on cross-log
	// anchor publishing — same backdoor shape as L1 but cross-log
	// instead of within-log).
	//
	// nil ⇒ wire/wire.go falls back to cfg.ParentAdmissionURL (the
	// legacy canary path), preserving operability during the
	// bootstrap window before any FederationGraph entry has been
	// admitted.
	PeerAdmissionURLResolver anchor.PeerAdmissionURLResolver

	// L3 fetcher adapters (api.*Fetcher interfaces) used to serve
	// /v1/network/labels, /v1/network/auditors,
	// /v1/network/witness-endpoints. Populated at boot by
	// wireV1_32Resolver (cmd/ledger/boot/wire/wire.go) when the
	// LEDGER_*_SCHEMA env vars are set; nil ⇒ the corresponding
	// handler returns 404 ("walker not configured").
	WitnessLabelsFetcher    api.WitnessLabelFetcher
	AuditorRegistryFetcher  api.AuditorRegistryFetcher
	WitnessEndpointsFetcher api.WitnessEndpointsFetcher

	// SchemaRegistry is the baseproof v0.4.0 DI schema admission
	// registry. Built once at wire time via
	// schemareg.BuildLedgerSchemaRegistry and consumed by both
	// the api submission handler (front-door admission gate) and
	// the sequencer (post-AppendLeaf SplitID dispatch). Single
	// instance is the audit guarantee: an auditor reading
	// schemareg.BuildLedgerSchemaRegistry sees the full schema
	// list this deployment admits, and both consumers route
	// through the same frozen Registry.
	SchemaRegistry *sdkschema.Registry

	// HTTPServer is the *api.Server wrapper — exposes Shutdown +
	// SetReady. Stdlib http.Server lives inside it; teardown calls
	// HTTPServer.Shutdown.
	HTTPServer *api.Server
	// HTTPListener is the netutil.LimitListener-wrapped listener
	// the HTTP server runs on. Held so teardown can close it
	// directly if Shutdown's drain misbehaves.
	HTTPListener net.Listener

	// HTTPTLSEnabled mirrors (cfg.TLSCertFile != "" && cfg.TLSKeyFile
	// != "") so the http-server goroutine knows which Serve method
	// to call without re-reading the original config.
	HTTPTLSEnabled bool

	// OutboundHTTPClient is the single *http.Client used by every
	// outbound HTTPS hop this binary makes — anchor cross-publish,
	// witness cosign POSTs, gossip peer pulls. When the operator
	// sets LEDGER_PEER_CLIENT_CERT_FILE + LEDGER_PEER_CLIENT_KEY_FILE,
	// it carries the configured client cert (TLS 1.3 floor); when both
	// are empty, the field stays nil and each caller falls back to the
	// SDK's default client (legacy posture). One client, built once,
	// pooled across all outbound surfaces — same lifetime as the binary.
	OutboundHTTPClient *http.Client

	// v1.37.0 Tier 2: EIP-1271 (smart-contract-wallet) wiring.
	//
	// EthereumRPC is the single Ethereum JSON-RPC client constructed
	// at boot when LEDGER_ETH_RPC_ENABLED=true. Nil when disabled (the
	// default). Used as the underlying transport for ExecutorClients
	// when EIP-1271 is enabled — but only when LEDGER_EIP1271_ENABLED=true
	// AND at least 2 executor endpoints are configured.
	EthereumRPC sdkcryptosigs.EthereumRPCClient

	// PKHVerifierOptions is the parsed EIP-1271 config. Zero-value
	// (Enabled=false / fields all zero) means EOA-only mode at the
	// did:pkh admission path — the production default. Populated only
	// when LEDGER_EIP1271_ENABLED=true with K>=2 executors. wire.go
	// passes this directly to did.DefaultVerifierRegistry.
	PKHVerifierOptions sdkdid.PKHVerifierOptions

	// ArchiveReader fetches entries from archived (frozen) shards
	// (cold storage). nil when LEDGER_ARCHIVE_SHARD_INDEX_SOURCE is
	// unset (the default). When set, Wire loads the shard index and
	// constructs an ArchiveReader carrying OutboundHTTPClient (so
	// mTLS-fronted archive endpoints work the same as peer-ledger
	// fetches).
	//
	// CURRENT STATE: constructed but not yet routed through the
	// builder's EntryFetcher composite — that wiring is the next step
	// in the cold-storage product. The Config field is plumbed so
	// production deployments that pre-stage shard indexes have a
	// reachable code path RIGHT NOW; switching the read path is a
	// strictly additive follow-up that doesn't churn the boot graph.
	ArchiveReader *lifecycle.ArchiveReader

	// SubmitHandler is the api.NewSubmissionHandler return value — the
	// admission HTTP handler. Wired by composeHandlers (Wire step 8);
	// captured by anchor.SubmitInProcess (Wire step 7) via a closure
	// that reads this field at call time. Reading-before-set returns a
	// clear "submit handler not yet wired" error rather than a nil-deref.
	//
	// This field replaces the previous http://localhost loopback self-
	// submit URL — loopback over HTTP fails under binary-terminated TLS
	// (the listener won't accept plain HTTP), and over HTTPS it requires
	// a localhost-SAN-bearing server cert that production deployments
	// don't carry. In-process call sidesteps both: same admission code,
	// no network.
	SubmitHandler http.Handler

	// ArtifactContentStore is the single content-addressed store shared by the
	// derivation-commitment publisher (the #190 off-log mutation blobs) and the
	// ReservationManager (docket-artifact uploads). One instance so the
	// in-memory dev/test fallback doesn't diverge between the two paths; posix /
	// http backends point at the same dir / service regardless.
	ArtifactContentStore storage.ContentStore

	// ReservationManager runs the artifact upload RESERVE/UPLOAD/FINISH/REAP
	// lifecycle (ledger#193). nil when the artifact-store feature is unwired.
	ReservationManager *reservation.Manager

	// PprofServer is nil when pprof is disabled.
	PprofServer *http.Server

	// WG joins every long-running goroutine started in Phase B
	// (HTTP server, builder loop, sequencer, shipper, etc.).
	// teardown waits on this group as part of the
	// "background-goroutines" shutdown step.
	WG sync.WaitGroup

	// ── closeStack — owned by Phase A, transcribed by Phase C ────
	closeStack []NamedCloser
}

// AppendCloser pushes a NamedCloser onto the stack in registration
// order. The stack is consumed by teardown.Register in the same
// order, then drained.
//
// Allocators call this after every successful resource open. The
// caller's pattern is:
//
//	pool, err := store.InitPool(...)
//	if err != nil { return deps.UnwindReverse(...); err }
//	deps.PgPool = pool
//	deps.AppendCloser(deps.NamedCloser("postgres", 30*time.Second, ...))
func (d *AppDeps) AppendCloser(c NamedCloser) {
	d.closeStack = append(d.closeStack, c)
}

// TakeClosers returns the close stack in REGISTRATION order and
// resets it to nil. Called by teardown.Register exactly once. The
// reset matters: it makes a second teardown attempt a no-op (the
// stack is empty) so a panic during teardown can't double-close.
func (d *AppDeps) TakeClosers() []NamedCloser {
	out := d.closeStack
	d.closeStack = nil
	return out
}

// UnwindReverse calls every NamedCloser.Close in REVERSE registration
// order, with the supplied ctx as parent for each per-component
// budget. Used by alloc.Allocate when an open fails part-way through
// — every previously-opened resource is closed before the error
// propagates to main.
//
// Errors from individual closes are logged via deps.Logger (with the
// resource name) but do not abort the unwind. Best-effort: the goal
// is to release fds + flush state, not to surface a clean error.
//
// After UnwindReverse returns, closeStack is reset; subsequent
// teardown.Register calls find nothing to register (correct: alloc
// failure means no shutdown chain ever runs).
func (d *AppDeps) UnwindReverse(ctx context.Context) {
	for i := len(d.closeStack) - 1; i >= 0; i-- {
		c := d.closeStack[i]
		// Per-component bounded ctx: the same budget the
		// ShutdownChain would have used.
		cctx, cancel := context.WithTimeout(ctx, c.Timeout)
		if err := c.Close(cctx); err != nil && d.Logger != nil {
			d.Logger.Warn("alloc unwind: close error",
				"step", c.Name, "error", err)
		}
		cancel()
	}
	d.closeStack = nil
}
