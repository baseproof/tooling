// Ledger binary configuration.
//
// FILE PATH:
//
//	cmd/ledger/config.go
//
// DESCRIPTION:
//
//	Config struct + loadConfig + Validate + the small helpers
//	(defaultPgMaxConns, buildLogInfo, networkIDHex,
//	validatePgPoolSizing, toBytestoreConfig). Extracted from
//	cmd/ledger/main.go as part of
//	the lifecycle-phase decomposition (P3): config loading + boot
//	allocation + topology wiring + teardown registration must each be
//	separable surfaces. This file owns the first.
//
//	Behaviour is unchanged from the inline version. No new fields,
//	no new validation. The split is purely organisational.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/ledger/anchor"
	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/bytestore"
)

// ─────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────

type Config struct {
	ServerAddr  string
	DatabaseURL string
	PgMaxConns  int32 // LEDGER_PG_MAX_CONNS; defaults to defaultPgMaxConns (decoupled from MaxInFlight).

	// PgStatementTimeout, when > 0, is applied via the AfterConnect
	// hook on every pool connection so EVERY query gets a DB-side
	// statement_timeout cap. Defense-in-depth on per-call-site
	// context.WithTimeout discipline. Default 5 s; 0 disables (the
	// application is then sole authority on per-query budgets).
	// Set via LEDGER_PG_STATEMENT_TIMEOUT (Go duration syntax).
	PgStatementTimeout time.Duration

	LogDID string // Destination for self-published entries (anchors, commitments).

	// LedgerDID is the ledger's single OPERATIONAL secp256k1 did:key, used in
	// TWO roles BY DESIGN — kept unified, not split:
	//   - L2 entry-author: the SignerDID on ledger-authored entries (anchor /
	//     commitment commentary), verified by admission (secp256k1-only).
	//   - L4 gossip-originator: the Originator of every gossip envelope (STH,
	//     rotation, escrow), verified by peers/auditors as a did:key.
	// Both roles are the same principal ("the ledger") on the same curve, and a
	// did:key cannot be rotated in place (replacing it mints a new identity
	// either way), so splitting would yield two un-rotatable keys with no
	// independent-rotation benefit while making /v1/log-info's ledger_did
	// ambiguous and complicating auditor trust-binding. The blast radius of the
	// key is already bounded by the K-of-N witness layer (a stolen ledger key
	// can neither forge a cosigned head nor admit an entry without witnesses).
	// Derived from the loaded signer key (see cmd/ledger/signers.go); LEDGER_DID
	// env is informational and ignored if it doesn't match.
	LedgerDID string

	// TLSCertFile / TLSKeyFile, when both non-empty, switch the
	// HTTP listener to ListenAndServeTLS. Administrator deployments
	// fronted by a TLS-terminating proxy leave both empty (plain
	// HTTP). Standalone (VM / bare-metal / sigsum-witness) administrators
	// populate both for in-binary TLS termination.
	TLSCertFile string // LEDGER_TLS_CERT_FILE
	TLSKeyFile  string // LEDGER_TLS_KEY_FILE

	// InboundClientCAFile is the PEM bundle of CA certificates allowed
	// to sign client certs presented BY callers TO this binary's
	// listener. REQUIRED when TLSCertFile/TLSKeyFile are set; the
	// listener refuses to start without it.
	//
	// Ledgers fronted by a TLS-terminating proxy that enforces mTLS
	// at the proxy layer leave TLSCertFile + TLSKeyFile +
	// InboundClientCAFile all empty — the binary serves plain HTTP
	// behind the proxy. There is no "TLS without mTLS" middle ground
	// for binaries that own their own listener: the JN's zero-trust
	// contract requires every caller to authenticate at the transport
	// layer.
	//
	// Naming note: "inbound" disambiguates this from the outbound
	// PeerCAFile (the CA that signs PEER ledgers' SERVER certs that
	// THIS binary verifies). The two CAs play opposite roles in the
	// mTLS handshake.
	InboundClientCAFile string // LEDGER_INBOUND_CLIENT_CA_FILE

	// AllowPlaintext opts out of the secure-by-default mTLS listener: by default a
	// plaintext listener (no TLSCertFile) is startup-fatal, so the ledger never
	// serves clear text by accident. Set LEDGER_ALLOW_PLAINTEXT=true for a
	// TLS-terminating-proxy / loopback-dev deployment that intentionally fronts a
	// plaintext binary.
	AllowPlaintext bool // LEDGER_ALLOW_PLAINTEXT

	// PeerClient{Cert,Key}File + PeerCAFile present a client cert + verify
	// the server cert on every outbound HTTPS hop this binary makes to
	// PEER LEDGERS — the anchor cross-publisher, the witness HEAD-sync,
	// and the gossip peer pull. Configured together (cert + key);
	// PeerCAFile is optional (empty → system roots).
	//
	// Naming note: "peer" disambiguates from "inbound client" (above).
	// PeerClientCertFile is THIS binary's client cert presented TO peers.
	// PeerCAFile is the CA that signs PEERS' server certs (the inverse
	// trust direction of InboundClientCAFile).
	//
	// Symmetric to the inbound TLS posture: a deployment that REQUIRES
	// inbound mTLS on its own listener typically PRESENTS a client cert
	// when it calls a peer ledger that mirrors the same posture. The
	// two knob groups are independent — a binary can present a client
	// cert outbound even when its inbound listener is plaintext behind
	// a proxy.
	//
	// When PeerClientCertFile + PeerClientKeyFile are both empty, every
	// outbound client falls back to the SDK default (TLS 1.2+,
	// server-verify-only — the legacy posture). No silent demotion:
	// loading errors are startup-fatal in cfg.Validate.
	PeerClientCertFile string // LEDGER_PEER_CLIENT_CERT_FILE
	PeerClientKeyFile  string // LEDGER_PEER_CLIENT_KEY_FILE
	PeerCAFile         string // LEDGER_PEER_CA_FILE

	// MaxConcurrentConns caps the total simultaneous TCP sockets
	// the public HTTP listener will accept. Defends host physics
	// (sockets, ephemeral ports, file descriptors) independent of
	// per-request body size. 0 disables the cap (NOT recommended
	// in production); the default is computed from runtime.NumCPU
	// at boot.
	MaxConcurrentConns int // LEDGER_MAX_CONCURRENT_CONNS

	// PprofAddr, when non-empty, mounts net/http/pprof on a
	// SEPARATE listener bound to the supplied address (typically
	// "127.0.0.1:6060"). pprof is NEVER mixed onto the public
	// listener — it's diagnostic surface, not user surface. Empty
	// disables pprof entirely.
	PprofAddr string // LEDGER_PPROF_ADDR

	// TileServeDisable, when true, suppresses the public Static-CT
	// tile-serving routes (GET /checkpoint, GET /tile/{level}/...).
	// Private deployments where auditors fetch via a designated
	// witness — not directly from the ledger — set this to true.
	// The default (false) serves tiles publicly so external
	// auditors can use the SDK's log/tessera_fetcher primitive
	// without bespoke ledger config.
	TileServeDisable bool // LEDGER_TILE_SERVE_DISABLE

	// TileBackend selects the tile-storage backend the /tile/ +
	// /checkpoint HTTP routes read from. One of:
	//
	//   "posix" (default) — reads from <LEDGER_TESSERA_STORAGE_DIR>.
	//                       Local POSIX I/O. Path Tessera writes
	//                       to today.
	//   "gcs"             — reads from gs://<LEDGER_BYTE_STORE_GCS_BUCKET>/
	//                       <LEDGER_TILE_BUCKET_PREFIX>/. Reuses
	//                       the entry-bytestore GCS client (one
	//                       auth surface). Suitable when Tessera
	//                       writes tiles directly to GCS or an
	//                       external sync mirrors POSIX → GCS.
	//
	// Both share the bytestore.TileBackend interface; switching
	// requires only this env var (no code change).
	TileBackend string // LEDGER_TILE_BACKEND

	// TileBucketPrefix scopes tile keys under the GCS bucket.
	// Defaults to "tessera/" so entries (under "entries/") and
	// tiles (under "tessera/") never collide in the same bucket.
	// Empty prefix means tiles at bucket root. Only consulted
	// when TileBackend=="gcs".
	TileBucketPrefix string // LEDGER_TILE_BUCKET_PREFIX

	MaxEntrySize          int64
	BatchSize             int
	PollInterval          time.Duration
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
	AnchorInterval        time.Duration
	AnchorSources         []anchor.AnchorSource

	// II.9 — parent-target anchor publishing. Populated from
	// LEDGER_PARENT_LOG_DID + LEDGER_PARENT_ADMISSION_URL +
	// LEDGER_PARENT_ANCHOR_INTERVAL. When all three are empty,
	// the parent-target flow stays disabled. Partial config logs
	// at boot but does not crash — the wire layer falls back to
	// the local-only posture.
	//
	// ParentLogDID is the parent log's DID (the anchor entry's
	// Destination so admission on the parent's side accepts it).
	//
	// ParentAdmissionURL is the parent's /v1/entries endpoint —
	// e.g., "https://parent.example/v1/entries". Recorded
	// verbatim in the anchor's LedgerEndpoint for SDK fork-
	// detection binding hashes (plan §I.13).
	//
	// ParentAnchorInterval defaults to AnchorInterval when zero —
	// independent so operators can run the two loops at
	// different rates.
	ParentLogDID         string
	ParentAdmissionURL   string
	ParentAnchorInterval time.Duration

	// II.10 — federation graph file. Operator-supplied JSON file
	// matching api.WireFederationGraph (this_log + parent +
	// siblings + root + historical_parents). Empty path leaves
	// the /v1/network/peers endpoint unconfigured (handler
	// returns 404). Loaded once at boot via loadNetworkPeers and
	// served verbatim — the file is authoritative for the index;
	// downstream callers re-verify each hop against on-log anchor
	// entries (the SDK I.20 walker's responsibility).
	NetworkPeersFile string

	// NetworkPeers is the parsed federation graph loaded from
	// NetworkPeersFile at boot. Zero value (ThisLog.LogDID == "")
	// means no file was configured; the /v1/network/peers handler
	// returns 404 in that case.
	NetworkPeers api.WireFederationGraph

	// II.1 — mirror manifest file. Operator-supplied JSON file
	// matching api.WireMirrorManifest (log_did + mirrors). Empty
	// path → /v1/network/mirrors returns 404. Same loader pattern
	// as NetworkPeersFile.
	NetworkMirrorsFile string

	// NetworkMirrors is the parsed mirror manifest loaded from
	// NetworkMirrorsFile at boot. Zero LogDID → handler 404s.
	NetworkMirrors api.WireMirrorManifest

	// PublicURL is the ledger's advertised base URL
	// (LEDGER_PUBLIC_URL), used by the GET /v1/network/bundle
	// composer as the declared ledger endpoint + bootstrap
	// endpoint. Empty ⇒ the served manifest declares no endpoint
	// addresses (consumers already know the URL they fetched it
	// from); the transport posture is derived from the scheme
	// (https ⇒ server-verify, http ⇒ plaintext).
	PublicURL string

	// ManifestAnchor optionally names the on-log network-manifest
	// anchor "<log-did>@<seq>" (LEDGER_MANIFEST_ANCHOR). When set,
	// GET /v1/network/bundle resolves the PUBLISHED manifest from
	// this ledger's own surface and reports drift against the
	// boot-composed projection. Requires PublicURL — a configured
	// anchor with nowhere to resolve it from is boot-fatal, never
	// a silent downgrade.
	ManifestAnchor string

	// II.1 — anchor chain file. Operator-supplied JSON file
	// matching api.WireAnchorChain (log_did + hops with
	// per-parent witness_set_hash + latest_anchor_seq +
	// latest_anchor_tree_size). Empty path → /v1/network/anchors
	// returns 404. The hops carry cross-log positions (seq on
	// the PARENT'S log) that this ledger does not know
	// authoritatively without parent-side queries; operator-
	// curated metadata closes the gap.

	// Sequencer settings (SCT/MMD architecture). The Sequencer
	// drains StatePending entries asynchronously; v2 admission
	// returns an SCT immediately after WAL fsync and the
	// Sequencer redeems the promise within MMD.
	SequencerInterval    time.Duration // default 1s; LEDGER_SEQUENCER_INTERVAL
	SequencerMaxInFlight int           // default 4; LEDGER_SEQUENCER_MAX_INFLIGHT
	MMD                  time.Duration // default 24h; LEDGER_MMD

	// ShipperMaxInFlight is the worker-pool size for parallel
	// bytestore uploads. Drain rate ceiling ≈ MaxInFlight ÷
	// per-upload-latency. Default 64 (10M/day capacity with
	// ~100ms GCS latency).
	// Env: LEDGER_SHIPPER_MAX_IN_FLIGHT
	ShipperMaxInFlight int

	// ShipperPollInterval is how often the scanner re-iterates
	// StateSequenced WAL entries. Should track per-upload latency
	// so the in-flight dedupe guard works efficiently. Default
	// 100ms.
	// Env: LEDGER_SHIPPER_POLL_INTERVAL
	ShipperPollInterval time.Duration

	// Phase-2 tuning knobs — exposed for 30K sustained/durability runs.
	// Defaults match the prior hardcoded behavior.
	//
	//   LEDGER_SHIPPER_MAX_ATTEMPTS    per-entry retries before StateManual (10)
	//   LEDGER_SHIPPER_BACKOFF_BASE    initial retry delay (1s)
	//   LEDGER_SHIPPER_BACKOFF_MAX     retry backoff cap (60s)
	//   LEDGER_SHIPPER_HEALTHY_WINDOW  store-healthy window for quarantine (60s)
	//   LEDGER_SHIPPER_AIMD_STEP       AIMD additive-increase step (0.5)
	//   LEDGER_CHECKPOINT_INTERVAL     checkpoint/horizon publish cadence (1s)
	//   LEDGER_WAL_QUEUE_SIZE          committer submission queue (0 ⇒ 4096)
	//   LEDGER_WAL_BATCH_MAX_ENTRIES   group-commit flush-on-count (0 ⇒ 256)
	//   LEDGER_WAL_BATCH_MAX_BYTES     group-commit flush-on-bytes (0 ⇒ 5MiB)
	//   LEDGER_WAL_BATCH_MAX_LATENCY   group-commit flush-on-age (0 ⇒ 10ms)
	ShipperMaxAttempts   int
	ShipperBackoffBase   time.Duration
	ShipperBackoffMax    time.Duration
	ShipperHealthyWindow time.Duration
	ShipperAIMDStep      float64
	CheckpointInterval   time.Duration
	WALQueueSize         int
	WALBatchMaxEntries   int
	WALBatchMaxBytes     int
	WALBatchMaxLatency   time.Duration
	WALRetentionBuffer   uint64 // LEDGER_WAL_RETENTION_BUFFER: shipped-entry GC margin (0 ⇒ GC off)
	// Tessera embedding — in-process upstream Tessera.
	// TesseraStorageDir is the POSIX directory the embedded
	// Tessera POSIX driver writes tiles, entry bundles, and the
	// checkpoint to. Ledger-reader and ledger-writer must
	// agree on this path.
	// TesseraSignerKeyFile is the path to a note.Signer private
	// key file. When empty, an ephemeral key is generated at boot
	// (with a logged warning) — fine for local dev, never for
	// production.
	// TesseraOrigin is the c2sp.org/tlog-tiles origin string
	// embedded in every signed checkpoint. Defaults to LogDID.
	TesseraStorageDir    string
	TesseraSignerKeyFile string
	TesseraOrigin        string
	// LedgerSignerKeyFile is the path to the ledger's secp256k1
	// signing key — a raw 32-byte big-endian scalar, hex-encoded
	// (NOT PEM: secp256k1 is not a stdlib x509 curve). The same
	// on-disk form cmd/genesis-ceremony dev writes via -out-ledger-key. The
	// ledger uses it to sign its own entries (anchor publisher,
	// commitment publisher). When empty, an ephemeral key is
	// generated at boot — fine for local dev, never for production.
	// The corresponding did:key is computed from the public key and
	// used as cfg.LedgerDID; LEDGER_DID is ignored if it doesn't
	// match. The same key is what admission's
	// did.NewECDSAKeyResolver verifies signatures against, so
	// the ledger's self-published anchors and commitments
	// satisfy the sig-verification path.
	LedgerSignerKeyFile string
	// TesseraAntispamPath is the BadgerDB directory backing
	// Tessera's antispam (dedup) layer. Required so re-Add via
	// integrity.Reasserter on boot returns the previously-assigned
	// seq instead of allocating a new one. Separate Badger DB
	// from cfg.WALPath — antispam is recoverable from the log
	// (Follower tails entries and rebuilds the index) so the
	// recovery story differs.
	TesseraAntispamPath string

	// Tessera integration-batcher cadence. AppendLeaf blocks until
	// the integration batch flushes; the batch flushes when EITHER
	// TesseraBatchSize entries accumulate OR TesseraBatchMaxAge
	// elapses since the first entry in the batch.
	//
	// THROUGHPUT COUPLING: the sequencer offers at most
	// SequencerMaxInFlight entries concurrently (each stage-1 worker
	// blocks on its integration future before the next is dispatched).
	// When SequencerMaxInFlight < TesseraBatchSize the batch can never
	// fill on count and always ages out — so steady-state committed
	// throughput is SequencerMaxInFlight / TesseraBatchMaxAge. The
	// default BatchMaxAge is therefore SHORT (100ms) so a low
	// in-flight degree still drains promptly; raise SequencerMaxInFlight
	// toward TesseraBatchSize to switch to the (faster) flush-on-count
	// regime under sustained load.
	// Env: LEDGER_TESSERA_BATCH_MAX_AGE, LEDGER_TESSERA_BATCH_SIZE,
	//      LEDGER_TESSERA_CHECKPOINT_INTERVAL.
	TesseraBatchMaxAge        time.Duration
	TesseraBatchSize          int
	TesseraCheckpointInterval time.Duration

	// Byte store backend selects where the ledger's entry bytes
	// live. The composition root passes
	// these directly to bytestore.NewFromConfig; per-backend
	// validation lives in the factory.
	//
	//   - "gcs" — GCS adapter. ADC credentials by default;
	//     fake-gcs-server via ByteStoreGCSEndpoint +
	//     ByteStoreGCSAnonymous.
	//   - "s3"  — S3 adapter. Default credential chain on AWS;
	//     static creds + endpoint + path-style for RustFS / R2 /
	//     other S3-compatible servers.
	//
	// "memory" is intentionally rejected at the composition root —
	// production must select a real backend. Tests that need a
	// Store-only impl call bytestore.NewMemory directly.
	ByteStoreBackend   string
	ByteStorePrefix    string // empty = "entries"
	ByteStoreNamespace string // empty = derived from the log identity (NetworkID hex)
	ByteStoreCacheSize int

	// GCS-specific.
	ByteStoreGCSBucket   string
	ByteStoreGCSEndpoint string // empty = default GCS endpoint
	ByteStoreGCSAnon     bool   // true = no auth (fake-gcs-server)

	// S3-specific.
	ByteStoreS3Bucket    string
	ByteStoreS3Endpoint  string // empty = default AWS S3 endpoint
	ByteStoreS3Region    string // empty = us-east-1 in factory
	ByteStoreS3AccessKey string // empty = default credential chain
	ByteStoreS3SecretKey string // empty = default credential chain
	ByteStoreS3PathStyle bool   // true for RustFS; false for AWS S3

	// Public-URL routing (transparency-log convention; see
	// bytestore/publicurl.go). The architecture has only one read
	// path: every bucket is anonymous-read by design (RFC 9162,
	// c2sp.org/tlog-tiles), every 302 returns a credential-free
	// public URL. There is no private-bucket / presigned fallback.
	//
	// ByteStorePublicBaseURL — explicit public-URL prefix override.
	// Empty means "use the appropriate default for the backend":
	//   gcs:               https://storage.googleapis.com/{bucket}
	//   s3 (path-style):   {endpoint}/{bucket}
	//   s3 (virtual-host): https://{bucket}.s3.{region}.amazonaws.com
	// Set explicitly to point at a CDN / custom DNS in front of the
	// bucket.
	// Env: LEDGER_BYTE_STORE_PUBLIC_BASE_URL
	ByteStorePublicBaseURL string

	// TileCacheSize is the in-memory LRU capacity (entries) for the
	// Tessera tile reader (tessera/tile_reader.go:NewTileReader). Each
	// entry holds one decoded tile; full-256 tiles are ~8 KB so the
	// default 10000 ≈ 80 MB resident. Sized for the read working set.
	//
	// Dynamic adjustment: change LEDGER_TILE_CACHE_SIZE in the
	// deployment env (Helm values → ConfigMap; docker-compose env;
	// systemd Environment=) and restart. The Helm chart's
	// checksum/configmap annotation on the Deployment forces a
	// rolling restart automatically on ConfigMap change. Reads are
	// idempotent; a cold cache only degrades latency briefly.
	//
	// Env: LEDGER_TILE_CACHE_SIZE (default 10000; values < 100
	// fall back to 10000 inside tessera.NewTileReader)
	TileCacheSize    int
	SMTNodeCacheSize int
	DeltaWindow      int

	// RecentEntryCacheSize caps the F1 cache by ENTRY COUNT. Default 8192
	// (~2× the default builder-lag bound) covers ~8 s of commits at 1k TPS.
	// 0 disables this bound — RecentEntryCacheMaxBytes alone then governs.
	// Both bounds zero ⇒ the cache is disabled entirely (every fetch takes
	// the durable path; unchanged pre-F1 behavior).
	// Env: LEDGER_RECENT_ENTRY_CACHE_SIZE
	RecentEntryCacheSize int

	// ArchiveShardIndexSource is the path or URL of the shard-index
	// JSON for cold-storage reads via lifecycle.ArchiveReader. Empty
	// (default) ⇒ archive reads disabled (only the live PG+bytestore
	// path serves entries). When set, Wire constructs an ArchiveReader
	// with the binary's outbound mTLS client (so archived shards behind
	// mTLS-required endpoints work the same as peer-ledger fetches).
	//
	// Local file path: "/etc/ledger/shards.json".
	// HTTP/HTTPS URL: "https://archive.example.com/shards.json".
	//
	// NOTE: the constructed ArchiveReader is currently exposed as
	// d.ArchiveReader for future composition into the read path —
	// wiring it INTO the builder's EntryFetcher composite (so the live
	// binary serves archived ranges) is the next step in the cold-
	// storage product. Setting this env var today makes the reader
	// available but does not yet route reads through it.
	//
	// Env: LEDGER_ARCHIVE_SHARD_INDEX_SOURCE
	ArchiveShardIndexSource string

	// RecentEntryCacheMaxBytes caps the F1 cache by CUMULATIVE bytes of
	// CanonicalBytes. The load-bearing memory bound at production scale —
	// entry size varies ~100x (small attestations vs multi-sig EIP-1271
	// evidence blobs), so an entry-count-only cap can drift to OOM under
	// worst-case admission. Default 1 GiB covers ~17 minutes of commits
	// at 1k TPS and 1KB entries; sized as a memory safety net that fires
	// before the entry-count bound under large-entry mixes. 0 disables
	// this bound — RecentEntryCacheSize alone then governs (the legacy
	// posture). Both bounds zero ⇒ cache disabled.
	// Env: LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES
	RecentEntryCacheMaxBytes int64
	// WitnessEndpoints is the comma-separated list of peer witness
	// URLs the builder loop's HeadSync requester posts cosign
	// requests to. Empty (default) → no cosignature collection;
	// the BuilderLoop tolerates a nil cosigner and emits self-
	// signed checkpoints unwitnessed.
	//
	// Local-dev "self-witness K=1" pattern: set this to the
	// ledger's own server addr (e.g. http://localhost:8080)
	// and LEDGER_WITNESS_QUORUM_K=1 plus
	// LEDGER_WITNESS_KEY_FILE — same code paths as production
	// K=N witnesses, no test-mode flag.
	WitnessEndpoints []string
	WitnessQuorumK   int

	// NetworkBootstrapFile is the path to a JSON file containing
	// the network's bootstrap document (network.BootstrapDocument).
	// Required when witness mode is active (WitnessEndpoints set)
	// — the cosign canonical-message preamble rejects a zero
	// NetworkID, so a verifier without one fails at runtime.
	// The same document MUST be loaded by every component
	// participating in the network (other ledgers, JN composer,
	// peer witnesses); cross-component signature verification
	// depends on byte-identical bootstrap inputs.
	NetworkBootstrapFile string

	// NetworkID is derived from the bootstrap document at config
	// load and threaded through to the cosign client + verifier
	// (any primitive that calls cosign.Sign/Verify). Zero (and
	// unused) when witness mode is inactive.
	NetworkID cosign.NetworkID

	// GenesisWitnessSet is the slice of witness DIDs extracted
	// from the network bootstrap document. Consumed by the
	// equivocation monitor to verify K-of-N signatures on
	// observed cosigned tree heads. Empty when witness mode is
	// inactive (no bootstrap doc loaded).
	GenesisWitnessSet []string

	// GenesisAdmissionAuthorities is the founding write-path EOA keyset from the
	// bootstrap doc (20-byte addresses). Seeds the gate-5 keyset resolver so
	// default-require gating works from genesis. nil when no bootstrap loaded.
	GenesisAdmissionAuthorities [][20]byte

	// GenesisAdmissionPolicy is the founding admission policy from the bootstrap
	// doc. Zero value (resolved to SecureDefaultPolicy) when no bootstrap loaded.
	GenesisAdmissionPolicy authz.AdmissionPolicy

	// GenesisBootstrapDocument is the parsed network.BootstrapDocument loaded
	// from LEDGER_NETWORK_BOOTSTRAP_FILE. Kept so the boot wirer can derive
	// secondary genesis surfaces from it — in v1.3 this means the
	// GenesisSignaturePolicy (Part II.6) translated via
	// admission.NewGenesisSignaturePolicyResolver. Zero value when no bootstrap
	// file is loaded; that path keeps the Part II.6 gate disabled (resolver
	// stays nil, gate is intent-vs-capability gated).
	GenesisBootstrapDocument network.BootstrapDocument

	// WALPath is the BadgerDB directory the WAL Committer opens.
	// Required for WAL-first admission (commit 10). The Shipper
	// migrates entries from this path into the byte store; the
	// integrity Detector reconciles inflight entries against
	// Tessera at boot.
	WALPath string

	// GossipPeerEndpoints is the comma-separated list of peer
	// ledger base URLs whose /v1/gossip endpoints this ledger
	// fans out to. Empty (default) → no fan-out (NopSink); the
	// gossip handler still accepts inbound publishes and serves
	// the read-side feed.
	GossipPeerEndpoints []string

	// GossipPeerDIDs is parallel to GossipPeerEndpoints — the DID
	// at index i is the peer ledger's originator DID for the
	// endpoint at index i. Required (non-empty) for the
	// anti-entropy loop to know who to ask for events from. If
	// empty, anti-entropy is disabled (the publish + feed paths
	// still work).
	GossipPeerDIDs []string

	// GossipDisable, when true, disables gossip endpoint mounting
	// and publisher wiring. Useful for read-only ledgers or
	// trimmed-down test rigs.
	GossipDisable bool

	// MetricsEnable, when true, constructs an OpenTelemetry
	// MeterProvider at boot, mounts /metrics with Prometheus
	// scrape format, and threads gossip.Instruments into the
	// gossip handler/sink for received_total, published_total,
	// verify_duration_seconds, queue_depth, and drops_total
	// observability. Off by default (zero overhead) — enable
	// per-deployment via LEDGER_METRICS_ENABLE=true.
	MetricsEnable bool

	// MetricsEnvironment is the deployment-context tag used by
	// the OTel resource attributes. Required when MetricsEnable
	// is true. Convention: "production" / "staging" / "dev".
	MetricsEnvironment string

	// ServiceVersion is the binary's git tag or build hash,
	// surfaced as the OTel resource service.version attribute.
	// Defaults to "dev" when unset.
	ServiceVersion string

	// OTLPTracesEndpoint controls D2 tracing:
	//   "" / unset      → NoOp tracer (zero overhead, default)
	//   "stdout"        → stdouttrace (laptop dev — spans to stderr)
	//   "host:port"     → OTLP HTTP exporter (Jaeger / Tempo / collector)
	//   "https://..."   → OTLP HTTP over TLS
	OTLPTracesEndpoint string
}

// decodeGenesisAdmissionAddr parses a "0x"-prefixed (or bare) 20-byte hex
// Ethereum address from a bootstrap doc's genesis admission authority list.
func decodeGenesisAdmissionAddr(s string) ([20]byte, error) {
	var addr [20]byte
	h := s
	if len(h) >= 2 && (h[0:2] == "0x" || h[0:2] == "0X") {
		h = h[2:]
	}
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 20 {
		return addr, fmt.Errorf("genesis admission authority %q is not a 20-byte hex address", s)
	}
	copy(addr[:], raw)
	return addr, nil
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ServerAddr:            listenAddr("LEDGER_ADDR", ":8080"),
		DatabaseURL:           os.Getenv("LEDGER_DATABASE_URL"),
		LogDID:                os.Getenv("LEDGER_LOG_DID"),
		LedgerDID:             os.Getenv("LEDGER_DID"),
		MaxEntrySize:          1 << 20, // 1 MB, matches SDK-D11.
		BatchSize:             1000,
		PollInterval:          100 * time.Millisecond,
		EpochWindowSeconds:    3600, // 1h — matches testEpochWindowSeconds.
		EpochAcceptanceWindow: 1,
		AnchorInterval:        1 * time.Hour,
		TesseraStorageDir:     envOr("LEDGER_TESSERA_STORAGE_DIR", "/var/lib/baseproof/tessera"),
		TesseraSignerKeyFile:  resolveFile("LEDGER_TESSERA_SIGNER_KEY_FILE", "/etc/ledger/keys/tessera-signer.pem", "/etc/secrets/tessera-signer.pem"),
		LedgerSignerKeyFile:   resolveFile("LEDGER_SIGNER_KEY_FILE", "/etc/ledger/keys/signer.pem", "/etc/secrets/signer.pem"),
		TesseraOrigin:         os.Getenv("LEDGER_TESSERA_ORIGIN"), // defaults to LogDID below
		ByteStoreBackend:      os.Getenv("LEDGER_BYTE_STORE_BACKEND"),
		ByteStorePrefix:       envOr("LEDGER_BYTE_STORE_PREFIX", "entries"),
		ByteStoreNamespace:    os.Getenv("LEDGER_BYTE_STORE_NAMESPACE"), // empty → derived in toBytestoreConfig
		ByteStoreCacheSize:    4096,
		// GCS family.
		ByteStoreGCSBucket:   os.Getenv("LEDGER_BYTE_STORE_GCS_BUCKET"),
		ByteStoreGCSEndpoint: os.Getenv("LEDGER_BYTE_STORE_GCS_ENDPOINT"),
		ByteStoreGCSAnon:     os.Getenv("LEDGER_BYTE_STORE_GCS_ANONYMOUS") == "true",
		// S3 family.
		ByteStoreS3Bucket:    os.Getenv("LEDGER_BYTE_STORE_S3_BUCKET"),
		ByteStoreS3Endpoint:  os.Getenv("LEDGER_BYTE_STORE_S3_ENDPOINT"),
		ByteStoreS3Region:    os.Getenv("LEDGER_BYTE_STORE_S3_REGION"),
		ByteStoreS3AccessKey: os.Getenv("LEDGER_BYTE_STORE_S3_ACCESS_KEY"),
		ByteStoreS3SecretKey: os.Getenv("LEDGER_BYTE_STORE_S3_SECRET_KEY"),
		ByteStoreS3PathStyle: os.Getenv("LEDGER_BYTE_STORE_S3_PATH_STYLE") == "true",
		// Public-URL routing — transparency-log convention is the
		// only read path. Optional CDN / custom-DNS override.
		ByteStorePublicBaseURL:   os.Getenv("LEDGER_BYTE_STORE_PUBLIC_BASE_URL"),
		TileCacheSize:            envIntOr("LEDGER_TILE_CACHE_SIZE", 10_000),
		SMTNodeCacheSize:         100_000,
		DeltaWindow:              10,
		RecentEntryCacheSize:     envIntOr("LEDGER_RECENT_ENTRY_CACHE_SIZE", 8192),
		RecentEntryCacheMaxBytes: envInt64Or("LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES", 1<<30), // 1 GiB default
		ArchiveShardIndexSource:  os.Getenv("LEDGER_ARCHIVE_SHARD_INDEX_SOURCE"),
		WitnessEndpoints:         parseCSV(os.Getenv("LEDGER_WITNESS_ENDPOINTS")),
		WitnessQuorumK:           envIntOr("LEDGER_WITNESS_QUORUM_K", 1),
		NetworkBootstrapFile:     resolveFile("LEDGER_NETWORK_BOOTSTRAP_FILE", "/etc/ledger/bootstrap.json", "/etc/secrets/bootstrap.json"),
		GossipPeerEndpoints:      parseCSV(os.Getenv("LEDGER_GOSSIP_PEER_ENDPOINTS")),
		GossipPeerDIDs:           parseCSV(os.Getenv("LEDGER_GOSSIP_PEER_DIDS")),
		GossipDisable:            os.Getenv("LEDGER_GOSSIP_DISABLE") == "true",
		// D1 — Metrics default ON. Disabled-by-default observability
		// is a footgun. Set LEDGER_METRICS_ENABLE=false to opt out
		// (e.g., for resource-constrained edge deployments).
		MetricsEnable:       os.Getenv("LEDGER_METRICS_ENABLE") != "false",
		MetricsEnvironment:  envOr("LEDGER_METRICS_ENVIRONMENT", "dev"),
		ServiceVersion:      envOr("LEDGER_SERVICE_VERSION", "dev"),
		OTLPTracesEndpoint:  os.Getenv("LEDGER_OTLP_TRACES_ENDPOINT"),
		WALPath:             envOr("LEDGER_WAL_PATH", "/var/lib/baseproof/wal"),
		TesseraAntispamPath: envOr("LEDGER_TESSERA_ANTISPAM_PATH", "/var/lib/baseproof/tessera-antispam"),

		// Tessera integration-batcher cadence. BatchMaxAge defaults to
		// 100ms (not the upstream 1s) so a low SequencerMaxInFlight
		// still drains promptly — see the Config field docstring for
		// the SequencerMaxInFlight × BatchSize throughput coupling.
		TesseraBatchMaxAge:        envDurationOr("LEDGER_TESSERA_BATCH_MAX_AGE", 100*time.Millisecond),
		TesseraBatchSize:          envIntOr("LEDGER_TESSERA_BATCH_SIZE", 256),
		TesseraCheckpointInterval: envDurationOr("LEDGER_TESSERA_CHECKPOINT_INTERVAL", 1*time.Second),

		// HTTP-server hardening knobs. Server TLS + outbound peer mTLS auto-mount
		// from the standard paths (and their flat /etc/secrets PaaS twins — the
		// peer-* prefix disambiguates server vs peer material in that flat dir);
		// inbound mTLS enforcement does NOT auto-mount from the cert-manager-
		// conventional ca.crt (which ships next to a server tls.crt/tls.key) — it
		// reads a DEDICATED client-ca.crt so a stray ca.crt can never silently
		// start requiring client certs.
		TLSCertFile:         resolveFile("LEDGER_TLS_CERT_FILE", "/etc/ledger/tls/tls.crt", "/etc/secrets/tls.crt"),
		TLSKeyFile:          resolveFile("LEDGER_TLS_KEY_FILE", "/etc/ledger/tls/tls.key", "/etc/secrets/tls.key"),
		InboundClientCAFile: resolveFile("LEDGER_INBOUND_CLIENT_CA_FILE", "/etc/ledger/tls/client-ca.crt", "/etc/secrets/client-ca.crt"),
		AllowPlaintext:      os.Getenv("LEDGER_ALLOW_PLAINTEXT") == "true",
		PeerClientCertFile:  resolveFile("LEDGER_PEER_CLIENT_CERT_FILE", "/etc/ledger/peer/tls.crt", "/etc/secrets/peer-tls.crt"),
		PeerClientKeyFile:   resolveFile("LEDGER_PEER_CLIENT_KEY_FILE", "/etc/ledger/peer/tls.key", "/etc/secrets/peer-tls.key"),
		PeerCAFile:          resolveFile("LEDGER_PEER_CA_FILE", "/etc/ledger/peer/ca.crt", "/etc/secrets/peer-ca.crt"),
		MaxConcurrentConns:  envIntOr("LEDGER_MAX_CONCURRENT_CONNS", 0),
		PprofAddr:           os.Getenv("LEDGER_PPROF_ADDR"),
		TileServeDisable:    os.Getenv("LEDGER_TILE_SERVE_DISABLE") == "true",
		TileBackend:         envOr("LEDGER_TILE_BACKEND", "posix"),
		TileBucketPrefix:    envOr("LEDGER_TILE_BUCKET_PREFIX", "tessera/"),

		SequencerInterval: envDurationOr("LEDGER_SEQUENCER_INTERVAL", 1*time.Second),
		// 64 in-flight stage-1 workers. Each blocks on a Tessera
		// integration future and touches NO Postgres (the singleton
		// committer is the sole PG writer), so this concurrency is
		// decoupled from the PG pool — it bounds Tessera-append
		// parallelism only. At the 100ms BatchMaxAge default this
		// sustains ~640 committed entries/s before the batch even
		// reaches its flush-on-count regime.
		SequencerMaxInFlight: envIntOr("LEDGER_SEQUENCER_MAX_INFLIGHT", 64),
		MMD:                  envDurationOr("LEDGER_MMD", 24*time.Hour),

		// Shipper drain throughput. Drain rate ceiling is approximately
		// MaxInFlight ÷ per-upload-latency (real GCS ≈ 100ms in observed
		// soak). Default 64 sustains ~640 entries/sec — comfortably above
		// the 116/sec required for 10M/day uniformly-distributed traffic
		// and the ~580/sec sustained admission rate observed under burst.
		// PollInterval=100ms aligns with per-upload latency so the in-
		// flight dedupe guard (shipper.Shipper.inflight) operates
		// efficiently — see soak telemetry: skipInflight ≈ 2× unique.
		ShipperMaxInFlight: envIntOr("LEDGER_SHIPPER_MAX_IN_FLIGHT", 64),
		ShipperPollInterval: envDurationOr("LEDGER_SHIPPER_POLL_INTERVAL",
			100*time.Millisecond),

		// Phase-2 tuning knobs (30K sustained/durability). All defaults
		// preserve prior behavior; 0 on a WAL-batch knob ⇒ committer default.
		ShipperMaxAttempts:   envIntOr("LEDGER_SHIPPER_MAX_ATTEMPTS", 10),
		ShipperBackoffBase:   envDurationOr("LEDGER_SHIPPER_BACKOFF_BASE", 1*time.Second),
		ShipperBackoffMax:    envDurationOr("LEDGER_SHIPPER_BACKOFF_MAX", 60*time.Second),
		ShipperHealthyWindow: envDurationOr("LEDGER_SHIPPER_HEALTHY_WINDOW", 60*time.Second),
		ShipperAIMDStep:      envFloatOr("LEDGER_SHIPPER_AIMD_STEP", 0.5),
		CheckpointInterval:   envDurationOr("LEDGER_CHECKPOINT_INTERVAL", 1*time.Second),
		WALQueueSize:         envIntOr("LEDGER_WAL_QUEUE_SIZE", 0),
		WALBatchMaxEntries:   envIntOr("LEDGER_WAL_BATCH_MAX_ENTRIES", 0),
		WALBatchMaxBytes:     envIntOr("LEDGER_WAL_BATCH_MAX_BYTES", 0),
		WALRetentionBuffer:   uint64(envInt64Or("LEDGER_WAL_RETENTION_BUFFER", 0)),
		WALBatchMaxLatency:   envDurationOr("LEDGER_WAL_BATCH_MAX_LATENCY", 0),

		// Pool size: env override OR derived from MaxInFlight (set
		// after we know the final MaxInFlight value below).
		PgMaxConns:         int32(envIntOr("LEDGER_PG_MAX_CONNS", 0)),
		PgStatementTimeout: envDurationOr("LEDGER_PG_STATEMENT_TIMEOUT", 5*time.Second),

		// Part II.9 parent-target anchor publishing. All three
		// fields default to empty/zero; partial config triggers a
		// boot-time warning in wire/Run but does NOT fail boot.
		ParentLogDID:         os.Getenv("LEDGER_PARENT_LOG_DID"),
		ParentAdmissionURL:   os.Getenv("LEDGER_PARENT_ADMISSION_URL"),
		ParentAnchorInterval: envDurationOr("LEDGER_PARENT_ANCHOR_INTERVAL", 0),

		// Part II.10 — federation graph file. Operator-supplied
		// JSON file matching api.WireFederationGraph. Empty path
		// leaves the /v1/network/peers endpoint unconfigured
		// (handler returns 404 with "not configured").
		NetworkPeersFile: os.Getenv("LEDGER_NETWORK_PEERS_FILE"),

		// Part II.1 — mirror manifest file. Operator-supplied
		// JSON file matching api.WireMirrorManifest.
		NetworkMirrorsFile: os.Getenv("LEDGER_NETWORK_MIRRORS_FILE"),

		// API-1 T3b — the network-bundle composer's advertised
		// base URL + optional on-log manifest anchor.
		PublicURL:      os.Getenv("LEDGER_PUBLIC_URL"),
		ManifestAnchor: os.Getenv("LEDGER_MANIFEST_ANCHOR"),

		// Part II.1 — anchor chain file. Operator-supplied JSON
		// matching api.WireAnchorChain.
	}
	if cfg.PgMaxConns == 0 {
		cfg.PgMaxConns = defaultPgMaxConns()
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("LEDGER_DATABASE_URL required")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("LEDGER_LOG_DID required (destination-binding)")
	}
	if cfg.LedgerDID == "" {
		cfg.LedgerDID = cfg.LogDID
	}
	switch cfg.ByteStoreBackend {
	case "":
		return nil, fmt.Errorf("LEDGER_BYTE_STORE_BACKEND required (gcs|s3)")
	case "gcs":
		if cfg.ByteStoreGCSBucket == "" {
			return nil, fmt.Errorf("LEDGER_BYTE_STORE_GCS_BUCKET required when LEDGER_BYTE_STORE_BACKEND=gcs")
		}
	case "s3":
		if cfg.ByteStoreS3Bucket == "" {
			return nil, fmt.Errorf("LEDGER_BYTE_STORE_S3_BUCKET required when LEDGER_BYTE_STORE_BACKEND=s3")
		}
	default:
		return nil, fmt.Errorf("LEDGER_BYTE_STORE_BACKEND=%q not supported (gcs|s3)", cfg.ByteStoreBackend)
	}
	if err := validatePgPoolSizing(cfg.PgMaxConns); err != nil {
		return nil, err
	}

	// Witness mode requires a network bootstrap document. The cosign
	// canonical-message preamble rejects a zero NetworkID; a verifier
	// without one fails at runtime. Load + derive at config-load so
	// any error surfaces with a clear cause before the ledger
	// advances any further.
	witnessActive := len(cfg.WitnessEndpoints) > 0
	if witnessActive {
		if cfg.NetworkBootstrapFile == "" {
			return nil, fmt.Errorf(
				"LEDGER_NETWORK_BOOTSTRAP_FILE required when LEDGER_WITNESS_ENDPOINTS is set")
		}
		raw, err := os.ReadFile(cfg.NetworkBootstrapFile)
		if err != nil {
			return nil, fmt.Errorf("read network bootstrap %s: %w",
				cfg.NetworkBootstrapFile, err)
		}
		// #75 Phase B — fail-closed first contact with our OWN mounted file,
		// through the SDK's self-pin door (strict decode + the genesis ceremony
		// whenever the constitution's policy requires it; baseproof#52 owns the
		// idiom and documents why the self-pin equality is vacuous). A
		// require-network bootstrap.json stripped of its endorsements REFUSES
		// BOOT here — it must never be loaded, re-served, or anchored quietly.
		verified, err := network.LoadSelfVerifiedBootstrap(raw)
		if err != nil {
			return nil, fmt.Errorf("network bootstrap %s failed first-contact verification "+
				"(stripped/incomplete genesis ceremony?): %w", cfg.NetworkBootstrapFile, err)
		}
		doc := *verified
		ids, err := doc.IDs()
		if err != nil {
			return nil, fmt.Errorf("network bootstrap %s: %w",
				cfg.NetworkBootstrapFile, err)
		}
		cfg.NetworkID = ids.NetworkID
		cfg.GenesisWitnessSet = append([]string{}, doc.GenesisWitnessSet...)

		// v1.20.0 genesis admission: the founding write-path authorities +
		// policy (NetworkID-bound). Seed the gate-5 resolvers so default-require
		// gating works from genesis. doc.IDs() already validated these.
		cfg.GenesisAdmissionAuthorities = nil
		for _, a := range doc.GenesisAdmissionAuthorities {
			addr, derr := decodeGenesisAdmissionAddr(a)
			if derr != nil {
				return nil, fmt.Errorf("network bootstrap %s: %w", cfg.NetworkBootstrapFile, derr)
			}
			cfg.GenesisAdmissionAuthorities = append(cfg.GenesisAdmissionAuthorities, addr)
		}
		cfg.GenesisAdmissionPolicy = authz.AdmissionPolicy{
			GatingRequired: doc.GenesisAdmissionPolicy.GatingRequired,
			CostMode:       authz.CostMode(doc.GenesisAdmissionPolicy.CostMode),
			FlatUnits:      doc.GenesisAdmissionPolicy.FlatUnits,
		}

		// Part II.6 — seed the SignaturePolicy gate's genesis source.
		// admission.NewGenesisSignaturePolicyResolver translates the
		// bootstrap document's GenesisSignaturePolicy into the SDK's
		// verifier.EntrySignaturePolicy shape + allow-list set, and
		// validates it (rejects malformed policy at boot). Held on
		// Config so wire.go can hand it to SubmissionDeps.
		cfg.GenesisBootstrapDocument = doc

		// rc4: GenesisQuorumK is the constitutional, NetworkID-bound quorum —
		// the single source of truth for K. Demote LEDGER_WITNESS_QUORUM_K to a
		// cross-check (see reconcileWitnessQuorumK).
		k, kErr := reconcileWitnessQuorumK(doc, cfg.NetworkBootstrapFile)
		if kErr != nil {
			return nil, kErr
		}
		cfg.WitnessQuorumK = k

		// PR-4: the anchoring cadence DERIVES from the constitutional
		// commitment (consumers derive, never restate). The publisher's
		// self-interval is computed from GenesisAnchoring.MaxIntervalSeconds;
		// the one operator knob (LEDGER_PARENT_ANCHOR_INTERVAL) demotes to a
		// cross-check — set looser than the constitutional bound is fatal.
		if aErr := reconcileAnchorCadence(doc, cfg); aErr != nil {
			return nil, aErr
		}
	}

	// Part II.10 — load the federation graph file (if any). Failure
	// here is fail-fast: a malformed file is worse than a missing
	// file. Empty path returns a zero graph (handler emits 404).
	peers, err := loadNetworkPeers(cfg.NetworkPeersFile)
	if err != nil {
		return nil, err
	}
	cfg.NetworkPeers = peers

	// Part II.1 — load the mirror manifest file (if any). Same
	// fail-fast contract.
	mirrors, err := loadNetworkMirrors(cfg.NetworkMirrorsFile)
	if err != nil {
		return nil, err
	}
	cfg.NetworkMirrors = mirrors

	// G1: cross-field validation. Anything that requires multiple
	// fields to be set together (or NOT together) is checked here.
	// Per-field "required" checks already happened above.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateMTLSRequired enforces secure-by-default transport: a plaintext listener
// (no TLS cert) is refused unless plaintext is explicitly allowed (a
// TLS-terminating proxy / loopback-dev). Pure, so it is unit-tested directly
// (cf. validatePgPoolSizing). The ledger never serves clear text by accident:
// LEDGER_ALLOW_PLAINTEXT=true is the deliberate opt-out.
func validateMTLSRequired(allowPlaintext bool, tlsCertFile string) error {
	if !allowPlaintext && tlsCertFile == "" {
		return fmt.Errorf("ledger listener is plaintext (no LEDGER_TLS_CERT_FILE): set " +
			"LEDGER_TLS_CERT_FILE + LEDGER_TLS_KEY_FILE + LEDGER_INBOUND_CLIENT_CA_FILE for the " +
			"mTLS edge, or LEDGER_ALLOW_PLAINTEXT=true for a TLS-terminating-proxy / loopback deployment")
	}
	return nil
}

// Validate runs cross-field consistency checks on a fully-loaded
// Config. Every check is fail-fast: a misconfigured deployment
// surfaces a clear, single-line error at boot instead of a
// runtime surprise.
func (cfg *Config) Validate() error {
	// TLS: cert + key must be both-set or both-unset. Half-
	// configured TLS would silently fall back to plain HTTP and
	// be an exposure surprise.
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("LEDGER_TLS_CERT_FILE and LEDGER_TLS_KEY_FILE must be both set or both unset (got cert=%q key=%q)",
			cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	if cfg.TLSCertFile != "" {
		if _, err := os.Stat(cfg.TLSCertFile); err != nil {
			return fmt.Errorf("LEDGER_TLS_CERT_FILE %q: %w", cfg.TLSCertFile, err)
		}
		if _, err := os.Stat(cfg.TLSKeyFile); err != nil {
			return fmt.Errorf("LEDGER_TLS_KEY_FILE %q: %w", cfg.TLSKeyFile, err)
		}
		// InboundClientCAFile is OPTIONAL. The ledger is a public transparency
		// substrate: with it empty the listener serves OPEN HTTPS (reads open;
		// writes gated CRYPTOGRAPHICALLY by admission + the in-body G5 signature,
		// not by the transport — the zero-trust default). Set it only for a
		// deliberately gated edge (opt-in mTLS). Validate the file when present.
		if cfg.InboundClientCAFile != "" {
			if _, err := os.Stat(cfg.InboundClientCAFile); err != nil {
				return fmt.Errorf("LEDGER_INBOUND_CLIENT_CA_FILE %q: %w", cfg.InboundClientCAFile, err)
			}
		}
	}
	if err := validateMTLSRequired(cfg.AllowPlaintext, cfg.TLSCertFile); err != nil {
		return err
	}

	// Peer (outbound) mTLS: cert + key must be both-set or both-unset.
	// Half-configured outbound mTLS would silently fall back to the
	// SDK default client (no client cert presented) — same exposure
	// surprise as the inbound side.
	if (cfg.PeerClientCertFile == "") != (cfg.PeerClientKeyFile == "") {
		return fmt.Errorf("LEDGER_PEER_CLIENT_CERT_FILE and LEDGER_PEER_CLIENT_KEY_FILE must be both set or both unset (got cert=%q key=%q)",
			cfg.PeerClientCertFile, cfg.PeerClientKeyFile)
	}
	if cfg.PeerClientCertFile != "" {
		if _, err := os.Stat(cfg.PeerClientCertFile); err != nil {
			return fmt.Errorf("LEDGER_PEER_CLIENT_CERT_FILE %q: %w", cfg.PeerClientCertFile, err)
		}
		if _, err := os.Stat(cfg.PeerClientKeyFile); err != nil {
			return fmt.Errorf("LEDGER_PEER_CLIENT_KEY_FILE %q: %w", cfg.PeerClientKeyFile, err)
		}
	}
	if cfg.PeerCAFile != "" {
		if _, err := os.Stat(cfg.PeerCAFile); err != nil {
			return fmt.Errorf("LEDGER_PEER_CA_FILE %q: %w", cfg.PeerCAFile, err)
		}
	}

	// Gossip peers: DID and endpoint slices MUST be the same
	// length so each peer has both an identity and a base URL.
	// Mismatched lengths point at a deployment misconfig where
	// one env var was forgotten or has a stale value.
	if len(cfg.GossipPeerDIDs) != len(cfg.GossipPeerEndpoints) {
		return fmt.Errorf("LEDGER_GOSSIP_PEER_DIDS (%d) and LEDGER_GOSSIP_PEER_ENDPOINTS (%d) must have the same length",
			len(cfg.GossipPeerDIDs), len(cfg.GossipPeerEndpoints))
	}

	// Tile backend: gcs requires the byte-store backend to also
	// be gcs (the GCSTiles handle reuses the *GCS bucket handle).
	if cfg.TileBackend == "gcs" && cfg.ByteStoreBackend != "gcs" {
		return fmt.Errorf("LEDGER_TILE_BACKEND=gcs requires LEDGER_BYTE_STORE_BACKEND=gcs (got %q)",
			cfg.ByteStoreBackend)
	}
	switch cfg.TileBackend {
	case "", "posix", "gcs":
	default:
		return fmt.Errorf("LEDGER_TILE_BACKEND must be one of posix|gcs (got %q)", cfg.TileBackend)
	}

	// Durations: every exposed duration MUST be positive. Zero
	// or negative values silently disable the relevant timer
	// (e.g., zero PollInterval = busy loop), which is a footgun.
	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"LEDGER_SEQUENCER_INTERVAL", cfg.SequencerInterval},
		{"LEDGER_MMD", cfg.MMD},
		{"PgStatementTimeout (LEDGER_PG_STATEMENT_TIMEOUT)", cfg.PgStatementTimeout},
	} {
		if d.v < 0 {
			return fmt.Errorf("%s must be >= 0 (got %v)", d.name, d.v)
		}
	}

	// Witness quorum K must be positive when witnesses are configured (a 0-of-N
	// quorum would never finalize a head). Under rc4 K is the constitutional
	// genesis_quorum_k (reconcileWitnessQuorumK), already >0 and 2K>N; this stays
	// as a defensive floor for the legacy no-bootstrap path.
	if len(cfg.WitnessEndpoints) > 0 && cfg.WitnessQuorumK <= 0 {
		return fmt.Errorf("witness quorum K must be > 0 when LEDGER_WITNESS_ENDPOINTS is set (got %d)",
			cfg.WitnessQuorumK)
	}
	if len(cfg.WitnessEndpoints) > 0 && cfg.WitnessQuorumK > len(cfg.WitnessEndpoints) {
		return fmt.Errorf("witness quorum K (%d) cannot exceed LEDGER_WITNESS_ENDPOINTS count (%d): "+
			"fewer endpoints than the constitutional quorum can never finalise a head",
			cfg.WitnessQuorumK, len(cfg.WitnessEndpoints))
	}

	return nil
}

// reconcileAnchorCadence derives the anchor publisher's cadence from the
// constitution's GenesisAnchoring commitment (PR-4). The commitment pins the
// MAXIMUM staleness (MaxIntervalSeconds); the publisher must run comfortably
// inside it, so the self-interval becomes clamp(bound/3, 10s, 1h) — and never
// above the bound itself. No constitutional commitment ⇒ everything stays as
// configured (the 1h operational default).
//
// LEDGER_PARENT_ANCHOR_INTERVAL is the one operator-settable cadence. Under a
// constitutional commitment it demotes to a cross-check: unset inherits the
// derived self-interval (existing publisher behavior); set within the bound is
// honored (an operator may anchor MORE often); set LOOSER than the bound is
// fatal — an off-log env var must never stretch a NetworkID-bound commitment.
func reconcileAnchorCadence(doc network.BootstrapDocument, cfg *Config) error {
	policy := doc.GenesisAnchoring
	if policy == nil {
		return nil
	}
	bound := time.Duration(policy.MaxIntervalSeconds) * time.Second
	derived := bound / 3
	if derived < 10*time.Second {
		derived = 10 * time.Second
	}
	if derived > time.Hour {
		derived = time.Hour
	}
	if derived > bound {
		derived = bound
	}
	cfg.AnchorInterval = derived
	if cfg.ParentAnchorInterval > bound {
		return fmt.Errorf("LEDGER_PARENT_ANCHOR_INTERVAL=%s is LOOSER than the constitutional "+
			"anchoring bound %s (genesis_anchoring.max_interval_seconds=%d) — an off-log env "+
			"cannot stretch a NetworkID-bound commitment; unset it or set it within the bound",
			cfg.ParentAnchorInterval, bound, policy.MaxIntervalSeconds)
	}
	return nil
}

// reconcileWitnessQuorumK derives the effective witness quorum K from the
// constitution and demotes LEDGER_WITNESS_QUORUM_K to a cross-check. Since rc4,
// genesis_quorum_k is hashed into the NetworkID — the single source of truth
// for K — so an off-log env knob must never silently override it. The three
// arms of the demotion rule:
//
//	unset            → adopt the constitutional value (doc.GenesisQuorumK)
//	set, == doc      → honoured (the operator's assertion agrees with the chain)
//	set, != doc      → fatal (the env disagrees with the identity-bound quorum)
//
// doc.IDs() (called by the caller before this) already enforced 1<=K<=N and the
// quorum-intersection invariant 2K>N, so the returned K is known-valid.
func reconcileWitnessQuorumK(doc network.BootstrapDocument, bootstrapPath string) (int, error) {
	envK, set, perr := envIntLookup("LEDGER_WITNESS_QUORUM_K")
	if perr != nil {
		return 0, perr
	}
	if set && envK != doc.GenesisQuorumK {
		return 0, fmt.Errorf(
			"LEDGER_WITNESS_QUORUM_K=%d disagrees with the constitutional genesis_quorum_k=%d in %s: "+
				"the quorum is bound into the NetworkID, so an env override cannot change it — "+
				"unset LEDGER_WITNESS_QUORUM_K to adopt the constitutional value",
			envK, doc.GenesisQuorumK, bootstrapPath)
	}
	return doc.GenesisQuorumK, nil
}

// minPgPoolConns is the hard floor the pool must clear regardless of
// tuning: the singleton committer (1) + builder loop (1) + lag/cursor
// reads + a handful of concurrent read/admission handlers. Below this,
// HTTP admission can hang on connection acquisition under even light
// concurrency.
const minPgPoolConns = 8

// defaultPgPoolSize is the LEDGER_PG_MAX_CONNS default. Sized to the
// read/admission path + background loops — see defaultPgMaxConns for
// why it is decoupled from SequencerMaxInFlight.
const defaultPgPoolSize = 32

// defaultPgMaxConns returns the default Postgres pool size.
//
// The pool is sized to Postgres's concurrency sweet spot (Postgres is
// process-per-connection and degrades past ~100-200 backends), NOT to
// SequencerMaxInFlight. The high-concurrency stage of the write
// pipeline — stage-1 (sequencer/loop.go::processOne, up to
// SequencerMaxInFlight workers) — touches NO Postgres: it uses the
// Badger WAL and Tessera only. The singleton committer
// (sequencer/committer.go) is the sole sequencer-side PG writer and
// holds exactly one connection at a time. Pool demand therefore comes
// from the read/admission path (HTTP handlers, auth/credit lookups),
// the builder loop, and the lag/cursor reads — all bounded by HTTP
// concurrency, not by SequencerMaxInFlight. Override with
// LEDGER_PG_MAX_CONNS for large hosts.
func defaultPgMaxConns() int32 {
	return defaultPgPoolSize
}

// validatePgPoolSizing enforces the boot-time invariant that the
// configured pool has enough connections to support the sequencer
// plus headroom for the rest of the ledger. Returns a clear
// error if the ledger was misconfigured — better to refuse to
// start than to have HTTP admission hang on connection acquisition
// under load.
// buildLogInfo flattens the auditor-facing subset of Config into
// the public deployment-posture payload served by GET /v1/log-info.
// SCOPE: only fields an external auditor needs to verify the log's
// trust posture. Operational tunables (PG pool sizes, statement
// timeout, internal file paths, WAL path) are intentionally absent
// — they're surfaced via the boot banner log (G7) for administrators
// to read from their log shipper.
//
// The ledger is zero-trust by design (L-1 dumb ledger, T-6
// zero-trust dual verification): there is no privileged "admin"
// surface. Anything below this filter is genuinely public —
// never any secret content, never any internal-only telemetry.
func buildLogInfo(cfg *Config) api.LogInfo {
	return api.LogInfo{
		// Identity + addressing — auditors must know which log
		// they're verifying.
		"log_did":     cfg.LogDID,
		"ledger_did":  cfg.LedgerDID,
		"network_id":  networkIDHex(cfg.NetworkID),
		"server_addr": cfg.ServerAddr,

		// Storage backend types — auditor needs to know whether
		// to fetch tiles from POSIX origin or GCS bucket.
		"byte_store_backend": cfg.ByteStoreBackend,
		"tile_backend":       cfg.TileBackend,
		"tile_bucket_prefix": cfg.TileBucketPrefix,
		"tile_serve_disable": cfg.TileServeDisable,

		// Witness topology — drives K-of-N quorum verification.
		"witness_endpoint_count": len(cfg.WitnessEndpoints),
		"witness_quorum_k":       cfg.WitnessQuorumK,

		// Gossip + transport posture.
		"gossip_enabled":    !cfg.GossipDisable,
		"gossip_peer_count": len(cfg.GossipPeerDIDs),
		"tls_enabled":       cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",
		"peer_mtls_enabled": cfg.PeerClientCertFile != "" && cfg.PeerClientKeyFile != "",

		// Sequencer cadence — affects MMD compliance window an
		// auditor evaluates.
		"sequencer_interval": cfg.SequencerInterval.String(),
		"mmd":                cfg.MMD.String(),
	}
}

// networkIDHex returns the first-8-bytes hex prefix of the
// NetworkID, suitable for log correlation. The full 32 bytes
// are not interesting in the boot banner; the prefix is enough
// to disambiguate networks at a glance and it matches the
// convention used elsewhere in the codebase.
func networkIDHex(id cosign.NetworkID) string {
	var zero cosign.NetworkID
	if id == zero {
		return ""
	}
	return fmt.Sprintf("%x", id[:8])
}

// validateTesseraStorageDir was moved to cmd/ledger/boot/alloc as
// part of P3.4 (alloc.allocateTessera owns the dir-sanity step). The
// stub here is removed; the doc-comment cross-link in package docs
// continues to reference its current home.

// validatePgPoolSizing enforces the boot-time floor on the configured
// pool. It is INTENTIONALLY independent of SequencerMaxInFlight: the
// sequencer's parallel stage-1 workers hold no Postgres connection
// (see defaultPgMaxConns), so raising SequencerMaxInFlight does not
// raise pool demand. Refusing to start on an undersized pool is better
// than hanging HTTP admission on connection acquisition under load.
func validatePgPoolSizing(maxConns int32) error {
	if maxConns < minPgPoolConns {
		return fmt.Errorf(
			"LEDGER_PG_MAX_CONNS=%d is below the minimum %d "+
				"(committer + builder + read-path headroom). "+
				"Raise LEDGER_PG_MAX_CONNS or unset it to use the safe default",
			maxConns, minPgPoolConns,
		)
	}
	return nil
}

// loadNetworkPeers reads LEDGER_NETWORK_PEERS_FILE (if set) and
// parses it into the api.WireFederationGraph shape. The empty path
// returns a zero graph (the handler treats this as "not configured"
// → 404). A malformed file fails boot — better to refuse to start
// than to silently serve a corrupt federation index.
//
// The file's wire shape mirrors the /v1/network/peers response:
// snake_case keys, hex-encoded byte arrays, omitempty on
// parent/root/siblings/historical_parents. Operators hand-edit
// or generate from a network-topology config repo.
//
// Part II.10.
func loadNetworkPeers(path string) (api.WireFederationGraph, error) {
	if path == "" {
		return api.WireFederationGraph{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return api.WireFederationGraph{},
			fmt.Errorf("LEDGER_NETWORK_PEERS_FILE: read %s: %w", path, err)
	}
	var g api.WireFederationGraph
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return api.WireFederationGraph{},
			fmt.Errorf("LEDGER_NETWORK_PEERS_FILE: parse %s: %w", path, err)
	}
	if g.ThisLog.LogDID == "" {
		return api.WireFederationGraph{},
			fmt.Errorf("LEDGER_NETWORK_PEERS_FILE: this_log.log_did required")
	}
	return g, nil
}

// loadNetworkMirrors reads LEDGER_NETWORK_MIRRORS_FILE (if set) and
// parses it into the api.WireMirrorManifest shape. Same loader
// shape as loadNetworkPeers: empty path → zero manifest; malformed
// file → fail boot.
//
// Part II.1.
func loadNetworkMirrors(path string) (api.WireMirrorManifest, error) {
	if path == "" {
		return api.WireMirrorManifest{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return api.WireMirrorManifest{},
			fmt.Errorf("LEDGER_NETWORK_MIRRORS_FILE: read %s: %w", path, err)
	}
	var m api.WireMirrorManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return api.WireMirrorManifest{},
			fmt.Errorf("LEDGER_NETWORK_MIRRORS_FILE: parse %s: %w", path, err)
	}
	if m.LogDID == "" {
		return api.WireMirrorManifest{},
			fmt.Errorf("LEDGER_NETWORK_MIRRORS_FILE: log_did required")
	}
	return m, nil
}

// toBytestoreConfig flattens the ledger config's bytestore-related
// fields into the bytestore.Config the factory expects. Per-backend
// required-field validation already happened in loadConfig; the factory
// applies the remaining defaults (prefix=entries, cache_size, region).
func (cfg *Config) toBytestoreConfig() bytestore.Config {
	bc := bytestore.Config{
		Backend:       cfg.ByteStoreBackend,
		Prefix:        cfg.ByteStorePrefix,
		Namespace:     cfg.byteStoreNamespace(),
		CacheSize:     cfg.ByteStoreCacheSize,
		PublicBaseURL: cfg.ByteStorePublicBaseURL,
	}
	switch cfg.ByteStoreBackend {
	case "gcs":
		bc.Bucket = cfg.ByteStoreGCSBucket
		bc.GCSEndpoint = cfg.ByteStoreGCSEndpoint
		bc.GCSAnonymous = cfg.ByteStoreGCSAnon
	case "s3":
		bc.Bucket = cfg.ByteStoreS3Bucket
		bc.S3Endpoint = cfg.ByteStoreS3Endpoint
		bc.S3Region = cfg.ByteStoreS3Region
		bc.S3AccessKey = cfg.ByteStoreS3AccessKey
		bc.S3SecretKey = cfg.ByteStoreS3SecretKey
		bc.S3PathStyle = cfg.ByteStoreS3PathStyle
	}
	return bc
}

// byteStoreNamespace resolves the per-log object-store namespace prepended to the
// RAW substrate surface (SMT tiles + the fixed-name cosigned-checkpoint horizon).
// An explicit LEDGER_BYTE_STORE_NAMESPACE wins; otherwise it is DERIVED from the
// log identity via the SHARED bytestore.NamespaceForLog so per-log isolation is
// the SAFE DEFAULT — two logs that share one bucket can never collide on the
// fixed-name cosigned-checkpoint (the last-writer-clobbers class) — and so every
// offline reader resolves the SAME namespace for a given log. Empty only when
// LogDID is empty (impossible after boot validation), which preserves the flat
// legacy layout.
func (cfg *Config) byteStoreNamespace() string {
	if cfg.ByteStoreNamespace != "" {
		return cfg.ByteStoreNamespace
	}
	return bytestore.NamespaceForLog(cfg.LogDID)
}
