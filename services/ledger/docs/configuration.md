# Configuration

Every `LEDGER_*` variable read by `cmd/ledger/main.go::loadConfig`
(line 547–632). The ledger refuses to start if any required
variable is missing — no implicit fallback on load-bearing inputs.
Cross-field invariants are enforced by `Config.Validate()` (line
705–768) and surface as a fatal error before any subsystem is
wired.

## Required at startup

| Variable | Read at | Purpose |
|---|---|---|
| `LEDGER_DATABASE_URL` | `main.go:550` | Postgres DSN. Migrations are applied at startup |
| `LEDGER_LOG_DID` | `main.go:551` | This ledger's log identity. Every entry must have `Header.Destination == LEDGER_LOG_DID` |
| `LEDGER_BYTE_STORE_BACKEND` | `main.go:563` | `gcs` or `s3`. Anything else fails closed at `main.go:654` |

When `LEDGER_BYTE_STORE_BACKEND=gcs`:

| Variable | Read at |
|---|---|
| `LEDGER_BYTE_STORE_GCS_BUCKET` | `main.go:567` |

When `LEDGER_BYTE_STORE_BACKEND=s3`:

| Variable | Read at |
|---|---|
| `LEDGER_BYTE_STORE_S3_BUCKET` | `main.go:571` |

### Per-log object-store namespace (shared-bucket isolation)

| Variable | Default | Purpose |
|---|---|---|
| `LEDGER_BYTE_STORE_NAMESPACE` | derived from `LEDGER_LOG_DID` (`bytestore.NamespaceForLog`) | First key segment prepended to the **raw** object surface — the SMT tiles and the fixed-name `cosigned-checkpoint` horizon. Lets multiple logs share one bucket without the last writer clobbering another log's horizon. The content-addressed **entry** surface is NOT namespaced (its keys carry the SHA-256 identity and never collide), so offline readers (`ledger-reader`, `rebuild-projection`) and the 302 public URL are unaffected. The resolved value is logged at boot (`byte store ready … namespace=…`). Empty only collapses to the flat legacy layout. |

When witness mode is active — i.e., when `LEDGER_WITNESS_KEY_FILE` is
set (witness dial URLs come from on-log `WitnessEndpointDeclaration`
records, not env):

| Variable | Read at | Purpose |
|---|---|---|
| `LEDGER_NETWORK_BOOTSTRAP_FILE` | `main.go:586` | Network bootstrap definition (defines genesis witness DIDs + NetworkID) |

## Optional with defaults

### Server / identity

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_ADDR` | `:8080` | `main.go:549` |
| `LEDGER_DID` | `LEDGER_LOG_DID` | `main.go:552` (ignored if it doesn't match the loaded signer key) |
| `LEDGER_SERVICE_VERSION` | `dev` | `main.go:595` |
| `LEDGER_TLS_CERT_FILE` | (unset) | `main.go:601` |
| `LEDGER_TLS_KEY_FILE` | (unset) | `main.go:602` |
| `LEDGER_MAX_CONCURRENT_CONNS` | `0` (`0` → `8 × NumCPU`) | `main.go:603` |
| `LEDGER_PPROF_ADDR` | (unset) | `main.go:604` |
| `LEDGER_PREDRAIN_GRACE` | `5s` | `main.go:2609` (read late, during shutdown) |

### mTLS — inbound (callers → this binary)

When this binary terminates TLS itself (not behind a TLS-terminating proxy)
the listener REQUIRES mTLS — `RequireAndVerifyClientCert` + TLS 1.3. There
is no "TLS without mTLS" middle ground for binaries that own their own
listener: the JN's zero-trust contract requires every caller to authenticate
at the transport layer.

| Variable | Default | Purpose |
|---|---|---|
| `LEDGER_TLS_CERT_FILE` | (unset) | Server cert. Set together with key file to terminate TLS on the listener. |
| `LEDGER_TLS_KEY_FILE` | (unset) | Server key. Both-set or both-unset (cross-field check). |
| `LEDGER_INBOUND_CLIENT_CA_FILE` | (unset, REQUIRED when TLS is on) | PEM CA bundle that signed the certs of callers we will verify. The listener refuses to start if `LEDGER_TLS_CERT_FILE` is set but this is empty. |

Deployments fronted by a TLS-terminating proxy that enforces mTLS at the
proxy layer leave all three empty — the binary then serves plain HTTP behind
the proxy.

### mTLS — outbound (this binary → peers)

When set, the binary presents a client cert on every outbound HTTPS hop
(anchor cross-publish, witness cosign POST, gossip peer pull). Symmetric
to inbound but independent — a binary can present a client cert outbound
even when its inbound listener is plaintext behind a proxy.

| Variable | Default | Purpose |
|---|---|---|
| `LEDGER_PEER_CLIENT_CERT_FILE` | (unset) | Client cert this binary presents to peers. Set together with the key file. |
| `LEDGER_PEER_CLIENT_KEY_FILE` | (unset) | Client key. Both-set or both-unset. |
| `LEDGER_PEER_CA_FILE` | (unset → system roots) | PEM CA bundle that signs peer server certs. Pin in production to defend against MITM via a publicly-trusted but unauthorized cert. |

When the cert + key pair is unset, every outbound client falls back to the
SDK default (TLS 1.2+, server-verify-only — the legacy posture). Loading
failures are startup-fatal; the binary never silently drops a configured
client cert and calls out plaintext.

CLI tools (`backfill`, `submit-stamp`, `admission-authority`, `audit`)
accept the same surface as flags:
`-client-cert`, `-client-key`, `-ca-cert`. They ALWAYS retryhttp-wrap their
client (DNS / connection-refused / EOF retries during pod startup), with
the TLS material composing in when configured.

### Storage paths (require persistent volumes in production)

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_WAL_PATH` | `/var/lib/baseproof/wal` | `main.go:597` |
| `LEDGER_TESSERA_STORAGE_DIR` | `/var/lib/baseproof/tessera` | `main.go:559` |
| `LEDGER_TESSERA_ANTISPAM_PATH` | `/var/lib/baseproof/tessera-antispam` | `main.go:598` |

### Signer keys

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `LEDGER_TESSERA_SIGNER_KEY_FILE` | (unset) | `main.go:560` | Tessera personality signer; ephemeral if unset (logs a warning) |
| `LEDGER_SIGNER_KEY_FILE` | (unset) | `main.go:561` | Ledger signer (signs SCTs + tree heads); ephemeral if unset |
| `LEDGER_WITNESS_KEY_FILE` | (unset) | `main.go:585` | Witness cosign key. Mounting `POST /v1/cosign` requires this |
| `LEDGER_TESSERA_ORIGIN` | `LEDGER_LOG_DID` | `main.go:562` | Tessera personality origin string |

### Bytestore details

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_BYTE_STORE_PREFIX` | `entries` | `main.go:564` |
| `LEDGER_BYTE_STORE_PUBLIC_BASE_URL` | (unset) | `main.go:579` |
| `LEDGER_BYTE_STORE_GCS_ENDPOINT` | (unset → real GCS) | `main.go:568` |
| `LEDGER_BYTE_STORE_GCS_ANONYMOUS` | `false` | `main.go:569` |
| `LEDGER_BYTE_STORE_S3_ENDPOINT` | (unset → AWS S3) | `main.go:572` |
| `LEDGER_BYTE_STORE_S3_REGION` | (unset) | `main.go:573` |
| `LEDGER_BYTE_STORE_S3_ACCESS_KEY` | (unset) | `main.go:574` |
| `LEDGER_BYTE_STORE_S3_SECRET_KEY` | (unset) | `main.go:575` |
| `LEDGER_BYTE_STORE_S3_PATH_STYLE` | `false` | `main.go:576` |

### Tile serving

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_TILE_BACKEND` | `posix` | `main.go:606` |
| `LEDGER_TILE_BUCKET_PREFIX` | `tessera/` | `main.go:607` |
| `LEDGER_TILE_SERVE_DISABLE` | `false` | `main.go:605` |

### Sequencer / shipper

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_SEQUENCER_INTERVAL` | `1s` | `main.go:609` |
| `LEDGER_SEQUENCER_MAX_INFLIGHT` | `4` | `main.go:610` |
| `LEDGER_MMD` | `24h` | `main.go:611` |
| `LEDGER_SHIPPER_MAX_IN_FLIGHT` | `64` | `main.go:621` |
| `LEDGER_SHIPPER_POLL_INTERVAL` | env-default (see code) | `main.go:622` |

### Postgres pool

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_PG_MAX_CONNS` | `0` (auto: `defaultPgMaxConns(SequencerMaxInFlight)`) | `main.go:627` |
| `LEDGER_PG_STATEMENT_TIMEOUT` | `5s` (per-statement timeout via `pgxpool.AfterConnect`) | `main.go:628` |

### Gossip

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_GOSSIP_DISABLE` | `false` | `main.go:589` |
| `LEDGER_GOSSIP_PEER_ENDPOINTS` | (CSV; default empty) | `main.go:587` |
| `LEDGER_GOSSIP_PEER_DIDS` | (CSV; default empty) | `main.go:588` |

### Witness mode

Witness dial URLs are NOT configured via env. PRE-11 Phase B (#114)
deleted the `LEDGER_WITNESS_ENDPOINTS` dial-list; witness endpoints now
resolve exclusively from on-log `WitnessEndpointDeclaration` records keyed
by `LEDGER_LOG_DID`. A static env list would be the silent-URL-substitution
bypass those on-log declarations exist to close.

| Variable | Default | Read at |
|---|---|---|
| `LEDGER_WITNESS_QUORUM_K` | `1` | `main.go:584` |

### Observability

| Variable | Default | Read at | Effect |
|---|---|---|---|
| `LEDGER_METRICS_ENABLE` | **`true`** (defaults to enabled; opt-out by setting to the literal string `"false"`) | `main.go:593` | Constructs the OTel MeterProvider, mounts `GET /metrics`, installs counters/histograms |
| `LEDGER_METRICS_ENVIRONMENT` | `dev` | `main.go:594` | OTel resource attribute |
| `LEDGER_OTLP_TRACES_ENDPOINT` | (unset → NoOp tracer) | `main.go:596` | OTLP exporter; accepts `""`, `stdout`, `host:port`, `https://...` |

### Anchor (optional)

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `LEDGER_ETH_RPC_ENABLED` | `false` | `main.go:1099` (probe site; declared earlier in the same file) | EIP-1271 verification path |

### Recent-entry cache (F1)

In-process bounded FIFO cache of just-committed entries that short-circuits
the builder's hot read path. At least ONE of the two bounds MUST be positive
— both zero is a startup error (no silent unbounded cache).

| Variable | Default | Purpose |
|---|---|---|
| `LEDGER_RECENT_ENTRY_CACHE_SIZE` | `8192` | Entry-count cap. 0 disables this bound (byte cap alone governs). |
| `LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES` | `1073741824` (1 GiB) | Cumulative `CanonicalBytes` cap. The load-bearing memory bound at production scale — entry sizes vary ~100x (small attestations vs multi-sig EIP-1271 evidence). 0 disables this bound. |

Entries whose `CanonicalBytes` ALONE exceed `LEDGER_RECENT_ENTRY_CACHE_MAX_BYTES`
are REFUSED at Put (counted in the `baseproof_recent_entry_cache_rejects_total`
metric). A non-zero reject rate means `MAX_BYTES` is undersized for the
workload — bump it or investigate the upstream constructing pathologically
large entries.

### Archive reader (cold storage, optional)

Reads entries from archived (frozen) shards. Currently exposed on the
boot graph (`d.ArchiveReader`) for future composition into the builder's
EntryFetcher chain — wiring the fetcher composite is the next step in the
cold-storage product.

| Variable | Default | Purpose |
|---|---|---|
| `LEDGER_ARCHIVE_SHARD_INDEX_SOURCE` | (unset) | File path or `http(s)://` URL of the shard-index JSON. When set, Wire loads the index and constructs an `*lifecycle.ArchiveReader` with the binary's outbound mTLS client. |

The archive reader uses `d.OutboundHTTPClient` for shard byte/tile fetches,
so mTLS-fronted archive endpoints work the same as peer-ledger fetches.

## Compile-time defaults (not env-configurable)

`cmd/ledger/main.go::loadConfig` hard-codes these:

| Field | Value | Why |
|---|---|---|
| `MaxEntrySize` | 1 MiB | SDK envelope size cap |
| `BatchSize` | 1000 | Builder batch size |
| `PollInterval` | 100 ms | Builder loop tick |
| `EpochWindowSeconds` | 3600 (1h) | Mode B PoW epoch |
| `EpochAcceptanceWindow` | 1 | Accept current ± 1 epoch |
| `AnchorInterval` | 1h | External anchor publish cadence |
| `ByteStoreCacheSize` | 4096 | LRU entries |
| `TileCacheSize` | 10,000 | LRU tile entries |
| `SMTNodeCacheSize` | 100,000 | SMT node LRU |
| `DeltaWindow` | 10 | OCC commit window |

## Cross-field validation (G1)

`Config.Validate()` runs at the end of `loadConfig()` and rejects
the boot if any of these invariants is violated:

| Check | Failure mode |
|---|---|
| `LEDGER_TLS_CERT_FILE` and `LEDGER_TLS_KEY_FILE` both-set or both-unset | Half-configured TLS would silently fall back to plain HTTP |
| Both TLS files exist on disk | Misnamed path surfaces immediately |
| `LEDGER_GOSSIP_PEER_DIDS` and `LEDGER_GOSSIP_PEER_ENDPOINTS` same length | Length mismatch points at a stale env var |
| `LEDGER_TILE_BACKEND=gcs` requires `LEDGER_BYTE_STORE_BACKEND=gcs` | Tile-GCS reuses the GCS bucket handle |
| `LEDGER_TILE_BACKEND ∈ {posix, gcs}` | Typo protection |
| `LEDGER_SEQUENCER_INTERVAL`, `LEDGER_MMD`, `LEDGER_PG_STATEMENT_TIMEOUT` ≥ 0 | Negative values would invert select branches |
| `LEDGER_WITNESS_QUORUM_K > 0` when witnesses configured | 0-of-N would never finalize |
| `LEDGER_WITNESS_QUORUM_K ≤ count(on-log WitnessEndpointDeclaration records)` | Unreachable quorum (checked at HeadSync construction) |

## Quick start

```sh
export LEDGER_DATABASE_URL="postgres://ledger:secret@db:5432/baseproof"
export LEDGER_LOG_DID="did:web:ledger.example/log/main"
export LEDGER_BYTE_STORE_BACKEND=s3
export LEDGER_BYTE_STORE_S3_BUCKET=baseproof-entries
export LEDGER_BYTE_STORE_S3_REGION=us-east-1
export LEDGER_SIGNER_KEY_FILE=/etc/baseproof/ledger.key
export LEDGER_TESSERA_SIGNER_KEY_FILE=/etc/baseproof/tessera.key

# Metrics are ON by default; the only opt-out is the literal "false":
# export LEDGER_METRICS_ENABLE=false
export LEDGER_METRICS_ENVIRONMENT=production
export LEDGER_SERVICE_VERSION=$(git describe --tags)

./ledger
```

## Signer key format

`LEDGER_SIGNER_KEY_FILE` and `LEDGER_TESSERA_SIGNER_KEY_FILE` point
at PEM-encoded keys (`crypto/signatures` family). When unset, the
ledger generates an ephemeral key at boot and logs a warning —
acceptable for dev, **never for production** because every restart
issues a new identity.
