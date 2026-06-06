/*
FILE PATH: api/entries_read.go

Entry fetch-by-position endpoints. Three routes:

	GET /v1/entries/{seq}             → JSON metadata (no bytes)
	GET /v1/entries/batch?start&count → JSON list of metadata
	GET /v1/entries/{seq}/raw → wire bytes
	                                     200 OK inline (un-shipped)
	                                     302 Found redirect (shipped)

THE 302 ROUTE — design summary:

	Under WAL-first admission, an entry's wire bytes live in one of
	two places at any moment:
	  - the WAL (local NVMe, fast) — for pending/sequenced/manual
	    states AND for shipped entries within the GC retention window
	  - the byte store (network, GCS/S3) — for shipped entries past
	    the GC retention window

	Serving inline from the ledger (proxy-mode) for shipped entries
	doubles the egress bandwidth — the ledger reads from GCS, then
	re-streams to the consumer. At 10B+ entries × ~1 MB each, this is
	petabytes of pointless re-transfer. The 302 redirect cuts the
	ledger out of the byte path entirely: the consumer's HTTP client
	follows Location: <public URL> and fetches directly from the
	byte store. The transparency-log convention (RFC 9162,
	c2sp.org/tlog-tiles) makes the bucket anonymous-read by design;
	the hash-suffixed key shape lets consumers statically verify the
	URL points at the promised bytes before fetching.

	Routing decision matrix (computed inside the handler):

	  Postgres entry_index WAL meta state Outcome
	  ─────────────────────────   ─────────────────   ──────────────────
	  no row at seq —                   404
	  row at seq StateSequenced 200 + wal.Read
	  row at seq StateManual 200 + wal.Read
	  row at seq StatePending 200 + wal.Read *defensive*
	  row at seq StateShipped 302 + public URL
	  row at seq wal.ErrNotFound 302 + public URL *post-GC*
	  row at seq transport error 500
	  no PublicURLer configured + StateShipped/post-GC 500 *misconfig*

	The handler is opaque to envelope structure — wire bytes go out
	raw. Consumers feed the response body to envelope.Deserialize and
	recover signatures via entry.Signatures.

KEY ARCHITECTURAL DECISIONS:
  - JSON-metadata endpoint (NewEntryBySequenceHandler) keeps its
    existing shape — backward-compatible for clients that only want
    the canonical_hash + log_time + signer_did.
  - Raw-bytes endpoint (NewRawEntryHandler) is the WAL-aware route.
  - Decoupled WAL surface: EntryWALReader and PublicURLer are
    interfaces; *wal.Committer satisfies the former, *bytestore.GCS
    or *bytestore.S3 satisfy the latter.
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/apitypes"
	"github.com/baseproof/tooling/services/ledger/wal"
)

// ─────────────────────────────────────────────────────────────────────
// Interfaces
// ─────────────────────────────────────────────────────────────────────

// EntryFetcher fetches a single entry by log position.
// Satisfied by store.PostgresEntryFetcher.
type EntryFetcher interface {
	Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// EntryWALReader is the WAL surface the raw-bytes handler needs.
// *wal.Committer satisfies it.
type EntryWALReader interface {
	Read(ctx context.Context, hash [32]byte) ([]byte, error)
	MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error)
}

// SeqHashLookup resolves seq → canonical_hash + log_time via Postgres entry_index.
// *store.EntryStore satisfies it.
type SeqHashLookup interface {
	FetchHashBySeq(ctx context.Context, seq uint64) ([32]byte, time.Time, bool, bool, error)
	FetchPrimarySeqByHash(ctx context.Context, hash [32]byte) (uint64, bool, error)
}

// PublicURLer issues credential-free URLs for (seq, hash) tuples.
// The transparency-log architecture has only one read path: every
// bucket is anonymous-read, every 302 returns a public URL, no
// presigning, no expiry, no auth. See bytestore/publicurl.go for
// the rationale (RFC 9162, c2sp.org/tlog-tiles).
//
// bytestore.GCS and bytestore.S3 both satisfy this; nil disables
// the redirect path and the handler returns 500 on shipped
// entries (fail-closed — misconfiguration surfaces loudly rather
// than silently proxying through the WAL composite).
type PublicURLer interface {
	PublicURL(seq uint64, hash [32]byte) (string, error)
}

// EntryReadDeps holds dependencies for entry read handlers.
type EntryReadDeps struct {
	Fetcher    EntryFetcher
	QueryAPI   QueryAPI
	EntryStore SeqHashLookup
	WAL        EntryWALReader
	// PublicURLer composes the credential-free 302 target. Required
	// for the redirect path; nil → 500 on shipped entries.
	PublicURLer PublicURLer
	// SeqHashFallback resolves seq→canonical_hash from the entry tile (object
	// store) when EntryStore.FetchHashBySeq fails because Postgres is
	// unavailable. Optional: nil preserves PG-only behavior (a lookup error is a
	// 500). When set (the PG-off read front), the raw handler uses it on a
	// FetchHashBySeq error and serves bytes via the bytestore redirect — the
	// reader runs WAL==nil, so the redirect is the only serving mode regardless.
	// found=false means seq is beyond the cosigned horizon → 404.
	SeqHashFallback func(ctx context.Context, seq uint64) (hash [32]byte, found bool, err error)
	LogDID          string
	Logger          *slog.Logger
}

const maxBatchSize = 1000

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/{sequence} — JSON metadata
// ─────────────────────────────────────────────────────────────────────

// NewEntryBySequenceHandler creates GET /v1/entries/{sequence}.
// Returns metadata only (no bytes). For wire bytes use the /raw
// subroute.
func NewEntryBySequenceHandler(deps *EntryReadDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		seqStr := r.PathValue("sequence")
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid sequence number")
			return
		}

		pos := types.LogPosition{LogDID: deps.LogDID, Sequence: seq}
		entry, err := deps.Fetcher.Fetch(ctx, pos)
		if err != nil {
			deps.Logger.Error("entry fetch", "sequence", seq, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassFetcherFailed,
				http.StatusInternalServerError, "fetch failed")
			return
		}
		if entry == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "entry not found")
			return
		}

		responses := toEntryResponses([]types.EntryWithMetadata{*entry})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responses[0])
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/batch?start&count — JSON metadata list
// ─────────────────────────────────────────────────────────────────────

func NewEntryBatchHandler(deps *EntryReadDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		startStr := r.URL.Query().Get("start")
		countStr := r.URL.Query().Get("count")
		if startStr == "" || countStr == "" {
			writeTypedError(ctx, w, apitypes.ErrorClassMissingQueryParam,
				http.StatusBadRequest, "start and count parameters required")
			return
		}

		start, err := strconv.ParseUint(startStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid start parameter")
			return
		}
		count, err := strconv.ParseUint(countStr, 10, 64)
		if err != nil || count == 0 {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid count parameter")
			return
		}
		if count > maxBatchSize {
			count = maxBatchSize
		}

		entries, err := deps.QueryAPI.ScanFromPosition(start, int(count))
		if err != nil {
			deps.Logger.Error("batch entry fetch", "start", start, "count", count, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "batch fetch failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toEntryResponses(entries))
	}
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/entries/{seq}/raw — wire bytes (200 inline OR 302 redirect)
// ─────────────────────────────────────────────────────────────────────

// NewRawEntryHandler creates GET /v1/entries/{sequence}/raw.
// See file docblock for the routing decision matrix.
func NewRawEntryHandler(deps *EntryReadDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Path: /v1/entries/{seq}/raw — strip prefix + suffix
		// (path-router patterns differ between Go versions; do
		// it manually here for portability).
		path := r.URL.Path
		if !strings.HasPrefix(path, "/v1/entries/") {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "invalid path")
			return
		}
		rest := strings.TrimPrefix(path, "/v1/entries/")
		rest = strings.TrimSuffix(rest, "/raw")
		seq, err := strconv.ParseUint(rest, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid sequence")
			return
		}

		// Part II.5: X-Storage-Tier-Hint observability — the client
		// declares its expected tier so clients can adapt timeouts
		// (hot ≈ ms, warm ≈ tens-of-ms, cold ≈ seconds). The ledger
		// does NOT route on the hint; routing is determined by the
		// WAL meta-state. The response always carries X-Storage-Tier
		// describing what tier actually served, so the client can
		// reconcile expected-vs-served. The hint is logged for
		// observability so a deployment can detect chronically-
		// mis-hinting clients.
		if hint := normalizeStorageTierHint(r.Header.Get("X-Storage-Tier-Hint")); hint != "" {
			deps.Logger.DebugContext(ctx, "storage-tier hint",
				"seq", seq, "hint", hint)
		}

		// Step 1: seq → canonical_hash + log_time + isGhost via
		// Postgres entry_index.
		hash, logTime, isGhost, found, err := deps.EntryStore.FetchHashBySeq(ctx, seq)
		if err != nil {
			// Postgres entry_index unavailable. PG-off read front: fall back to
			// the entry tile (object store) for seq→hash, then serve via the
			// bytestore redirect (the reader runs WAL==nil, so redirect is the
			// only serving mode anyway).
			if deps.SeqHashFallback != nil {
				h, ok, ferr := deps.SeqHashFallback(ctx, seq)
				if ferr != nil {
					deps.Logger.Error("raw entry: tile seq lookup", "seq", seq, "error", ferr)
					writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
						http.StatusInternalServerError, "lookup failed")
					return
				}
				if !ok {
					writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
						http.StatusNotFound, "entry not found")
					return
				}
				deps.serveBytestoreRedirect(w, r, seq, h, time.Time{})
				return
			}
			deps.Logger.Error("raw entry: seq lookup", "seq", seq, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "lookup failed")
			return
		}
		if !found {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "entry not found")
			return
		}

		// Step 1b: ghost-row resolution.
		//
		// Tessera publishes a leaf at every seq it assigns, including
		// the duplicate seq produced by a pre_commit_post_pg crash
		// recovery. The corresponding entry_index row is marked
		// StatusGhostLeaf — the bytes live in the bytestore under
		// the PRIMARY seq (with the same canonical_hash). We MUST
		// route the request to the primary's path; returning 404
		// for a ghost seq would be cryptographically equivalent to
		// the operator destroying evidence (Tessera says the leaf
		// exists; the API says it doesn't).
		//
		// 302 Found → /v1/entries/{primarySeq}/raw. The client
		// re-issues the request and the second-call path serves the
		// bytes inline or via bytestore redirect. The X-Sequence
		// header on this 302 response remains the GHOST seq, so the
		// client can correlate with the Tessera tile leaf they
		// were verifying.
		if isGhost {
			primarySeq, ok, lookupErr := deps.EntryStore.FetchPrimarySeqByHash(ctx, hash)
			if lookupErr != nil {
				deps.Logger.Error("raw entry: ghost lookup", "seq", seq, "error", lookupErr)
				writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
					http.StatusInternalServerError, "ghost lookup failed")
				return
			}
			if !ok {
				// A ghost row whose primary canonical_hash row is
				// missing — should be impossible (the migration's
				// partial unique index requires a primary per
				// canonical_hash to exist when a ghost is inserted).
				// Surface as 500 so the integrity invariant
				// violation gets paged.
				deps.Logger.Error("raw entry: ghost row with no primary",
					"seq", seq, "hash", fmt.Sprintf("%x", hash[:8]))
				writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
					http.StatusInternalServerError, "ghost row missing primary")
				return
			}
			// 308 Permanent Redirect (NOT 302 Found):
			//
			// The ledger is append-only and immutable — a ghost
			// row at ghost_seq with canonical_seq=N is bound
			// FOREVER (the canonical_hash → canonical_seq mapping
			// is monotonic; the ghost can never be re-pointed). A
			// 308 signals to caches and clients that the forwarding
			// is permanent: CDN-cache for a year (matches the SDK
			// fetcher's tile-cache horizon), and clients may
			// permanently substitute the canonical URL for the
			// ghost URL in their state.
			//
			// 302 Found would let caches re-ask the ledger every
			// request — wasted roundtrips for a redirect that is
			// mathematically permanent. Per RFC 7538 §3 the
			// semantic for permanent redirects on idempotent GETs
			// is 308.
			redirectURL := fmt.Sprintf("/v1/entries/%d/raw", primarySeq)
			w.Header().Set("Location", redirectURL)
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			setRawHeaders(w, seq, hash, logTime)
			w.Header().Set("X-Source", "ghost-redirect")
			w.Header().Set("X-Primary-Sequence", strconv.FormatUint(primarySeq, 10))
			w.WriteHeader(http.StatusPermanentRedirect)
			return
		}

		// Step 2: probe WAL meta to decide route.
		// Read-only ledger (cmd/ledger-reader) has no WAL —
		// serve everything via 302 redirect to the byte store.
		// Un-shipped entries surface as bytestore 404; consumers
		// retry against the writer or wait for the Shipper to
		// migrate them.
		if deps.WAL == nil {
			deps.serveBytestoreRedirect(w, r, seq, hash, logTime)
			return
		}

		meta, metaErr := deps.WAL.MetaState(ctx, hash)
		if metaErr != nil {
			if errors.Is(metaErr, wal.ErrNotFound) {
				// Post-GC: WAL has dropped the entry. The byte store
				// is the only source of truth.
				deps.serveBytestoreRedirect(w, r, seq, hash, logTime)
				return
			}
			deps.Logger.Error("raw entry: WAL meta probe",
				"seq", seq, "hash", fmt.Sprintf("%x", hash[:8]), "error", metaErr)
			writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, "WAL probe failed")
			return
		}

		switch meta.State {
		case wal.StateSequenced, wal.StateManual, wal.StatePending:
			// Bytes still in the WAL — serve inline.
			deps.serveWALInline(w, r, seq, hash, logTime)
		case wal.StateShipped:
			// Bytes have migrated to the byte store. Redirect.
			deps.serveBytestoreRedirect(w, r, seq, hash, logTime)
		default:
			deps.Logger.Error("raw entry: unknown WAL state",
				"seq", seq, "state", meta.State)
			writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, "WAL state machine corrupted")
		}
	}
}

// normalizeStorageTierHint validates the X-Storage-Tier-Hint
// header value. Returns the canonical lowercase form for hot/warm/
// cold, or empty string for absent/invalid. Empty hints are silently
// ignored (the hint is optional). Invalid non-empty hints are
// observable via the empty return — callers can log unknowns
// distinctly. Part II.5.
func normalizeStorageTierHint(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "hot", "warm", "cold":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return ""
	}
}

// setRawHeaders writes the SDK-canonical /raw response headers:
// X-Sequence (uint64 decimal), X-Log-Time (RFC-3339Nano UTC), and
// X-Content-SHA256 (the entry's canonical hash in lowercase hex)
// — Part II.5 tamper-evidence header.
//
// The SDK's log.HTTPEntryFetcher reads X-Sequence + X-Log-Time;
// pre-Part-II.5 the ledger only stamped those two, so a consumer
// chasing a 302 redirect to the bytestore could not verify what it
// downloaded against the ledger's promise without re-running a
// hash over the bytes AND independently fetching the JSON metadata
// endpoint to learn the expected hash. The X-Content-SHA256 header
// closes that loop on every /raw response — both the 200-inline
// and 302-redirect paths — so the consumer can hash the body it
// receives and compare to the header on a single round trip.
//
// X-Log-Time is omitted (rather than stamping a zero-time string)
// when the ledger does not have a log_time on file — older
// entry_index rows pre-dating the column population may exist; the
// SDK fetcher tolerates absence with a zero-valued LogTime.
//
// X-Content-SHA256 is ALWAYS stamped: the hash is part of the
// caller-supplied URL (/v1/entries/{seq}/raw resolves to the
// canonical hash in the handler), so the value is invariably
// available.
func setRawHeaders(w http.ResponseWriter, seq uint64, hash [32]byte, logTime time.Time) {
	w.Header().Set("X-Sequence", strconv.FormatUint(seq, 10))
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(hash[:]))
	if !logTime.IsZero() {
		w.Header().Set("X-Log-Time", logTime.UTC().Format(time.RFC3339Nano))
	}
}

// serveWALInline writes the WAL's wire bytes directly to the response.
// 200 OK with Content-Type: application/octet-stream.
func (deps *EntryReadDeps) serveWALInline(w http.ResponseWriter, r *http.Request, seq uint64, hash [32]byte, logTime time.Time) {
	wire, err := deps.WAL.Read(r.Context(), hash)
	if err != nil {
		// WAL had meta but lost the entry between probe and read —
		// concurrent GC, in principle. Fall through to bytestore
		// redirect if available; otherwise 500.
		if errors.Is(err, wal.ErrNotFound) && deps.PublicURLer != nil {
			deps.serveBytestoreRedirect(w, r, seq, hash, logTime)
			return
		}
		deps.Logger.Error("raw entry: WAL read", "seq", seq, "error", err)
		writeTypedError(r.Context(), w, apitypes.ErrorClassReadProjectionFailed,
			http.StatusInternalServerError, "WAL read failed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	setRawHeaders(w, seq, hash, logTime)
	w.Header().Set("X-Source", "wal")
	// Part II.5: WAL-served bytes are the "hot" tier in the
	// storage-tier hint family — they're on local NVMe and
	// available in single-digit milliseconds. Stamp the response
	// header so callers asking with X-Storage-Tier-Hint can
	// confirm the served tier matches their hint (or learn what
	// tier they hit when they did NOT supply a hint).
	w.Header().Set("X-Storage-Tier", "hot")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(wire)
}

// serveBytestoreRedirect issues a 302 to the credential-free
// public URL composed by PublicURLer (transparency-log
// convention; see bytestore/publicurl.go).
//
// There is exactly one read path. PublicURLer is required;
// nil → 500. PublicURL returning an error → 500. The architecture
// has no private-bucket fallback — buckets are anonymous-read by
// design (RFC 9162, c2sp.org/tlog-tiles).
func (deps *EntryReadDeps) serveBytestoreRedirect(
	w http.ResponseWriter, r *http.Request,
	seq uint64, hash [32]byte, logTime time.Time,
) {
	if deps.PublicURLer == nil {
		deps.Logger.Error("raw entry: shipped entry but no PublicURLer configured",
			"seq", seq, "hash", fmt.Sprintf("%x", hash[:8]))
		writeTypedError(r.Context(), w, apitypes.ErrorClassFetcherFailed,
			http.StatusInternalServerError,
			"byte store redirect not configured")
		return
	}
	url, err := deps.PublicURLer.PublicURL(seq, hash)
	if err != nil || url == "" {
		deps.Logger.Error("raw entry: PublicURL",
			"seq", seq, "hash", fmt.Sprintf("%x", hash[:8]), "error", err)
		writeTypedError(r.Context(), w, apitypes.ErrorClassFetcherFailed,
			http.StatusInternalServerError, "public URL composition failed")
		return
	}
	w.Header().Set("Location", url)
	setRawHeaders(w, seq, hash, logTime)
	w.Header().Set("X-Source", "bytestore")
	// Part II.5: bytestore-served bytes are the "warm" tier —
	// network-attached GCS/S3, typically tens-to-hundreds of ms.
	// For genuinely cold tiers (Glacier, Archive, lifecycled to
	// deep storage), the bucket layer answers the eventual
	// follow-up GET with whatever Storage-Class header it sets;
	// the ledger reports the tier IT routes through.
	w.Header().Set("X-Storage-Tier", "warm")
	w.WriteHeader(http.StatusFound)
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time pins
// ─────────────────────────────────────────────────────────────────────

// SeqHashLookup is satisfied by api.EntryStore (see ports.go);
// the EntryStore interface declares FetchHashBySeq so any
// implementation that implements it satisfies SeqHashLookup
// transitively. The wire-time pin lives at cmd/ledger/main.go
// where *store.EntryStore is assigned into the api EntryStore
// interface field — drift in either side surfaces there.
var _ SeqHashLookup = EntryStore(nil)
