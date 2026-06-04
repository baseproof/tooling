/*
FILE PATH: libs/clitools/ledger_client.go

DESCRIPTION:

	LedgerClient is a thin compatibility shim over the SDK's
	log.HTTPEntryFetcher (/raw → wire bytes) plus a small in-package
	GET against /v1/query/scan (ledger metadata listing). It
	preserves the legacy RawEntry shape so the aggregator (Scanner,
	Reconciler, Deserializer) keeps working while every wire call now
	flows through the SDK-canonical endpoints.

KEY ARCHITECTURAL DECISIONS:
  - SDK is the source of truth for entry-byte retrieval. FetchEntry
    delegates to log.HTTPEntryFetcher (v0.7.75): GET
    /v1/entries/{seq}/raw, auto 302-follow to bucket, X-Sequence
    and X-Log-Time response headers. The fetcher's body cap is
    enforced by the SDK with cap+1 overflow detection (BUG #3).
  - ScanFrom targets the SDK-canonical /v1/query/scan endpoint and
    mirrors the SDK's queryListResponse / queryEntryResponse JSON
    shape exactly. A future PR can swap the in-package GET for a
    direct log.HTTPLedgerQueryAPI call (one-line change); the
    current shim already produces an identical wire request.
  - Each ScanFrom row is back-filled with CanonicalBytes via the SDK
    fetcher because /v1/query/scan deliberately omits the bytes
    (egress mandate, per baseproof-ledger/api/queries.go).
  - Connection pooling and 503-Retry-After backpressure come from
    the SDK's log.DefaultClient — every fetcher in the process
    shares the tuned transport.
  - Backwards compatibility: NewLedgerClient(url) still works;
    the optional logDID variadic arg lets callers (the cmd/main
    wiring) pass cfg.CasesLogDID. Without a logDID, ScanFrom returns
    a clear error rather than silently scanning the wrong log.

OVERVIEW:

	NewLedgerClient(baseURL [, logDID])
	FetchEntry(seq) → *RawEntry            (SDK HTTPEntryFetcher)
	ScanFrom(start, count) → []RawEntry    (/v1/query/scan + per-row Fetch)
	TreeHead() → map[string]any            (passthrough)

KEY DEPENDENCIES:
  - baseproof/log: HTTPEntryFetcher, DefaultClient
  - baseproof/types: EntryWithMetadata, LogPosition
*/
package clitools

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/httpmw/reliability"
)

// defaultLedgerTimeout caps every ledger round-trip (incl. SDK
// 503-Retry-After replays). Matches the prior hand-rolled value.
const defaultLedgerTimeout = 15 * time.Second

// maxScanResponseBytes caps the metadata response body. Sized for a
// 1000-row response (~1 KiB per row) with headroom; matches the SDK's
// pending HTTPLedgerQueryAPI cap.
const maxScanResponseBytes = 16 << 20

// LedgerClient adapts the SDK's HTTP fetcher (and a thin scan
// helper) to the legacy RawEntry API consumed by tools/aggregator.
// Read-only.
type LedgerClient struct {
	baseURL string
	logDID  string
	fetcher *sdklog.HTTPEntryFetcher
	httpc   *http.Client
}

// NewLedgerClient creates a non-mTLS client backed by the SDK fetcher.
// logDID populates types.LogPosition.LogDID on returned entries; pass
// the log DID this process scans against (cfg.CasesLogDID for
// court-tools callers). Without a logDID, the shim is still usable for
// TreeHead — FetchEntry and ScanFrom fail fast with a clear error
// (the SDK fetcher's LogDID is required as of baseproof v1.26.0).
//
// Production deployments that require mTLS to the ledger MUST use
// NewMTLSLedgerClient instead. This constructor is retained for
// dev/test paths where TLS material is not yet provisioned.
//
// Returns (nil, error) on SDK fetcher construction failure. The SDK's
// v1.26.0 HTTP-config sweep made every HTTP-bearing constructor return
// an error; surfacing it keeps the contract honest (a misconfigured
// client must die at boot, not at the first Fetch).
func NewLedgerClient(baseURL string, optionalLogDID ...string) (*LedgerClient, error) {
	logDID := ""
	if len(optionalLogDID) > 0 {
		logDID = optionalLogDID[0]
	}

	// One *http.Client shared between the SDK fetcher and the shim's
	// own /scan + /tree/head path. SDK-tuned: connection pool of 100
	// idle conns/host + RetryAfterRoundTripper (BUG #2/#6 contract).
	httpc := sdklog.DefaultClient(defaultLedgerTimeout, nil)

	// Fetcher construction is gated on logDID being supplied — SDK
	// v1.26.0 made LogDID a required field on HTTPEntryFetcherConfig.
	// nil fetcher signals "FetchEntry / ScanFrom unconfigured"; both
	// methods nil-guard and return a clear error.
	var fetcher *sdklog.HTTPEntryFetcher
	if logDID != "" {
		var err error
		fetcher, err = sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
			BaseURL: baseURL,
			LogDID:  logDID,
			Client:  httpc,
		})
		if err != nil {
			return nil, fmt.Errorf("clitools: ledger fetcher: %w", err)
		}
	}
	return &LedgerClient{
		baseURL: baseURL,
		logDID:  logDID,
		fetcher: fetcher,
		httpc:   httpc,
	}, nil
}

// NewMTLSLedgerClient is the production constructor: same SDK fetcher
// + scan client, but with a client certificate presented on every
// connection so the ledger can identify the caller cryptographically.
//
// As of baseproof v1.26.0, sdklog.HTTPEntryFetcherConfig.Client carries
// the mTLS material the SAME way ScanFrom / TreeHead does — so every
// outbound from this shim presents the configured client cert. The
// v1.25.0-era split (FetchEntry plaintext, others mTLS) is closed.
//
// Returns (nil, err) on any TLS-material failure. Callers MUST fail
// startup; the constructor refuses to silently fall back to plaintext.
func NewMTLSLedgerClient(baseURL string, tlsCfg sdklog.ClientTLSConfig, optionalLogDID ...string) (*LedgerClient, error) {
	logDID := ""
	if len(optionalLogDID) > 0 {
		logDID = optionalLogDID[0]
	}

	c, err := reliability.NewMTLSClient(reliability.ClientConfig{Timeout: defaultLedgerTimeout}, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("clitools: ledger mTLS client: %w", err)
	}

	// Same logDID-gating as NewLedgerClient — SDK v1.26.0 requires
	// LogDID on HTTPEntryFetcherConfig.
	var fetcher *sdklog.HTTPEntryFetcher
	if logDID != "" {
		fetcher, err = sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
			BaseURL: baseURL,
			LogDID:  logDID,
			Client:  c, // mTLS client — SDK v1.26.0 closed the FetchEntry-plaintext gap.
		})
		if err != nil {
			return nil, fmt.Errorf("clitools: ledger mTLS fetcher: %w", err)
		}
	}
	return &LedgerClient{
		baseURL: baseURL,
		logDID:  logDID,
		fetcher: fetcher,
		httpc:   c,
	}, nil
}

// NewServerVerifyLedgerClient is the open-HTTPS constructor: it presents NO
// client cert but pins caFile to verify the ledger's privately-signed /
// self-signed server cert (serverName overrides SNI for IP-addressed endpoints;
// empty infers from the URL host). This is the zero-trust read/scan posture —
// the ledger serves reads openly and gates writes on in-body crypto, so the
// aggregator authenticates WHO the ledger is without presenting a client cert.
//
// caFile is REQUIRED (an empty CA cannot verify a self-signed cert). Returns
// (nil, err) on CA load failure or fetcher construction failure; the caller
// MUST fail startup rather than fall back to system roots. Verification is
// always on — never InsecureSkipVerify.
func NewServerVerifyLedgerClient(baseURL, caFile, serverName string, optionalLogDID ...string) (*LedgerClient, error) {
	logDID := ""
	if len(optionalLogDID) > 0 {
		logDID = optionalLogDID[0]
	}
	if caFile == "" {
		return nil, fmt.Errorf("clitools: server-verify ledger client requires a CA file (cannot verify a self-signed cert against nothing)")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("clitools: read ledger CA %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("clitools: ledger CA %q contains no parseable certificates", caFile)
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13, ServerName: serverName}
	httpc := sdklog.DefaultClient(defaultLedgerTimeout, tlsCfg)

	var fetcher *sdklog.HTTPEntryFetcher
	if logDID != "" {
		fetcher, err = sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
			BaseURL: baseURL,
			LogDID:  logDID,
			Client:  httpc,
		})
		if err != nil {
			return nil, fmt.Errorf("clitools: ledger server-verify fetcher: %w", err)
		}
	}
	return &LedgerClient{
		baseURL: baseURL,
		logDID:  logDID,
		fetcher: fetcher,
		httpc:   httpc,
	}, nil
}

// RawEntry is the legacy shape consumed by tools/aggregator. Preserved
// for compatibility; new code should use types.EntryWithMetadata.
type RawEntry struct {
	Sequence         uint64 `json:"sequence"`
	CanonicalHex     string `json:"canonical_hex"`
	LogTimeUnixMicro int64  `json:"log_time_unix_micro"`
	SigAlgoID        uint16 `json:"sig_algo_id,omitempty"`
	SignatureHex     string `json:"signature_hex,omitempty"`
}

// FetchEntry retrieves a single entry by sequence. Returns (nil, nil)
// when the ledger returns 404. Wire path: SDK HTTPEntryFetcher →
// GET /v1/entries/{seq}/raw.
//
// Requires a logDID at construction (NewLedgerClient(url, logDID)) —
// the SDK fetcher rejects an empty LogDID as of baseproof v1.26.0.
func (c *LedgerClient) FetchEntry(ctx context.Context, seq uint64) (*RawEntry, error) {
	if c.fetcher == nil {
		return nil, fmt.Errorf("ledger: FetchEntry requires logDID at construction")
	}
	pos := types.LogPosition{LogDID: c.logDID, Sequence: seq}
	ewm, err := c.fetcher.Fetch(ctx, pos)
	if err != nil {
		return nil, fmt.Errorf("ledger: fetch %d: %w", seq, err)
	}
	if ewm == nil {
		return nil, nil
	}
	return entryToRaw(ewm), nil
}

// ScanFrom reads up to count entries starting at startPos. Returns an
// empty slice (not error) at log end. Wire path: GET /v1/query/scan
// (SDK-canonical JSON metadata) + per-row HTTPEntryFetcher.Fetch to
// back-fill CanonicalBytes (the deserializer requires the wire bytes).
func (c *LedgerClient) ScanFrom(ctx context.Context, startPos uint64, count int) ([]RawEntry, error) {
	if c.logDID == "" {
		return nil, fmt.Errorf("ledger: ScanFrom requires logDID at construction")
	}
	metas, err := c.scanMetadata(startPos, count)
	if err != nil {
		return nil, fmt.Errorf("ledger: scan from %d: %w", startPos, err)
	}
	out := make([]RawEntry, 0, len(metas))
	for _, m := range metas {
		full, fErr := c.fetcher.Fetch(ctx, m.Position)
		if fErr != nil {
			return nil, fmt.Errorf("ledger: scan fetch seq %d: %w", m.Position.Sequence, fErr)
		}
		if full == nil {
			// Race: present in scan, gone before /raw. Skip.
			continue
		}
		// Prefer LogTime from /raw header; fall back to the metadata.
		merged := *full
		if merged.LogTime.IsZero() {
			merged.LogTime = m.LogTime
		}
		out = append(out, *entryToRaw(&merged))
	}
	return out, nil
}

// TreeHead fetches the ledger's current tree head. Passthrough —
// the SDK does not yet ship a typed helper for /v1/tree/head.
func (c *LedgerClient) TreeHead() (map[string]any, error) {
	resp, err := c.httpc.Get(c.baseURL + "/v1/tree/head")
	if err != nil {
		return nil, fmt.Errorf("ledger: tree head: %w", err)
	}
	defer resp.Body.Close()

	// BUG #3 mirror: read cap+1 to detect oversize responses
	// instead of silently truncating. Tree heads are tiny
	// (~hundreds of bytes); anything > 64 KiB is ledger
	// misbehavior worth surfacing.
	const treeHeadBodyCap = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, treeHeadBodyCap+1))
	if err != nil {
		return nil, fmt.Errorf("ledger: read tree head: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ledger: tree head: HTTP %d: %s", resp.StatusCode, body)
	}
	if len(body) > treeHeadBodyCap {
		return nil, fmt.Errorf("ledger: tree head response exceeds %d bytes", treeHeadBodyCap)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ledger: parse tree head: %w", err)
	}
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// Internal: /v1/query/scan helper
// ─────────────────────────────────────────────────────────────────────
//
// Mirrors the SDK's pending HTTPLedgerQueryAPI shape exactly. When
// the SDK pin is bumped to include HTTPLedgerQueryAPI, this helper
// becomes a single delegated call.

// scanEntryResponse is one row of /v1/query/scan. Field tags match
// baseproof-ledger/api/queries.go::EntryResponse and the SDK's
// queryEntryResponse byte-for-byte.
type scanEntryResponse struct {
	SequenceNumber  uint64 `json:"sequence_number"`
	CanonicalHash   string `json:"canonical_hash"`
	LogTime         string `json:"log_time"`
	SignerDID       string `json:"signer_did,omitempty"`
	ProtocolVersion uint16 `json:"protocol_version"`
	PayloadSize     int    `json:"payload_size"`
	CanonicalSize   int    `json:"canonical_size"`
}

// scanListResponse mirrors the ledger's outer JSON envelope.
type scanListResponse struct {
	Entries []scanEntryResponse `json:"entries"`
	Count   int                 `json:"count"`
}

// scanMetadata calls /v1/query/scan and returns SDK-shaped
// EntryWithMetadata (CanonicalBytes nil — egress mandate).
func (c *LedgerClient) scanMetadata(startPos uint64, count int) ([]types.EntryWithMetadata, error) {
	v := url.Values{}
	v.Set("start", strconv.FormatUint(startPos, 10))
	if count > 0 {
		v.Set("count", strconv.Itoa(count))
	}
	resp, err := c.httpc.Get(c.baseURL + "/v1/query/scan?" + v.Encode())
	if err != nil {
		return nil, fmt.Errorf("scan request: %w", err)
	}
	defer resp.Body.Close()

	// BUG #3 mirror: read cap+1 to detect oversize responses
	// instead of silently truncating. The ledger caps scan
	// payload at maxScanResponseBytes; anything past that is
	// ledger misbehavior the consumer must see.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScanResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("scan read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scan HTTP %d: %s", resp.StatusCode, body)
	}
	if len(body) > maxScanResponseBytes {
		return nil, fmt.Errorf("scan response exceeds %d bytes", maxScanResponseBytes)
	}

	var list scanListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("scan parse: %w", err)
	}

	out := make([]types.EntryWithMetadata, 0, len(list.Entries))
	for _, r := range list.Entries {
		ewm := types.EntryWithMetadata{
			Position: types.LogPosition{LogDID: c.logDID, Sequence: r.SequenceNumber},
		}
		if r.LogTime != "" {
			if t, err := time.Parse(time.RFC3339Nano, r.LogTime); err == nil {
				ewm.LogTime = t.UTC()
			}
		}
		out = append(out, ewm)
	}
	return out, nil
}

// entryToRaw flattens an SDK EntryWithMetadata into the legacy
// RawEntry shape. CanonicalBytes is hex-encoded for the deserializer;
// LogTime is converted to micros to match the legacy field.
func entryToRaw(ewm *types.EntryWithMetadata) *RawEntry {
	r := &RawEntry{
		Sequence:     ewm.Position.Sequence,
		CanonicalHex: hex.EncodeToString(ewm.CanonicalBytes),
	}
	if !ewm.LogTime.IsZero() {
		r.LogTimeUnixMicro = ewm.LogTime.UnixMicro()
	}
	return r
}

// ─────────────────────────────────────────────────────────────────────
// Proof + horizon wrappers (scan-rebuild foundation)
//
// These wrap the ledger's /v1/tree/{inclusion,consistency,horizon} endpoints
// so the witness-rotation chain scanner can rebuild a PROVEN rotation chain
// from the LOG (source of truth), never from gossip. Same HTTP idiom as
// TreeHead: GET → cap-limited read → status check → JSON decode.
// ─────────────────────────────────────────────────────────────────────

const proofBodyCap = 1 << 20 // 1 MiB: an inclusion/consistency co-path is tiny; cap guards a hostile mirror.

// httpGetJSON is the shared GET → cap-read → status → unmarshal helper.
func (c *LedgerClient) httpGetJSON(path string, out any) ([]byte, error) {
	resp, err := c.httpc.Get(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("ledger: GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, proofBodyCap+1))
	if err != nil {
		return nil, fmt.Errorf("ledger: read %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ledger: %s: HTTP %d: %s", path, resp.StatusCode, body)
	}
	if len(body) > proofBodyCap {
		return nil, fmt.Errorf("ledger: %s response exceeds %d bytes", path, proofBodyCap)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return nil, fmt.Errorf("ledger: parse %s: %w", path, err)
		}
	}
	return body, nil
}

// rawInclusionResponse mirrors the ledger's GET /v1/tree/inclusion/{seq} JSON
// (tessera proof_adapter RawInclusionProof): {leaf_index, tree_size, hashes}.
type rawInclusionResponse struct {
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	Hashes    []string `json:"hashes"`
}

// InclusionProof fetches the RFC 6962 inclusion proof for the leaf at seq
// against the ledger's CURRENT head. LeafHash is left ZERO (the ledger does not
// fill it; the caller binds it via envelope.OnLogEntryLeafHash before
// verifying).
func (c *LedgerClient) InclusionProof(seq uint64) (*types.MerkleProof, error) {
	return c.inclusionProof(fmt.Sprintf("/v1/tree/inclusion/%d", seq))
}

// InclusionProofAtSize fetches the proof for the leaf at seq against a SPECIFIC
// tree size via GET /v1/tree/inclusion/{seq}?tree_size=N (ledger v1.42.0+). The
// witness-rotation scan-rebuild needs a proof bound to the witness-COSIGNED
// horizon (which lags the live head), not the live sub-quorum head — so it pins
// treeSize = horizon.TreeSize. The returned proof.TreeSize == treeSize.
func (c *LedgerClient) InclusionProofAtSize(seq, treeSize uint64) (*types.MerkleProof, error) {
	return c.inclusionProof(fmt.Sprintf("/v1/tree/inclusion/%d?tree_size=%d", seq, treeSize))
}

func (c *LedgerClient) inclusionProof(path string) (*types.MerkleProof, error) {
	var r rawInclusionResponse
	if _, err := c.httpGetJSON(path, &r); err != nil {
		return nil, err
	}
	sib := make([][32]byte, len(r.Hashes))
	for i, h := range r.Hashes {
		raw, derr := hex.DecodeString(h)
		if derr != nil {
			return nil, fmt.Errorf("ledger: inclusion sibling %d hex: %w", i, derr)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("ledger: inclusion sibling %d has %d bytes, want 32", i, len(raw))
		}
		copy(sib[i][:], raw)
	}
	return &types.MerkleProof{
		LeafPosition: r.LeafIndex,
		Siblings:     sib,
		TreeSize:     r.TreeSize,
		// LeafHash left zero — caller binds it.
	}, nil
}

// rawConsistencyResponse mirrors GET /v1/tree/consistency/{old}/{new}: {hashes}.
type rawConsistencyResponse struct {
	Hashes []string `json:"hashes"`
}

// ConsistencyProof fetches the RFC 6962 consistency proof between tree sizes
// oldSize and newSize, returning the raw sibling hashes. Used to prove the
// scanned window extends the previously-trusted tree with no rewrite (closes
// tail-omission). Verified via verifier.VerifyConsistency.
func (c *LedgerClient) ConsistencyProof(oldSize, newSize uint64) ([][32]byte, error) {
	var r rawConsistencyResponse
	if _, err := c.httpGetJSON(fmt.Sprintf("/v1/tree/consistency/%d/%d", oldSize, newSize), &r); err != nil {
		return nil, err
	}
	out := make([][32]byte, len(r.Hashes))
	for i, h := range r.Hashes {
		raw, derr := hex.DecodeString(h)
		if derr != nil {
			return nil, fmt.Errorf("ledger: consistency hash %d hex: %w", i, derr)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("ledger: consistency hash %d has %d bytes, want 32", i, len(raw))
		}
		copy(out[i][:], raw)
	}
	return out, nil
}

// Horizon fetches the latest witness-cosigned tree head (GET /v1/tree/horizon),
// the trust anchor a scan-verify anchors on. The K-of-N cosignatures are
// re-verified by the caller against the witness set it independently trusts;
// this call only transports the head. Returns the SDK CosignedTreeHead.
func (c *LedgerClient) Horizon() (types.CosignedTreeHead, error) {
	var w types.WireCosignedTreeHead
	if _, err := c.httpGetJSON("/v1/tree/horizon", &w); err != nil {
		return types.CosignedTreeHead{}, err
	}
	head, err := w.ToCosignedTreeHead()
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("ledger: decode horizon: %w", err)
	}
	return head, nil
}
