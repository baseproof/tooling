/*
FILE PATH: gossipnet/consistency_fetcher.go

ConsistencyProofFetcher — narrow client that GETs a peer ledger's
/v1/tree/consistency/{old}/{new} and returns the proof bytes as
[][]byte suitable for sdkwitness.DetectHistoryRewrite.

The fetcher is intentionally narrow — one HTTP call, one decode,
one transform — so the equivocation monitor's history-rewrite
branch composes cleanly: fetch → DetectHistoryRewrite →
NewHistoryRewriteFinding → Verify → Publish.

# WIRE SHAPE

The ledger's GET /v1/tree/consistency/{old}/{new} (api/tree.go:
NewTreeConsistencyHandler) serves:

	{
	  "old_size": <uint64>,
	  "new_size": <uint64>,
	  "hashes":   ["<hex>", ...]
	}

This fetcher decodes that JSON, hex-decodes each entry of hashes,
and returns [][]byte. An entry that fails hex-decode aborts the
whole fetch — partial proofs are silently corrupt and would
falsely succeed in DetectHistoryRewrite's verification path
(verifying an empty proof against equal-size heads passes
trivially).

# WHY HERE (NOT IN gossip.Client)

The SDK's gossip.Client surface (baseproof/gossip/client.go) covers
the gossip-feed protocol — Publish, LatestSTH, IterSince. Tree
proofs are a DIFFERENT protocol surface (RFC 6962); putting their
client in gossip/ would conflate the two. The consistency client
belongs next to its only caller (the equivocation monitor's
history-rewrite branch) until a second caller emerges.

Plan §II Post-Part-II #2 (issue #152).
*/
package gossipnet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// MaxConsistencyProofBytes caps the response body size when
// fetching a consistency proof. A 32-byte hash per ceil(log2(N))
// → at most ~64 hashes for a 2^64 tree → ~2 KB raw. The 16 KB
// cap is generous (covers JSON overhead + any future fields)
// without admitting denial-of-service responses.
const MaxConsistencyProofBytes = 16 << 10

// consistencyProofResponse is the wire shape served by
// /v1/tree/consistency/{old}/{new} (api/tree.go's adapter — see
// tessera/proof_adapter.go:ConsistencyProof). Extra fields are
// permitted (DisallowUnknownFields is NOT used here; the API may
// add fields in future versions without breaking this fetcher's
// existing callers).
type consistencyProofResponse struct {
	OldSize uint64   `json:"old_size"`
	NewSize uint64   `json:"new_size"`
	Hashes  []string `json:"hashes"`
}

// FetchConsistencyProof retrieves the consistency proof from
// baseURL+/v1/tree/consistency/{oldSize}/{newSize} using client.
// The proof's hashes are hex-decoded into [][]byte ready for
// sdkwitness.DetectHistoryRewrite.
//
// Empty oldSize → newSize trivially-consistent case returns an
// empty [][]byte without error — the SDK's DetectHistoryRewrite
// will surface ErrSameTreeSize / ErrDifferentSizes routing
// directly.
//
// Errors:
//   - HTTP error / non-200 status → wrapped with the URL + status
//   - body > MaxConsistencyProofBytes → "response too large"
//   - JSON malformed / hex malformed / wrong length → wrapped
//     with the offending index for diagnostic context
func FetchConsistencyProof(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	oldSize, newSize uint64,
) ([][]byte, error) {
	if client == nil {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: nil http.Client")
	}
	if baseURL == "" {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: empty baseURL")
	}
	url := baseURL + "/v1/tree/consistency/" +
		strconv.FormatUint(oldSize, 10) + "/" +
		strconv.FormatUint(newSize, 10)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: build request %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: %s returned HTTP %d",
			url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxConsistencyProofBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: read %s: %w", url, err)
	}
	if len(body) > MaxConsistencyProofBytes {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: %s response > %d bytes (DoS guard)",
			url, MaxConsistencyProofBytes)
	}

	var decoded consistencyProofResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("gossipnet/consistency_fetcher: decode %s: %w", url, err)
	}

	out := make([][]byte, 0, len(decoded.Hashes))
	for i, h := range decoded.Hashes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("gossipnet/consistency_fetcher: hash[%d] hex decode: %w", i, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("gossipnet/consistency_fetcher: hash[%d] length %d, want 32",
				i, len(raw))
		}
		out = append(out, raw)
	}
	return out, nil
}
