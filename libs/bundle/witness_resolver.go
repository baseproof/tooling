/*
FILE PATH: libs/bundle/witness_resolver.go

HTTP-backed WitnessSetResolver that consumes the ledger's
GET /v1/network/witnesses/{set_hash} — content-addressable +
immutable.

# WHY HERE

The SDK's log/bundle.VerifyBundle takes a WitnessSetResolver
interface — it does NOT know HOW to fetch witness sets. The
ledger publishes them via /v1/network/witnesses/{set_hash};
the resolver here is the HTTP client that consumes that
endpoint and projects the JSON shape back into the
*cosign.WitnessKeySet the verifier wants.

# CONTENT-ADDRESSABLE → AGGRESSIVE CACHE

Because the endpoint is keyed by SetHash and serves
Cache-Control: public, max-age=31536000, immutable, this
resolver can safely cache forever. Same hash → same bytes →
same set. A cache miss falls through to HTTP; a hit returns the
cached value with no I/O.

In-memory cache uses a sync.Map keyed by the hex-encoded set_hash.
Bundle verification never mutates the resolved set, so the cache
hands out the same shared pointer — defense-in-depth: the SDK's
*cosign.WitnessKeySet has no exported mutators.

# GOAL ALIGNMENT

  - #13 witness rotation without breaking historical bundles —
    every bundle's witness_set_hash resolves through this
    resolver, which serves the HISTORICAL set (by hash) not the
    current set. A bundle minted in year-1 against witness-set-A
    continues to verify in year-20 even after the ledger
    rotated to witness-set-B, because the lookup is by
    content-address.
*/
package bundle

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
)

// MaxWitnessSetBytes caps the HTTP response body. A typical
// witness-set JSON document is ~1 KB; 64 KiB is hostile.
const MaxWitnessSetBytes = 64 << 10

// ErrWitnessSetEmptyURL is returned when NewHTTPWitnessSetResolver
// is constructed with an empty base URL.
var ErrWitnessSetEmptyURL = errors.New("bundle/witness_resolver: empty baseURL")

// ErrWitnessSetNilClient is returned when the resolver is
// constructed with a nil *http.Client.
var ErrWitnessSetNilClient = errors.New("bundle/witness_resolver: nil http.Client")

// wireWitnessSetView mirrors api.WitnessSetView from the ledger
// (snake_case keys, hex-encoded byte fields). Kept in sync with
// the ledger's wire shape; an API change there surfaces here as
// a decode error.
type wireWitnessSetView struct {
	SetHash      string           `json:"set_hash"`
	SchemeTag    uint8            `json:"scheme_tag"`
	EffectiveSeq uint64           `json:"effective_seq"`
	RetiredSeq   *uint64          `json:"retired_seq,omitempty"`
	Keys         []wireWitnessKey `json:"keys"`
}

type wireWitnessKey struct {
	ID                string `json:"id"`         // hex
	PublicKey         string `json:"public_key"` // hex
	SchemeTag         uint8  `json:"scheme_tag"`
	ProofOfPossession string `json:"proof_of_possession,omitempty"` // hex
}

// HTTPWitnessSetResolver consumes a ledger's
// GET /v1/network/witnesses/{set_hash} endpoint and projects the
// JSON response into a *cosign.WitnessKeySet. Caches each
// resolved hash forever (the endpoint is content-addressable +
// immutable).
//
// Thread-safe. Multiple bundle.VerifyBundle calls in flight on
// the same hash race through ResolveWitnessSet, but each completes
// independently; the LAST writer's value lands in the cache (all
// writers see the same content-addressed bytes, so the race is
// benign).
type HTTPWitnessSetResolver struct {
	baseURL   string
	client    *http.Client
	networkID cosign.NetworkID
	quorumK   int

	cache sync.Map // map[string]*cosign.WitnessKeySet, key = hex-encoded set_hash
}

// NewHTTPWitnessSetResolver constructs the resolver. networkID +
// quorumK are required because the SDK's cosign.NewWitnessKeySet
// constructor binds the set to (network_id, quorum_k); the ledger's
// /v1/network/witnesses/* endpoint returns just the keys, so we
// must supply the network-level context here.
//
// quorumK ≤ 0 is rejected — a zero or negative quorum cannot
// produce a valid WitnessKeySet (cosign.NewWitnessKeySet would
// reject); fail loud at construction.
func NewHTTPWitnessSetResolver(
	baseURL string,
	client *http.Client,
	networkID cosign.NetworkID,
	quorumK int,
) (*HTTPWitnessSetResolver, error) {
	if baseURL == "" {
		return nil, ErrWitnessSetEmptyURL
	}
	if client == nil {
		return nil, ErrWitnessSetNilClient
	}
	if quorumK <= 0 {
		return nil, fmt.Errorf("bundle/witness_resolver: quorumK %d must be > 0", quorumK)
	}
	var zero cosign.NetworkID
	if networkID == zero {
		return nil, fmt.Errorf("bundle/witness_resolver: networkID must be non-zero")
	}
	return &HTTPWitnessSetResolver{
		baseURL:   baseURL,
		client:    client,
		networkID: networkID,
		quorumK:   quorumK,
	}, nil
}

// ResolveWitnessSet implements sdkbundle.WitnessSetResolver.
// Looks up the cache, falls through to HTTP on miss, projects the
// JSON into a *cosign.WitnessKeySet, caches the result.
func (r *HTTPWitnessSetResolver) ResolveWitnessSet(
	ctx context.Context,
	setHash [32]byte,
) (*cosign.WitnessKeySet, error) {
	key := hex.EncodeToString(setHash[:])
	if cached, ok := r.cache.Load(key); ok {
		return cached.(*cosign.WitnessKeySet), nil
	}

	url := r.baseURL + "/v1/network/witnesses/" + key
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("bundle/witness_resolver: build request %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle/witness_resolver: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle/witness_resolver: %s returned HTTP %d",
			url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxWitnessSetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bundle/witness_resolver: read %s: %w", url, err)
	}
	if len(body) > MaxWitnessSetBytes {
		return nil, fmt.Errorf("bundle/witness_resolver: %s response > %d bytes (DoS guard)",
			url, MaxWitnessSetBytes)
	}

	var view wireWitnessSetView
	if err := json.Unmarshal(body, &view); err != nil {
		return nil, fmt.Errorf("bundle/witness_resolver: decode %s: %w", url, err)
	}

	set, err := r.projectToSDK(setHash, view)
	if err != nil {
		return nil, fmt.Errorf("bundle/witness_resolver: project %s: %w", url, err)
	}
	r.cache.Store(key, set)
	return set, nil
}

// projectToSDK translates the wire-shape JSON into the SDK's
// *cosign.WitnessKeySet via cosign.NewWitnessKeySet (so every
// validation the SDK enforces — non-empty keys, valid PoPs, etc.
// — runs on the resolved set; the resolver does NO crypto checks
// of its own).
//
// A defensive check: the ledger's reported SetHash MUST match the
// one we asked for. A mismatch is either a content-addressing
// collision (cryptographically impossible) or a malicious mirror
// returning a different set under our requested hash. The SDK's
// cosign.SetHash recomputation would catch this downstream, but
// failing loud HERE produces a more legible operator error.
func (r *HTTPWitnessSetResolver) projectToSDK(
	expectedHash [32]byte,
	view wireWitnessSetView,
) (*cosign.WitnessKeySet, error) {
	// Verify the response's set_hash matches what we asked for.
	gotHashBytes, err := hex.DecodeString(view.SetHash)
	if err != nil || len(gotHashBytes) != 32 {
		return nil, fmt.Errorf("malformed set_hash %q in response", view.SetHash)
	}
	var gotHash [32]byte
	copy(gotHash[:], gotHashBytes)
	if gotHash != expectedHash {
		return nil, fmt.Errorf("set_hash mismatch: requested %x, response carried %x",
			expectedHash, gotHash)
	}

	keys := make([]types.WitnessPublicKey, 0, len(view.Keys))
	for i, k := range view.Keys {
		idBytes, err := hex.DecodeString(k.ID)
		if err != nil || len(idBytes) != 32 {
			return nil, fmt.Errorf("keys[%d].id malformed (hex32): %q", i, k.ID)
		}
		pubBytes, err := hex.DecodeString(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("keys[%d].public_key malformed hex: %w", i, err)
		}
		var popBytes []byte
		if k.ProofOfPossession != "" {
			popBytes, err = hex.DecodeString(k.ProofOfPossession)
			if err != nil {
				return nil, fmt.Errorf("keys[%d].proof_of_possession malformed hex: %w", i, err)
			}
		}
		var id [32]byte
		copy(id[:], idBytes)
		keys = append(keys, types.WitnessPublicKey{
			ID:                id,
			PublicKey:         pubBytes,
			SchemeTag:         k.SchemeTag,
			ProofOfPossession: popBytes,
		})
	}

	set, err := cosign.NewWitnessKeySet(keys, r.networkID, r.quorumK, nil)
	if err != nil {
		return nil, fmt.Errorf("cosign.NewWitnessKeySet: %w", err)
	}

	// Defense-in-depth: confirm the SDK's SetHash matches what
	// the ledger published. A genuine ledger publishes
	// set.SetHash() at rotation time (II.2 history table);
	// a malicious mirror returning a set with a different hash
	// would surface here even though the bytes claim the hash.
	computed := set.SetHash()
	if computed != expectedHash {
		return nil, fmt.Errorf("cosign.SetHash mismatch: ledger claimed %x, SDK computed %x",
			expectedHash, computed)
	}
	return set, nil
}
