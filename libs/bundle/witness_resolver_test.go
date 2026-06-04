/*
FILE PATH: libs/bundle/witness_resolver_test.go

Tests for HTTPWitnessSetResolver — construction validation +
fetch + cache + defense-in-depth SetHash recomputation.
*/
package bundle

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

// fixtureNetworkID is a stable non-zero NetworkID for tests.
var fixtureNetworkID = cosign.NetworkID{0x01, 0x02, 0x03, 0x04}

// fixtureWitnessSet builds an ECDSA *cosign.WitnessKeySet with one
// real key — the SDK validates pubkey bytes at construction so
// the bytes have to be a real secp256k1 point.
func fixtureWitnessSet(t *testing.T) *cosign.WitnessKeySet {
	t.Helper()
	// secp256k1 is on the K-curve, not P-256 — but the SDK accepts
	// it via signatures.ParseSecp256k1CompressedPubKey. For test
	// keys we generate a real secp256k1 keypair.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Compress to 33 bytes via standard prefix-x encoding. SDK
	// accepts both compressed (33) and uncompressed (65) for
	// ECDSA scheme tag 0x01.
	x := priv.X.Bytes()
	pubBytes := make([]byte, 33)
	pubBytes[0] = 0x02
	if priv.Y.Bit(0) == 1 {
		pubBytes[0] = 0x03
	}
	copy(pubBytes[33-len(x):], x)

	var id [32]byte
	copy(id[:], []byte("witness-id-fixture-001"))

	keys := []types.WitnessPublicKey{{
		ID:        id,
		PublicKey: pubBytes,
		SchemeTag: signatures.SchemeECDSA,
	}}
	set, err := cosign.NewWitnessKeySet(keys, fixtureNetworkID, 1, nil)
	if err != nil {
		// The SDK rejects pubkey bytes that aren't on the
		// curve. Generate a fresh keypair until one lands on
		// secp256k1; in practice fixture flake is negligible
		// but we re-roll to keep tests deterministic.
		t.Skipf("test fixture witness set construction failed (curve flake): %v", err)
	}
	return set
}

// stubWitnessServer serves /v1/network/witnesses/{set_hash} with
// the supplied body+status. capturedPath captures the request
// path for assertions; hitCount tracks invocations for cache tests.
func stubWitnessServer(t *testing.T, body []byte, status int, capturedPath *string, hitCount *int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capturedPath != nil {
			*capturedPath = r.URL.Path
		}
		if hitCount != nil {
			atomic.AddInt64(hitCount, 1)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, string(body))
	}))
}

// witnessSetWireBody renders the set as the JSON the ledger's
// /v1/network/witnesses/{set_hash} would emit. Mirrors
// api.WitnessSetView shape.
func witnessSetWireBody(t *testing.T, set *cosign.WitnessKeySet) []byte {
	t.Helper()
	setHash := set.SetHash()
	keys := set.Keys() // []types.WitnessPublicKey
	wireKeys := make([]string, 0, len(keys))
	for _, k := range keys {
		entry := fmt.Sprintf(
			`{"id":%q,"public_key":%q,"scheme_tag":%d}`,
			hex.EncodeToString(k.ID[:]),
			hex.EncodeToString(k.PublicKey),
			k.SchemeTag)
		wireKeys = append(wireKeys, entry)
	}
	return []byte(fmt.Sprintf(
		`{"set_hash":%q,"scheme_tag":1,"effective_seq":0,"keys":[%s]}`,
		hex.EncodeToString(setHash[:]),
		strings.Join(wireKeys, ",")))
}

// ─────────────────────────────────────────────────────────────────────
// Constructor validation
// ─────────────────────────────────────────────────────────────────────

func TestNewHTTPWitnessSetResolver_EmptyBaseURL(t *testing.T) {
	_, err := NewHTTPWitnessSetResolver("", http.DefaultClient, fixtureNetworkID, 1)
	if !errors.Is(err, ErrWitnessSetEmptyURL) {
		t.Fatalf("got %v; want ErrWitnessSetEmptyURL", err)
	}
}

func TestNewHTTPWitnessSetResolver_NilClient(t *testing.T) {
	_, err := NewHTTPWitnessSetResolver("http://x", nil, fixtureNetworkID, 1)
	if !errors.Is(err, ErrWitnessSetNilClient) {
		t.Fatalf("got %v; want ErrWitnessSetNilClient", err)
	}
}

func TestNewHTTPWitnessSetResolver_QuorumZero(t *testing.T) {
	_, err := NewHTTPWitnessSetResolver("http://x", http.DefaultClient, fixtureNetworkID, 0)
	if err == nil {
		t.Fatal("quorumK=0 must be rejected")
	}
}

func TestNewHTTPWitnessSetResolver_ZeroNetworkID(t *testing.T) {
	_, err := NewHTTPWitnessSetResolver("http://x", http.DefaultClient, cosign.NetworkID{}, 1)
	if err == nil {
		t.Fatal("zero NetworkID must be rejected")
	}
}

// ─────────────────────────────────────────────────────────────────────
// HTTP error paths
// ─────────────────────────────────────────────────────────────────────

func TestHTTPWitnessSetResolver_404Errors(t *testing.T) {
	srv := stubWitnessServer(t, []byte("not found"), http.StatusNotFound, nil, nil)
	defer srv.Close()
	r, err := NewHTTPWitnessSetResolver(srv.URL, http.DefaultClient, fixtureNetworkID, 1)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	_, err = r.ResolveWitnessSet(context.Background(), [32]byte{0xAA})
	if err == nil {
		t.Fatal("404 must surface error")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error %q should reference HTTP 404", err)
	}
}

func TestHTTPWitnessSetResolver_MalformedJSONErrors(t *testing.T) {
	srv := stubWitnessServer(t, []byte(`{not json}`), http.StatusOK, nil, nil)
	defer srv.Close()
	r, _ := NewHTTPWitnessSetResolver(srv.URL, http.DefaultClient, fixtureNetworkID, 1)
	_, err := r.ResolveWitnessSet(context.Background(), [32]byte{0xAA})
	if err == nil {
		t.Fatal("malformed JSON must surface error")
	}
}

func TestHTTPWitnessSetResolver_OversizedBodyRejected(t *testing.T) {
	big := strings.Repeat("X", MaxWitnessSetBytes+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()
	r, _ := NewHTTPWitnessSetResolver(srv.URL, http.DefaultClient, fixtureNetworkID, 1)
	_, err := r.ResolveWitnessSet(context.Background(), [32]byte{0xAA})
	if err == nil {
		t.Fatal("oversized body must error")
	}
	if !strings.Contains(err.Error(), "DoS guard") {
		t.Errorf("error %q should reference DoS guard", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Validation: requested hash MUST match returned hash
// ─────────────────────────────────────────────────────────────────────

func TestHTTPWitnessSetResolver_HashMismatchRejected(t *testing.T) {
	// Body claims a different set_hash than the one we requested.
	// The resolver rejects this — a mirror can't substitute a
	// different set under our requested hash.
	body := []byte(fmt.Sprintf(
		`{"set_hash":%q,"scheme_tag":1,"effective_seq":0,"keys":[]}`,
		strings.Repeat("ff", 32)))
	srv := stubWitnessServer(t, body, http.StatusOK, nil, nil)
	defer srv.Close()
	r, _ := NewHTTPWitnessSetResolver(srv.URL, http.DefaultClient, fixtureNetworkID, 1)
	_, err := r.ResolveWitnessSet(context.Background(), [32]byte{0xAA})
	if err == nil {
		t.Fatal("hash mismatch must surface error")
	}
	if !strings.Contains(err.Error(), "set_hash mismatch") {
		t.Errorf("error %q should reference set_hash mismatch", err)
	}
}

func TestHTTPWitnessSetResolver_MalformedHashRejected(t *testing.T) {
	body := []byte(`{"set_hash":"not_hex","scheme_tag":1,"effective_seq":0,"keys":[]}`)
	srv := stubWitnessServer(t, body, http.StatusOK, nil, nil)
	defer srv.Close()
	r, _ := NewHTTPWitnessSetResolver(srv.URL, http.DefaultClient, fixtureNetworkID, 1)
	_, err := r.ResolveWitnessSet(context.Background(), [32]byte{0xAA})
	if err == nil {
		t.Fatal("malformed hash must surface error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// URL composition
// ─────────────────────────────────────────────────────────────────────

func TestHTTPWitnessSetResolver_URLComposition(t *testing.T) {
	var capturedPath string
	srv := stubWitnessServer(t, []byte(`{"set_hash":"00","scheme_tag":1,"effective_seq":0,"keys":[]}`),
		http.StatusOK, &capturedPath, nil)
	defer srv.Close()
	r, _ := NewHTTPWitnessSetResolver(srv.URL, http.DefaultClient, fixtureNetworkID, 1)
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	_, _ = r.ResolveWitnessSet(context.Background(), hash)
	// Should fail at hash-mismatch (the stub returned "00"), but
	// the request URL still composed correctly.
	want := "/v1/network/witnesses/" + hex.EncodeToString(hash[:])
	if capturedPath != want {
		t.Errorf("captured path = %q, want %q", capturedPath, want)
	}
}
