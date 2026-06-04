/*
FILE PATH: api/network_test.go

Tests for the Part II.1 network introspection handlers:
  - GET /v1/network/bootstrap
  - GET /v1/network/identity
  - GET /v1/network/mirrors

In-memory fixtures only — no DB, no I/O.
*/
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
)

// ─────────────────────────────────────────────────────────────────────
// fixture
// ─────────────────────────────────────────────────────────────────────

// validBootstrap returns a BootstrapDocument with enough fields to
// pass IDs() (covers all the required GenesisXxx fields).
func validBootstrap(t *testing.T) network.BootstrapDocument {
	t.Helper()
	return network.BootstrapDocument{
		ProtocolVersion:             "1",
		ExchangeDID:                 "did:web:test.example",
		NetworkName:                 "test-net-network-handlers",
		GenesisWitnessSet:           []string{"did:key:zwitness1"},
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("01", 32)},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: true, CostMode: "uncharged",
		},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{1},
			AllowedCosignSchemeTags: []uint8{1},
			MinSignaturesPerEntry:   1,
		},
	}
}

// ─────────────────────────────────────────────────────────────────────
// /v1/network/bootstrap
// ─────────────────────────────────────────────────────────────────────

func TestNetworkBootstrapHandler_ServesCanonicalBytes(t *testing.T) {
	doc := validBootstrap(t)
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	h := NewNetworkBootstrapHandler(canonical)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/bootstrap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.Bytes(); !bytesEqual(got, canonical) {
		t.Errorf("body bytes drift: got %d, want %d", len(got), len(canonical))
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q", cc)
	}
	// Bytes MUST hash to the NetworkID — the load-bearing identity
	// invariant. A consumer recomputes this to confirm the network's
	// claim.
	got := sha256.Sum256(rec.Body.Bytes())
	ids, _ := doc.IDs()
	if got != [32]byte(ids.NetworkID) {
		t.Errorf("sha256(body) drift: %x vs NetworkID %x", got, ids.NetworkID)
	}
}

func TestNetworkBootstrapHandler_UnconfiguredReturns404(t *testing.T) {
	h := NewNetworkBootstrapHandler(nil)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/bootstrap", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestNetworkBootstrapHandler_DefensiveCopy — mutating the slice
// the constructor was handed MUST NOT change what the handler serves.
// Cache-Control: immutable would lie otherwise.
func TestNetworkBootstrapHandler_DefensiveCopy(t *testing.T) {
	doc := validBootstrap(t)
	canonical, _ := doc.CanonicalBytes()
	original := append([]byte(nil), canonical...)
	h := NewNetworkBootstrapHandler(canonical)
	// Mutate the caller's slice.
	for i := range canonical {
		canonical[i] = 0xFF
	}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/bootstrap", nil))
	if !bytesEqual(rec.Body.Bytes(), original) {
		t.Error("handler served mutated bytes — defensive copy missing")
	}
}

// ─────────────────────────────────────────────────────────────────────
// /v1/network/identity
// ─────────────────────────────────────────────────────────────────────

func TestBuildNetworkIdentity_DerivesIDsFromDoc(t *testing.T) {
	doc := validBootstrap(t)
	id, err := BuildNetworkIdentity(doc)
	if err != nil {
		t.Fatalf("BuildNetworkIdentity: %v", err)
	}
	if id.NetworkID == "" || len(id.NetworkID) != 64 {
		t.Errorf("NetworkID = %q (len %d), want 64-char hex", id.NetworkID, len(id.NetworkID))
	}
	if id.BootstrapHash != id.NetworkID {
		t.Errorf("BootstrapHash %q != NetworkID %q (must alias)", id.BootstrapHash, id.NetworkID)
	}
	if !strings.HasPrefix(id.NetworkDID, "did:baseproof:network:") {
		t.Errorf("NetworkDID = %q, want did:baseproof:network: prefix", id.NetworkDID)
	}
	// UUID v8 dashed form is 36 chars.
	if len(id.NetworkUUID) != 36 {
		t.Errorf("NetworkUUID = %q (len %d), want 36", id.NetworkUUID, len(id.NetworkUUID))
	}
}

func TestBuildNetworkIdentity_ZeroDocReturnsEmpty(t *testing.T) {
	id, err := BuildNetworkIdentity(network.BootstrapDocument{})
	if err != nil {
		t.Fatalf("BuildNetworkIdentity on zero doc: %v", err)
	}
	if id.NetworkID != "" {
		t.Errorf("NetworkID = %q, want empty (zero doc)", id.NetworkID)
	}
}

func TestNetworkIdentityHandler_ServesIdentity(t *testing.T) {
	doc := validBootstrap(t)
	id, _ := BuildNetworkIdentity(doc)
	h := NewNetworkIdentityHandler(id)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/identity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got NetworkIdentity
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != id {
		t.Errorf("identity drift: got %+v, want %+v", got, id)
	}
	// Sanity: NetworkID is decodable hex.
	if _, err := hex.DecodeString(got.NetworkID); err != nil {
		t.Errorf("NetworkID %q is not hex: %v", got.NetworkID, err)
	}
}

func TestNetworkIdentityHandler_UnconfiguredReturns404(t *testing.T) {
	h := NewNetworkIdentityHandler(NetworkIdentity{})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/identity", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// /v1/network/mirrors
// ─────────────────────────────────────────────────────────────────────

func TestNetworkMirrorsHandler_ServesManifest(t *testing.T) {
	m := WireMirrorManifest{
		LogDID: "did:web:source.example",
		Mirrors: []WireMirrorEntry{
			{URL: "https://mirror-a.example/entries/", Kind: "entries", Source: "did:web:mirror-a.example"},
			{URL: "https://mirror-b.example/tiles/", Kind: "tiles"},
			{URL: "https://mirror-c.example/bundles/", Kind: "bundles", Source: "did:web:archive.example"},
		},
	}
	h := NewNetworkMirrorsHandler(m)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/mirrors", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want public, max-age=300", cc)
	}
	var got WireMirrorManifest
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.LogDID != m.LogDID {
		t.Errorf("LogDID drift")
	}
	if len(got.Mirrors) != 3 {
		t.Fatalf("Mirrors len = %d, want 3", len(got.Mirrors))
	}
	// Source omitempty must elide the empty-string case.
	// Re-marshal got — we already consumed the body. Re-render
	// to check the SECOND mirror's source field is omitted.
	bs, _ := json.Marshal(got)
	body := string(bs)
	if strings.Count(body, `"source":`) != 2 {
		t.Errorf("expected 2 source fields (omitempty drops the empty case); body=%s", body)
	}
}

func TestNetworkMirrorsHandler_UnconfiguredReturns404(t *testing.T) {
	h := NewNetworkMirrorsHandler(WireMirrorManifest{})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/mirrors", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// bytesEqual avoids depending on bytes.Equal so this test file
// stays self-contained.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
