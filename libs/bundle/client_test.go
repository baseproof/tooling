/*
FILE PATH: libs/bundle/client_test.go

Tests for FetchBundleFromMirrors + FetchBundle + the per-mirror
HTTP/decode boundary. In-memory httptest fixtures; no real
network I/O.
*/
package bundle

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	sdktypes "github.com/baseproof/baseproof/types"
)

// fixtureBundleBytes returns the JCS-canonical bytes of a minimal
// well-formed bundle. The bytes round-trip through sdkbundle.Decode
// without error; cryptographic verification is OUT OF SCOPE for
// the fetcher tests (verify_test.go covers that).
func fixtureBundleBytes(t *testing.T) []byte {
	t.Helper()
	doc := network.BootstrapDocument{
		ProtocolVersion:             "1",
		ExchangeDID:                 "did:web:fixture.example",
		NetworkName:                 "fixture-net",
		GenesisWitnessSet:           []string{"did:key:zfixture1"},
		GenesisQuorumK:              1, // REQUIRED since rc4; N=1 ⇒ K=1 (2K>N)
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("01", 32)},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs: %v", err)
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	// SHA-256 of canonical = NetworkID; reuse as BootstrapHash.
	bootstrapHash := [32]byte(ids.NetworkID)
	_ = canonical

	bundle := &sdkbundle.Bundle{
		Format:        sdkbundle.FormatV1,
		NetworkID:     [32]byte(ids.NetworkID),
		NetworkDID:    ids.DID,
		BootstrapHash: bootstrapHash,
		Entry: sdkbundle.BundleEntry{
			WireBytes: []byte("test-entry-bytes"),
			Sequence:  42,
			LogTime:   time.Unix(1700000000, 0).UTC(),
		},
		CosignedHead: sdktypes.CosignedTreeHead{
			TreeHead: sdktypes.TreeHead{
				TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xBB},
			},
			Signatures: []sdktypes.WitnessSignature{{
				PubKeyID: [32]byte{0xCC}, SchemeTag: 0x01, SigBytes: []byte{0xDD, 0xEE},
			}},
		},
		InclusionProof: sdktypes.MerkleProof{LeafPosition: 42, TreeSize: 100},
		SMTProof: sdktypes.SMTProof{
			TerminalKind: sdktypes.SMTTerminalLeaf,
			TerminalLeaf: &sdktypes.SMTLeaf{Key: [32]byte{0x01}},
		},
		WitnessSetHint: sdkbundle.WitnessSetHint{SetHash: [32]byte{0xEE}},
		Algorithms:     sdkbundle.DefaultAlgorithmsHint(),
	}
	out, err := sdkbundle.Encode(bundle)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return out
}

// happyMirrorServer returns an httptest.Server that responds to
// GET /v1/bundle/{seq}?smt_key=hex with the supplied body+status.
// path query for assertions.
func happyMirrorServer(t *testing.T, body []byte, status int, capturedURL *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capturedURL != nil {
			*capturedURL = r.URL.String()
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

// ─────────────────────────────────────────────────────────────────────
// Input validation
// ─────────────────────────────────────────────────────────────────────

func TestFetchBundleFromMirrors_NilClient(t *testing.T) {
	_, err := FetchBundleFromMirrors(context.Background(), nil,
		[]MirrorEndpoint{{URL: "http://x", Source: "test"}}, 0, [32]byte{0xFF})
	if err == nil {
		t.Fatal("nil client must error")
	}
}

func TestFetchBundleFromMirrors_EmptyMirrorList(t *testing.T) {
	_, err := FetchBundleFromMirrors(context.Background(), http.DefaultClient,
		nil, 0, [32]byte{0xFF})
	if !errors.Is(err, ErrEmptyMirrorList) {
		t.Fatalf("got %v; want ErrEmptyMirrorList", err)
	}
}

func TestFetchBundleFromMirrors_ZeroSMTKeyRejected(t *testing.T) {
	_, err := FetchBundleFromMirrors(context.Background(), http.DefaultClient,
		[]MirrorEndpoint{{URL: "http://x", Source: "test"}}, 0, [32]byte{})
	if !errors.Is(err, ErrMissingSmtKey) {
		t.Fatalf("got %v; want ErrMissingSmtKey", err)
	}
}

func TestFetchBundle_EmptyBaseURL(t *testing.T) {
	_, err := FetchBundle(context.Background(), http.DefaultClient,
		"", 0, [32]byte{0xFF})
	if err == nil {
		t.Fatal("empty baseURL must error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Happy path + URL composition
// ─────────────────────────────────────────────────────────────────────

func TestFetchBundle_HappyPath(t *testing.T) {
	body := fixtureBundleBytes(t)
	var capturedURL string
	srv := happyMirrorServer(t, body, http.StatusOK, &capturedURL)
	defer srv.Close()

	var smtKey [32]byte
	for i := range smtKey {
		smtKey[i] = byte(i)
	}
	got, err := FetchBundle(context.Background(), http.DefaultClient,
		srv.URL, 42, smtKey)
	if err != nil {
		t.Fatalf("FetchBundle: %v", err)
	}
	if got.Format != sdkbundle.FormatV1 {
		t.Errorf("Format = %q, want %q", got.Format, sdkbundle.FormatV1)
	}
	if got.Entry.Sequence != 42 {
		t.Errorf("Entry.Sequence = %d, want 42", got.Entry.Sequence)
	}

	// URL composition pin: path includes seq + query carries smt_key.
	wantPath := "/v1/bundle/42"
	wantQuery := "smt_key=" + hex.EncodeToString(smtKey[:])
	if !strings.HasPrefix(capturedURL, wantPath) {
		t.Errorf("captured URL %q does not start with %q", capturedURL, wantPath)
	}
	if !strings.Contains(capturedURL, wantQuery) {
		t.Errorf("captured URL %q missing query %q", capturedURL, wantQuery)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Per-mirror failure modes
// ─────────────────────────────────────────────────────────────────────

func TestFetchBundleFromMirrors_4xxFailsOver(t *testing.T) {
	// Mirror A: 404. Mirror B: happy.
	notFoundA := happyMirrorServer(t, []byte("not found"), http.StatusNotFound, nil)
	defer notFoundA.Close()
	happyB := happyMirrorServer(t, fixtureBundleBytes(t), http.StatusOK, nil)
	defer happyB.Close()

	got, err := FetchBundleFromMirrors(context.Background(), http.DefaultClient,
		[]MirrorEndpoint{
			{URL: notFoundA.URL, Source: "mirror-a"},
			{URL: happyB.URL, Source: "mirror-b"},
		}, 1, [32]byte{0x01})
	if err != nil {
		t.Fatalf("expected failover success; got %v", err)
	}
	if got == nil {
		t.Fatal("nil bundle on supposed success")
	}
}

func TestFetchBundleFromMirrors_5xxFailsOver(t *testing.T) {
	a := happyMirrorServer(t, []byte("server error"), http.StatusInternalServerError, nil)
	defer a.Close()
	b := happyMirrorServer(t, fixtureBundleBytes(t), http.StatusOK, nil)
	defer b.Close()

	got, err := FetchBundleFromMirrors(context.Background(), http.DefaultClient,
		[]MirrorEndpoint{
			{URL: a.URL, Source: "mirror-a"},
			{URL: b.URL, Source: "mirror-b"},
		}, 1, [32]byte{0x01})
	if err != nil || got == nil {
		t.Fatalf("expected 5xx failover success; got err=%v", err)
	}
}

func TestFetchBundleFromMirrors_MalformedJSONFailsOver(t *testing.T) {
	bad := happyMirrorServer(t, []byte(`{not json}`), http.StatusOK, nil)
	defer bad.Close()
	good := happyMirrorServer(t, fixtureBundleBytes(t), http.StatusOK, nil)
	defer good.Close()

	got, err := FetchBundleFromMirrors(context.Background(), http.DefaultClient,
		[]MirrorEndpoint{
			{URL: bad.URL, Source: "bad-mirror"},
			{URL: good.URL, Source: "good-mirror"},
		}, 1, [32]byte{0x01})
	if err != nil || got == nil {
		t.Fatalf("expected decode-error failover; got err=%v", err)
	}
}

func TestFetchBundleFromMirrors_AllFailReturnsJoinedError(t *testing.T) {
	a := happyMirrorServer(t, []byte("nope"), http.StatusNotFound, nil)
	defer a.Close()
	b := happyMirrorServer(t, []byte("nope"), http.StatusInternalServerError, nil)
	defer b.Close()

	_, err := FetchBundleFromMirrors(context.Background(), http.DefaultClient,
		[]MirrorEndpoint{
			{URL: a.URL, Source: "a"},
			{URL: b.URL, Source: "b"},
		}, 1, [32]byte{0x01})
	if !errors.Is(err, ErrAllMirrorsFailed) {
		t.Fatalf("got %v; want wraps ErrAllMirrorsFailed", err)
	}
	// Each per-mirror error must be present in the joined chain
	// (Unwrap()[]error joins should let errors.Is reach them).
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("joined error missing 404 from mirror-a: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("joined error missing 500 from mirror-b: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// DoS guards
// ─────────────────────────────────────────────────────────────────────

func TestFetchBundle_OversizedBodyRejected(t *testing.T) {
	// Body exceeds MaxBundleBytes.
	bigBody := strings.Repeat("X", MaxBundleBytes+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, bigBody)
	}))
	defer srv.Close()
	_, err := FetchBundle(context.Background(), http.DefaultClient,
		srv.URL, 1, [32]byte{0x01})
	if err == nil {
		t.Fatal("oversized body must error")
	}
	if !strings.Contains(err.Error(), "DoS guard") {
		t.Errorf("error %q should reference DoS guard", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Context cancellation
// ─────────────────────────────────────────────────────────────────────

func TestFetchBundleFromMirrors_ContextCancellation(t *testing.T) {
	srv := happyMirrorServer(t, fixtureBundleBytes(t), http.StatusOK, nil)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel
	_, err := FetchBundleFromMirrors(ctx, http.DefaultClient,
		[]MirrorEndpoint{{URL: srv.URL, Source: "test"}}, 1, [32]byte{0x01})
	if err == nil {
		t.Fatal("cancelled ctx must surface error")
	}
}
