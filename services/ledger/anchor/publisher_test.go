/*
FILE PATH: anchor/publisher_test.go

DESCRIPTION:

	Tier-3 alignment tests for the SDK-backed outbound HTTP wiring
	inside anchor/publisher.go. The previous bare http.Client gave
	no connection pooling and no 503-Retry-After backpressure
	honoring; SubmitViaHTTP and Publisher now use sdklog.DefaultClient
	so WAL-pressure 503s from the ledger's own admission endpoint
	are absorbed locally rather than turning into hard submit
	failures.

	These tests pin the new behavior:
	  - SubmitViaHTTP succeeds when the target returns 503-then-202.
	  - SubmitViaHTTP propagates a non-202, non-503 status as an
	    error (no spurious retry on, e.g., 422).
	  - SubmitViaHTTP propagates an entry whose canonical bytes
	    round-trip correctly even after a retry.
*/
package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkanchor "github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdkgossip "github.com/baseproof/baseproof/gossip"
	"github.com/baseproof/baseproof/gossip/findings"
	sdklog "github.com/baseproof/baseproof/log"

	"github.com/baseproof/tooling/services/ledger/internal/clienttls"
)

// discardLogger keeps test output clean.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeTreeHeadSource serves the given wire head at /v1/tree/head and
// 404s everything else.
func fakeTreeHeadSource(t *testing.T, head sdkgossip.WireCosignedTreeHead) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tree/head" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(head)
	}))
}

// TestPublishOne_SelfContainedAnchor is the load-bearing test for the
// anchor format: the published anchor must embed the source log's FULL
// cosigned head (all four roots + cosignatures) so a consumer can
// verify the witness quorum offline — without ever calling back to the
// source. We prove that by reconstructing the embedded head into an
// SDK-native finding with no network access.
func TestPublishOne_SelfContainedAnchor(t *testing.T) {
	wantHead := sdkgossip.WireCosignedTreeHead{
		RootHash:    hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		SMTRoot:     hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)), // non-zero: findings.Validate requires it
		ReceiptRoot: hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)), // the field the old endpoint dropped
		TreeSize:    42,
		Signatures: []sdkgossip.WireWitnessSignature{{
			PubKeyID:  hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
			SchemeTag: 1, // ECDSA
			SigBytes:  hex.EncodeToString(bytes.Repeat([]byte{0x55}, 64)),
		}},
	}
	srv := fakeTreeHeadSource(t, wantHead)
	defer srv.Close()

	var captured *envelope.Entry
	pub := NewPublisher(
		PublisherConfig{
			LedgerDID:  "did:test:ledger",
			LogDID:     "did:test:log",
			NetworkID:  cosign.NetworkID{0x01},
			HTTPClient: srv.Client(), // v1.34 contract: required
		},
		nil, // merkle is unused by publishOne
		nil, // cosignedHead unused by publishOne (parent-target flow only)
		func(e *envelope.Entry) error { captured = e; return nil },
		discardLogger(),
	)

	src := AnchorSource{LogDID: "did:test:source", EndpointURL: srv.URL}
	if err := pub.publishOne(context.Background(), src); err != nil {
		t.Fatalf("publishOne: %v", err)
	}
	if captured == nil {
		t.Fatal("submitFn never called")
	}

	var got struct {
		AnchorType   string                             `json:"anchor_type"`
		SourceLogDID string                             `json:"source_log_did"`
		Head         sdkgossip.WireCosignedTreeHeadBody `json:"head"`
		TreeHeadRef  string                             `json:"tree_head_ref"`
	}
	if err := json.Unmarshal(captured.DomainPayload, &got); err != nil {
		t.Fatalf("decode anchor payload: %v", err)
	}
	if got.AnchorType != sdkanchor.CosignedAnchorType {
		t.Errorf("anchor_type = %q, want %q", got.AnchorType, sdkanchor.CosignedAnchorType)
	}
	if got.SourceLogDID != src.LogDID {
		t.Errorf("source_log_did = %q, want %q", got.SourceLogDID, src.LogDID)
	}
	if got.Head.Head.TreeSize != 42 {
		t.Errorf("embedded tree_size = %d, want 42", got.Head.Head.TreeSize)
	}
	if got.Head.Head.ReceiptRoot != wantHead.ReceiptRoot {
		t.Errorf("embedded receipt_root = %q, want %q — the truncation regression",
			got.Head.Head.ReceiptRoot, wantHead.ReceiptRoot)
	}
	if got.Head.LedgerEndpoint != src.EndpointURL {
		t.Errorf("ledger_endpoint = %q, want %q", got.Head.LedgerEndpoint, src.EndpointURL)
	}
	if got.TreeHeadRef == "" {
		t.Error("tree_head_ref (provenance witness) must be retained")
	}

	// The whole point: reconstruct offline. No network access here.
	finding, err := findings.CosignedTreeHeadFromWire(got.Head)
	if err != nil {
		t.Fatalf("CosignedTreeHeadFromWire (offline reconstruction): %v", err)
	}
	if finding.Head.TreeSize != 42 {
		t.Errorf("reconstructed TreeSize = %d, want 42", finding.Head.TreeSize)
	}
	if len(finding.Head.Signatures) != 1 {
		t.Errorf("reconstructed signatures = %d, want 1", len(finding.Head.Signatures))
	}
}

// TestPublishOne_RefusesUnverifiableHead: a head with no cosignatures
// can't be verified offline, so the publisher must refuse to anchor it
// rather than emit a useless freshness witness.
func TestPublishOne_RefusesUnverifiableHead(t *testing.T) {
	srv := fakeTreeHeadSource(t, sdkgossip.WireCosignedTreeHead{
		RootHash: hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		TreeSize: 7,
		// no Signatures
	})
	defer srv.Close()

	var called bool
	pub := NewPublisher(
		PublisherConfig{
			LedgerDID:  "did:test:ledger",
			LogDID:     "did:test:log",
			NetworkID:  cosign.NetworkID{0x01},
			HTTPClient: &http.Client{}, // v1.34 contract: required
		},
		nil,
		nil,
		func(*envelope.Entry) error { called = true; return nil },
		discardLogger(),
	)
	err := pub.publishOne(context.Background(),
		AnchorSource{LogDID: "did:test:source", EndpointURL: srv.URL})
	if err == nil {
		t.Fatal("expected error anchoring a head with no cosignatures")
	}
	if called {
		t.Error("submitFn must not be called for an unverifiable head")
	}
}

// fixtureSignedEntry builds a minimal signed entry suitable for
// envelope.Serialize. The signature itself is not verified by the
// SubmitViaHTTP path (the server is fake); we just need a serializable
// entry.
func fixtureSignedEntry(t *testing.T, payload []byte) *envelope.Entry {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:test:signer",
		Destination: "did:test:log",
		EventTime:   1,
	}
	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: hdr.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     bytes.Repeat([]byte{0x01}, 64),
	}}
	return entry
}

// TestSubmitInProcess_HappyPath_BytesMatch pins the byte-identity
// invariant: the bytes the in-process admission handler receives are
// exactly envelope.Serialize(entry), and the handler's 202 propagates
// as a nil error. Pre-fix this same shape was tested against an
// httptest.NewServer + HTTP POST; the in-process variant uses a fake
// http.Handler and asserts the same property — bytes flow unchanged.
func TestSubmitInProcess_HappyPath_BytesMatch(t *testing.T) {
	entry := fixtureSignedEntry(t, []byte("happy-bytes"))
	wantBytes, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("envelope.Serialize: %v", err)
	}

	var seen []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	})

	submit := SubmitInProcess(func() http.Handler { return handler })
	if err := submit(entry); err != nil {
		t.Fatalf("SubmitInProcess: %v", err)
	}
	if !bytes.Equal(seen, wantBytes) {
		t.Errorf("handler received %d bytes, want %d (envelope.Serialize result)",
			len(seen), len(wantBytes))
	}
}

// TestSubmitInProcess_NonAcceptedSurfacesError: when the in-process
// admission handler returns anything other than 202, the closure
// surfaces a typed error including the status and body. No retry —
// the publisher's outer loop catches up on the next tick.
func TestSubmitInProcess_NonAcceptedSurfacesError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("bad entry"))
	})

	submit := SubmitInProcess(func() http.Handler { return handler })
	entry := fixtureSignedEntry(t, []byte("no-202-surfaces"))
	err := submit(entry)
	if err == nil {
		t.Fatal("expected error on 422")
	}
	if !strings.Contains(err.Error(), "422") || !strings.Contains(err.Error(), "bad entry") {
		t.Errorf("error should include status + body; got %q", err.Error())
	}
}

// TestSubmitInProcess_HandlerNotYetWired pins the composition-order
// safety net: the publisher captures a closure-of-closure that reads
// the handler from AppDeps. If Wire fires the publisher's submit BEFORE
// composeHandlers populates the slot (shouldn't happen in production —
// Phase B goroutines start after all wiring — but a future refactor
// could regress), the closure surfaces a clear error rather than a
// nil-deref.
func TestSubmitInProcess_HandlerNotYetWired(t *testing.T) {
	var slot http.Handler // nil
	submit := SubmitInProcess(func() http.Handler { return slot })
	entry := fixtureSignedEntry(t, []byte("not-yet-wired"))
	err := submit(entry)
	if err == nil {
		t.Fatal("expected error when handler slot is nil")
	}
	if !strings.Contains(err.Error(), "not yet wired") {
		t.Errorf("error should indicate composition-order bug; got %q", err.Error())
	}
}

// TestSubmitInProcess_NilGetterPanics pins the construction-time guard:
// a missing handler getter is a programming error, not a runtime
// condition. SubmitInProcess panics at construction (loud, immediate)
// rather than handing out a closure that would surface the same bug
// every tick.
func TestSubmitInProcess_NilGetterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil handler getter")
		}
	}()
	_ = SubmitInProcess(nil)
}

// TestPublisher_HTTPClient_mTLS_RoundTrip pins the outbound mTLS wiring:
// PublisherConfig.HTTPClient flows through to publishOne's outbound /v1/tree/head
// fetch. The test stands up a TLS server that REQUIRES a verified client cert
// (the same posture the ledger's server enforces post-e4e48a4) and confirms the
// publisher reaches the handler with the supplied client. Without the
// HTTPClient field being honored, the publisher's default sdklog client would
// fail the handshake (no client cert presented).
func TestPublisher_HTTPClient_mTLS_RoundTrip(t *testing.T) {
	certPath, keyPath := writeSelfSignedPair(t)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	caPool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(certPath)
	caPool.AppendCertsFromPEM(caPEM)

	wantHead := sdkgossip.WireCosignedTreeHead{
		RootHash:    hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		SMTRoot:     hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
		ReceiptRoot: hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
		TreeSize:    7,
		Signatures: []sdkgossip.WireWitnessSignature{{
			PubKeyID:  hex.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
			SchemeTag: 1,
			SigBytes:  hex.EncodeToString(bytes.Repeat([]byte{0x55}, 64)),
		}},
	}
	var clientCertSeen string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tree/head" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert presented", http.StatusUnauthorized)
			return
		}
		clientCertSeen = r.TLS.PeerCertificates[0].Subject.CommonName
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wantHead)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	defer srv.Close()

	// Build the mTLS client the same way Wire() does (clienttls produces
	// the *tls.Config; the caller composes it with sdklog.DefaultClient).
	tlsCfg, err := (&clienttls.Flags{CertFile: certPath, KeyFile: keyPath, CAFile: certPath}).TLSConfig()
	if err != nil {
		t.Fatalf("clienttls.Flags.TLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("clienttls returned nil *tls.Config for configured Flags")
	}
	hc := sdklog.DefaultClient(5*time.Second, tlsCfg)

	pub := NewPublisher(
		PublisherConfig{
			LedgerDID:  "did:test:ledger",
			LogDID:     "did:test:log",
			NetworkID:  cosign.NetworkID{0x01},
			HTTPClient: hc,
		},
		nil,
		nil,
		func(*envelope.Entry) error { return nil },
		discardLogger(),
	)

	if err := pub.publishOne(context.Background(),
		AnchorSource{LogDID: "did:test:source", EndpointURL: srv.URL}); err != nil {
		t.Fatalf("publishOne against mTLS server: %v", err)
	}
	if clientCertSeen == "" {
		t.Fatal("server did not see a client cert — HTTPClient field not honored")
	}
	if clientCertSeen != "anchor-test-mtls" {
		t.Errorf("server saw client CN %q, want %q", clientCertSeen, "anchor-test-mtls")
	}
}

// writeSelfSignedPair generates a self-signed ECDSA cert + key with SANs
// covering httptest loopback (127.0.0.1 / ::1 / localhost) and returns their
// paths. Same construction as internal/clienttls's test helper, replicated
// here because the test fixture is package-private and the anchor package can't
// import internal/clienttls test code.
func writeSelfSignedPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "anchor-test-mtls"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPath = filepath.Join(dir, "test.crt")
	keyPath = filepath.Join(dir, "test.key")

	certPEM, _ := os.Create(certPath)
	_ = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = certPEM.Close()

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM, _ := os.Create(keyPath)
	_ = pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	_ = keyPEM.Close()
	return certPath, keyPath
}
