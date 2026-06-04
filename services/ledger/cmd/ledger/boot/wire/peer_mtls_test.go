// Tests for peer-mTLS outbound client wiring.
//
// FILE PATH:
//
//	cmd/ledger/boot/wire/peer_mtls_test.go
//
// What we test here:
//
//   - buildPeerHTTPClient — three cases: unconfigured (nil/nil),
//     configured + good certs (*http.Client/nil), configured + bad
//     certs (nil/err). Pinned without driving the whole Wire graph.
//
//   - Threading regression guard: every Config-struct literal in
//     wire.go + gossip.go that has an `HTTPClient` field MUST set it
//     to `d.OutboundHTTPClient`. If a future contributor adds a new
//     outbound component and forgets the `HTTPClient: d.OutboundHTTPClient`
//     line, the AST walker here flags it.
//
// The threading test is structural, not a runtime test of Wire(). A
// runtime test would need Postgres + Badger + Tessera POSIX which the
// wire-package tests deliberately don't pull in. The structural form
// catches the exact bug class the reviewer flagged ("a bug that drops
// OutboundHTTPClient on one of the four sites wouldn't be caught")
// without bringing the infrastructure tax.
package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildPeerHTTPClient_Unconfigured_ReturnsPlaintextClient pins the
// v1.34 contract: buildPeerHTTPClient ALWAYS returns a non-nil
// *http.Client. When no mTLS material is configured, the returned
// client is plaintext (TLSClientConfig nil) and carries the SDK's
// RetryAfterRoundTripper.
//
// Replaces the pre-v1.34 TestBuildPeerHTTPClient_Unconfigured_ReturnsNil
// which pinned the removed silent-nil-fallback behavior. Downstream
// SDK constructors (gossip, cosign, head-sync, anti-entropy,
// equivocation monitor) reject a nil *http.Client at construction
// time per baseproof v1.34 CHANGELOG; matching the contract here means
// every plaintext-dev boot still gets a working outbound transport.
func TestBuildPeerHTTPClient_Unconfigured_ReturnsPlaintextClient(t *testing.T) {
	c, err := buildPeerHTTPClient(Config{})
	if err != nil {
		t.Fatalf("unexpected err on unconfigured Config: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil *http.Client (plaintext), got nil")
	}
	if c.Timeout != 30*time.Second {
		t.Errorf("client Timeout = %v, want 30s (SDK DefaultClient posture)", c.Timeout)
	}
	if c.Transport == nil {
		t.Error("client Transport = nil, want non-nil RetryAfterRoundTripper")
	}
}

func TestBuildPeerHTTPClient_ConfiguredButMalformed_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatalf("write bad.pem: %v", err)
	}
	_, err := buildPeerHTTPClient(Config{
		PeerClientCertFile: bad,
		PeerClientKeyFile:  bad,
	})
	if err == nil {
		t.Fatal("expected error on malformed cert/key, got nil — would silently demote to plaintext")
	}
}

func TestBuildPeerHTTPClient_Configured_ReturnsClient(t *testing.T) {
	pki := buildWirePKI(t)
	c, err := buildPeerHTTPClient(Config{
		PeerClientCertFile: pki.clientCertFile,
		PeerClientKeyFile:  pki.clientKeyFile,
		PeerCAFile:         pki.serverCAFile, // pins the server's CA — NOT the client's own cert
	})
	if err != nil {
		t.Fatalf("unexpected err on valid config: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil *http.Client on valid config")
	}
	if c.Timeout != 30*time.Second {
		t.Errorf("client Timeout = %v, want 30s (SDK DefaultClient posture)", c.Timeout)
	}
}

// TestBuildPeerHTTPClient_RoundTrip_SeparatePKI pins the production
// mTLS trust shape: client cert signed by CA-A, server cert signed by
// CA-B, PeerCAFile points at CA-B (NOT CA-A). A CA-pinning bug — the
// client trusting any cert signed by ITS OWN CA rather than the
// designated server CA — would not surface in a self-signed-as-own-CA
// test. This one would: it stands up a TLS server using a server cert
// signed by CA-B and asserts the buildPeerHTTPClient-constructed client
// completes the handshake AND that swapping in CA-A as PeerCAFile fails.
func TestBuildPeerHTTPClient_RoundTrip_SeparatePKI(t *testing.T) {
	pki := buildWirePKI(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	defer srv.Close()

	// Happy path: correct PeerCAFile (server CA) succeeds.
	c, err := buildPeerHTTPClient(Config{
		PeerClientCertFile: pki.clientCertFile,
		PeerClientKeyFile:  pki.clientKeyFile,
		PeerCAFile:         pki.serverCAFile,
	})
	if err != nil {
		t.Fatalf("buildPeerHTTPClient: %v", err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET (correct PKI): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d (want 200) — handshake failed", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "wire-test-client" {
		t.Errorf("server saw client CN %q, want %q", body, "wire-test-client")
	}

	// Negative path: PeerCAFile pointing at the WRONG CA (the client's
	// own CA, NOT the server's) must fail the handshake. This is the
	// concrete check the previous "self-signed cert as own CA" test
	// could not have done.
	wrong, err := buildPeerHTTPClient(Config{
		PeerClientCertFile: pki.clientCertFile,
		PeerClientKeyFile:  pki.clientKeyFile,
		PeerCAFile:         pki.clientCAFile, // pins WRONG CA — should fail
	})
	if err != nil {
		t.Fatalf("buildPeerHTTPClient (wrong CA): %v", err)
	}
	if _, err := wrong.Get(srv.URL); err == nil {
		t.Fatal("expected handshake failure when PeerCAFile points at wrong CA — CA pinning is broken")
	}
}

// wirePKI carries a 3-tier PKI: a client cert signed by CA-A and a
// server cert signed by CA-B. Distinct from clienttls's identical
// helper because that's package-private; reproducing here keeps the
// wire-package tests self-contained.
type wirePKI struct {
	clientCertFile string
	clientKeyFile  string
	clientCAFile   string // PEM of CA-A (signs client cert); the server pins this
	serverCAFile   string // PEM of CA-B (signs server cert); the client pins this
	serverCert     tls.Certificate
	clientCAs      *x509.CertPool // server's pool of CAs whose-signed CLIENT-certs it trusts
}

func buildWirePKI(t *testing.T) *wirePKI {
	t.Helper()
	dir := t.TempDir()

	caAKey, caACert := mkWireCA(t, "client-ca")
	caBKey, caBCert := mkWireCA(t, "server-ca")

	// Client leaf signed by CA-A.
	clientKey, clientCertDER := mkWireLeaf(t, caAKey, caACert, "wire-test-client", false)
	clientCertFile := filepath.Join(dir, "client.crt")
	clientKeyFile := filepath.Join(dir, "client.key")
	writeWirePEM(t, clientCertFile, "CERTIFICATE", clientCertDER)
	writeWirePEMKey(t, clientKeyFile, clientKey)

	// Server leaf signed by CA-B.
	serverKey, serverCertDER := mkWireLeaf(t, caBKey, caBCert, "wire-test-server", true)
	serverCertFile := filepath.Join(dir, "server.crt")
	serverKeyFile := filepath.Join(dir, "server.key")
	writeWirePEM(t, serverCertFile, "CERTIFICATE", serverCertDER)
	writeWirePEMKey(t, serverKeyFile, serverKey)
	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair server: %v", err)
	}

	// CA PEM files (for the client to load via PeerCAFile).
	clientCAFile := filepath.Join(dir, "client-ca.pem")
	writeWirePEM(t, clientCAFile, "CERTIFICATE", caACert.Raw)
	serverCAFile := filepath.Join(dir, "server-ca.pem")
	writeWirePEM(t, serverCAFile, "CERTIFICATE", caBCert.Raw)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caACert)

	return &wirePKI{
		clientCertFile: clientCertFile,
		clientKeyFile:  clientKeyFile,
		clientCAFile:   clientCAFile,
		serverCAFile:   serverCAFile,
		serverCert:     serverCert,
		clientCAs:      clientCAs,
	}
}

func mkWireCA(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey CA %q: %v", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate CA %q: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate CA %q: %v", cn, err)
	}
	return key, cert
}

func mkWireLeaf(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, cn string, server bool) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey leaf %q: %v", cn, err)
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if server {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate leaf %q: %v", cn, err)
	}
	return key, der
}

func writeWirePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("PEM encode %s: %v", path, err)
	}
}

func writeWirePEMKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	writeWirePEM(t, path, "EC PRIVATE KEY", der)
}

// TestWiring_AllHTTPClientFieldsUseOutboundHTTPClient is the
// structural regression guard. It parses wire.go + gossip.go with
// go/ast and finds every `Config{...}`-shape literal (anchor,
// witnessclient, gossipnet) that has an `HTTPClient` field. Each MUST
// set it to `d.OutboundHTTPClient` — anything else (literal nil, a
// fresh sdklog client, a local variable) silently drops the peer
// mTLS posture for that outbound surface.
//
// The reviewer's concern: "a bug that drops OutboundHTTPClient on one
// of the four sites (anchor, witness, anti-entropy, equivocation
// monitor) wouldn't be caught." This test catches it.
func TestWiring_AllHTTPClientFieldsUseOutboundHTTPClient(t *testing.T) {
	const want = "d.OutboundHTTPClient"
	files := []string{"wire.go", "gossip.go"}
	for _, fname := range files {
		t.Run(fname, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, fname, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", fname, err)
			}
			var violations []string
			ast.Inspect(f, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				for _, elt := range cl.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					ident, ok := kv.Key.(*ast.Ident)
					if !ok || ident.Name != "HTTPClient" {
						continue
					}
					// Render the value side and assert it's the expected
					// canonical reference. Anything else is a bug.
					pos := fset.Position(kv.Pos())
					got := exprString(kv.Value)
					if got != want {
						violations = append(violations,
							pos.String()+": HTTPClient = "+got+"  (want "+want+")")
					}
				}
				return true
			})
			if len(violations) > 0 {
				t.Errorf("%s: %d HTTPClient field(s) do not thread d.OutboundHTTPClient:\n  %s",
					fname, len(violations), strings.Join(violations, "\n  "))
			}
		})
	}
}

// exprString renders an ast.Expr into the canonical "pkg.Field" or
// "ident" string we're matching against. We only need the cases the
// HTTPClient values can actually take here — selector expression
// (a.b) and bare ident (foo). Anything else returns its type name so
// the failure message is useful.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		base, ok := v.X.(*ast.Ident)
		if !ok {
			return "<non-ident-selector>"
		}
		return base.Name + "." + v.Sel.Name
	case *ast.Ident:
		return v.Name
	default:
		return "<unrecognized-expr>"
	}
}
