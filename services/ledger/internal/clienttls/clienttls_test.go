/*
FILE PATH: internal/clienttls/clienttls_test.go

Contract tests for the shared mTLS-flag helper. Pins:
  - Configured() returns false on zero value, true only when BOTH cert
    and key are set.
  - TLSConfig() returns (nil, nil) when not configured — the cue for
    callers to compose their non-mTLS client.
  - TLSConfig() returns a *tls.Config that completes an mTLS handshake
    against a server that REQUIRES a verified client cert (the exact
    posture the ledger's server enforces).
  - TLSConfig() returns a non-nil error when cert/key files don't
    parse — the operator's mTLS intent is honored as fail-closed, not
    silently demoted.
  - Bind() exposes the canonical flag names.

The round-trip test uses SEPARATE client + server certs signed by a
dedicated CA. This exercises the production-shaped trust path
(client presents cert signed by CA-A; server presents cert signed by
CA-B; CAFile pins CA-B, ClientCAs pins CA-A). The previous version of
this test used a self-signed cert for all three roles — a CA-pinning
bug would not have surfaced.
*/
package clienttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
)

// pkiBundle holds the cert/key file paths for a 3-tier PKI used in
// the round-trip test: distinct CA-signed client cert and CA-signed
// server cert. The server's CA verifies the client; the client's CA
// verifies the server. This is the production mTLS trust shape.
type pkiBundle struct {
	// Client side
	clientCertFile string
	clientKeyFile  string
	clientCACerts  []byte // PEM of the CA that signed the SERVER's cert (client pins this)

	// Server side
	serverCert      tls.Certificate
	serverClientCAs *x509.CertPool // CA that signed the CLIENT's cert (server pins this)
}

func buildPKI(t *testing.T) *pkiBundle {
	t.Helper()
	dir := t.TempDir()

	// CA-A: signs the CLIENT cert. Server pins CA-A as ClientCAs.
	caAKey, caACert := mkCA(t, "client-ca")
	// CA-B: signs the SERVER cert. Client pins CA-B as RootCAs.
	caBKey, caBCert := mkCA(t, "server-ca")

	// Client cert signed by CA-A.
	clientKey, clientCertDER := mkLeaf(t, caAKey, caACert, "test-client", false)
	clientCertFile := filepath.Join(dir, "client.crt")
	clientKeyFile := filepath.Join(dir, "client.key")
	writePEM(t, clientCertFile, "CERTIFICATE", clientCertDER)
	writePEMKey(t, clientKeyFile, clientKey)

	// Server cert signed by CA-B.
	serverKey, serverCertDER := mkLeaf(t, caBKey, caBCert, "test-server", true)
	serverCertFile := filepath.Join(dir, "server.crt")
	serverKeyFile := filepath.Join(dir, "server.key")
	writePEM(t, serverCertFile, "CERTIFICATE", serverCertDER)
	writePEMKey(t, serverKeyFile, serverKey)
	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair server: %v", err)
	}

	// Server's pool of CAs whose-signed CLIENT-certs the server trusts.
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caACert)

	// Client's PEM of CA(s) whose-signed SERVER-certs the client trusts.
	caBPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBCert.Raw})

	return &pkiBundle{
		clientCertFile:  clientCertFile,
		clientKeyFile:   clientKeyFile,
		clientCACerts:   caBPEM,
		serverCert:      serverCert,
		serverClientCAs: clientCAs,
	}
}

func mkCA(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
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

func mkLeaf(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, cn string, server bool) (*ecdsa.PrivateKey, []byte) {
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

func writePEM(t *testing.T, path, blockType string, der []byte) {
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

func writePEMKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	writePEM(t, path, "EC PRIVATE KEY", der)
}

func TestFlags_Configured(t *testing.T) {
	var f Flags
	if f.Configured() {
		t.Error("zero Flags should not be Configured")
	}
	f.CertFile = "c"
	if f.Configured() {
		t.Error("CertFile alone should not be Configured (need key too)")
	}
	f.KeyFile = "k"
	if !f.Configured() {
		t.Error("cert+key set should be Configured")
	}
	f.CertFile = ""
	if f.Configured() {
		t.Error("key alone should not be Configured")
	}
}

func TestFlags_Bind_RegistersCanonicalNames(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Bind(fs)
	for _, name := range []string{"client-cert", "client-key", "ca-cert"} {
		if fs.Lookup(name) == nil {
			t.Errorf("flag %q not registered", name)
		}
	}
}

func TestFlags_TLSConfig_UnconfiguredReturnsNilNil(t *testing.T) {
	var f Flags
	tlsCfg, err := f.TLSConfig()
	if err != nil {
		t.Fatalf("unexpected err on unconfigured Flags: %v", err)
	}
	if tlsCfg != nil {
		t.Fatalf("expected nil *tls.Config on unconfigured Flags, got %+v", tlsCfg)
	}
}

func TestFlags_TLSConfig_MalformedFilesFailClosed(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, []byte("not-a-cert"), 0o600)
	f := Flags{CertFile: bad, KeyFile: bad}
	if _, err := f.TLSConfig(); err == nil {
		t.Fatal("expected fail-closed on malformed cert/key, got nil err")
	}
}

// TestFlags_TLSConfig_RoundTrip is the load-bearing test: an mTLS
// handshake against a server that REQUIRES a verified client cert
// (the ledger's RequireAndVerifyClientCert posture) succeeds with
// SEPARATE client/server certs signed by SEPARATE CAs — proving the
// CA pinning is honored (CAFile pins the server's CA; the client's
// CA is on the server). A self-signed-for-all-three test would pass
// even if CA pinning were broken; this one wouldn't.
func TestFlags_TLSConfig_RoundTrip(t *testing.T) {
	pki := buildPKI(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert presented", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.serverClientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	defer srv.Close()

	// CAFile points at the SERVER's CA — that's what the CLIENT verifies
	// the server cert against.
	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caFile, pki.clientCACerts, 0o600); err != nil {
		t.Fatalf("write server-ca.pem: %v", err)
	}

	f := Flags{
		CertFile: pki.clientCertFile,
		KeyFile:  pki.clientKeyFile,
		CAFile:   caFile,
	}
	tlsCfg, err := f.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig(): %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("TLSConfig() returned nil for configured Flags")
	}

	hc := sdklog.DefaultClient(5*time.Second, tlsCfg)
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "test-client" {
		t.Errorf("server saw CN %q, want %q", got, "test-client")
	}
}

// TestFlags_TLSConfig_WrongCAFailsClosed pins the negative: a client
// configured with the WRONG CAFile (pinning a CA that did not sign
// the server's cert) MUST fail the handshake. If the round-trip test
// were the only check, a no-op CAFile (system roots fallback) could
// accidentally pass against a publicly-trusted server.
func TestFlags_TLSConfig_WrongCAFailsClosed(t *testing.T) {
	pki := buildPKI(t)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.serverCert},
		ClientCAs:    pki.serverClientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	defer srv.Close()

	// Use a SECOND, unrelated CA file as the trust anchor — handshake
	// must fail because the server's cert isn't signed by it.
	wrongCAKey, wrongCACert := mkCA(t, "wrong-ca")
	_ = wrongCAKey // unused, just need the cert
	wrongCAFile := filepath.Join(t.TempDir(), "wrong-ca.pem")
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongCACert.Raw})
	if err := os.WriteFile(wrongCAFile, wrongPEM, 0o600); err != nil {
		t.Fatalf("write wrong-ca.pem: %v", err)
	}

	f := Flags{
		CertFile: pki.clientCertFile,
		KeyFile:  pki.clientKeyFile,
		CAFile:   wrongCAFile,
	}
	tlsCfg, err := f.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig(): %v", err)
	}

	hc := sdklog.DefaultClient(2*time.Second, tlsCfg)
	if _, err := hc.Get(srv.URL); err == nil {
		t.Fatal("expected handshake error with wrong CAFile, got success — CA pinning is broken")
	}
}
