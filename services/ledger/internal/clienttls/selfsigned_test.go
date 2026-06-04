package clienttls

import (
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// openHTTPSServer presents the bundle's server cert and does NOT request a
// client cert (tls.NoClientCert) — the ledger's new open-HTTPS posture.
func openHTTPSServer(t *testing.T, b *pkiBundle) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{b.serverCert}, ClientAuth: tls.NoClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// writeServerCAFile writes the CA that signed the SERVER cert to a PEM file the
// client pins via -ca-cert.
func writeServerCAFile(t *testing.T, b *pkiBundle) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(p, b.clientCACerts, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func getOK(t *testing.T, tlsCfg *tls.Config, url string) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("open-HTTPS GET failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("GET = (%d, %q), want (200, \"ok\")", resp.StatusCode, body)
	}
}

// FUNCTIONAL: -allow-self-signed + -ca-cert, no client cert → a server-verify
// config (RootCAs pinned, no client cert) that completes a real handshake
// against an open-HTTPS server. This is the submit-stamp/backfill/audit path
// against the now-open ledger.
func TestTLSConfig_AllowSelfSigned_ReachesOpenLedger(t *testing.T) {
	b := buildPKI(t)
	srv := openHTTPSServer(t, b)
	tlsCfg, err := (&Flags{CAFile: writeServerCAFile(t, b), AllowSelfSigned: true}).TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tlsCfg == nil || tlsCfg.RootCAs == nil {
		t.Fatal("server-verify config must pin RootCAs")
	}
	if len(tlsCfg.Certificates) != 0 {
		t.Fatal("server-verify config must present NO client cert")
	}
	getOK(t, tlsCfg, srv.URL)
}

// A CA with no client cert (and no -allow-self-signed) still pins the CA —
// honoring it never weakens verification.
func TestTLSConfig_CAOnly_HonorsPinWithoutClientCert(t *testing.T) {
	b := buildPKI(t)
	srv := openHTTPSServer(t, b)
	tlsCfg, err := (&Flags{CAFile: writeServerCAFile(t, b)}).TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tlsCfg == nil || tlsCfg.RootCAs == nil {
		t.Fatal("CA-only config must pin RootCAs even without a client cert")
	}
	getOK(t, tlsCfg, srv.URL)
}

// -allow-self-signed with no -ca-cert is startup-fatal (no silent skip-verify).
func TestTLSConfig_AllowSelfSigned_NoCAFailsClosed(t *testing.T) {
	if _, err := (&Flags{AllowSelfSigned: true}).TLSConfig(); !errors.Is(err, ErrSelfSignedNoCA) {
		t.Fatalf("err = %v, want ErrSelfSignedNoCA", err)
	}
}

func TestBind_RegistersAllowSelfSigned(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	f.Bind(fs)
	if err := fs.Parse([]string{"-allow-self-signed"}); err != nil {
		t.Fatal(err)
	}
	if !f.AllowSelfSigned {
		t.Error("-allow-self-signed did not set AllowSelfSigned")
	}
}
