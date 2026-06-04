// Package clienttls tests pin the contract for the binary's outbound client:
// posture is categorical (MTLS / Plaintext), never silent; half-config is
// startup-fatal; the env-driven and flag-driven entry points share the
// underlying validation.
package clienttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSelfSignedCert produces a self-signed PEM cert + key pair in dir.
// Sufficient for clienttls's loader to consume — actual handshake testing
// lives in the SDK's hermetic TLS tests; here we just need cert+key bytes
// that parse.
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "clienttls-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestFlags_BindRegistersCanonicalNames pins that Bind exposes the three
// vocabulary-aligned flag names callers (and operators reading -h output)
// expect.
func TestFlags_BindRegistersCanonicalNames(t *testing.T) {
	var f Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f.Bind(fs)
	for _, name := range []string{"client-cert", "client-key", "ca-cert"} {
		if fs.Lookup(name) == nil {
			t.Errorf("flag %q not registered", name)
		}
	}
}

// TestFlags_ConfiguredTruthTable pins the "both set" rule.
func TestFlags_ConfiguredTruthTable(t *testing.T) {
	cases := []struct {
		name string
		f    Flags
		want bool
	}{
		{"empty", Flags{}, false},
		{"cert only", Flags{CertFile: "c.pem"}, false},
		{"key only", Flags{KeyFile: "k.pem"}, false},
		{"both", Flags{CertFile: "c.pem", KeyFile: "k.pem"}, true},
		{"both + ca", Flags{CertFile: "c", KeyFile: "k", CAFile: "ca"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.Configured(); got != tc.want {
				t.Errorf("Configured() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFlags_Client_HalfConfigured pins the cert-without-key (and inverse)
// failure path. Half-configured is unambiguously an operator error.
func TestFlags_Client_HalfConfigured(t *testing.T) {
	for _, tc := range []Flags{
		{CertFile: "c.pem"},
		{KeyFile: "k.pem"},
		{CertFile: "c", CAFile: "ca"}, // cert without key
		{KeyFile: "k", CAFile: "ca"},  // key without cert
	} {
		_, posture, err := tc.Client(5 * time.Second)
		if !errors.Is(err, ErrHalfConfigured) {
			t.Errorf("Client(%+v): want ErrHalfConfigured, got %v", tc, err)
		}
		if posture != PostureUnset {
			t.Errorf("Client(%+v): want PostureUnset on error, got %v", tc, posture)
		}
	}
}

// TestFlags_Client_PlaintextWhenUnset pins that empty Flags yields
// PosturePlaintext (the explicit "no mTLS" mode) — not an error.
func TestFlags_Client_PlaintextWhenUnset(t *testing.T) {
	var f Flags
	client, posture, err := f.Client(5 * time.Second)
	if err != nil {
		t.Fatalf("Client(empty Flags): %v", err)
	}
	if posture != PosturePlaintext {
		t.Errorf("posture = %v, want PosturePlaintext", posture)
	}
	if client == nil {
		t.Error("nil client")
	}
}

// TestFlags_Client_MTLSWhenConfigured pins that valid cert+key yields
// PostureMTLS and a non-nil client.
func TestFlags_Client_MTLSWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)
	f := Flags{CertFile: certPath, KeyFile: keyPath}
	client, posture, err := f.Client(5 * time.Second)
	if err != nil {
		t.Fatalf("Client(valid): %v", err)
	}
	if posture != PostureMTLS {
		t.Errorf("posture = %v, want PostureMTLS", posture)
	}
	if client == nil {
		t.Error("nil client")
	}
}

// TestFlags_Client_BadCertFails pins that unreadable / unparseable cert
// material is startup-fatal — never silently demoted.
func TestFlags_Client_BadCertFails(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a real cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := Flags{CertFile: bad, KeyFile: bad}
	_, posture, err := f.Client(5 * time.Second)
	if err == nil {
		t.Fatal("want error on unparseable cert, got nil")
	}
	if posture != PostureUnset {
		t.Errorf("posture = %v, want PostureUnset on error", posture)
	}
}

// TestPostureString pins log output stability — operators grep logs for
// these strings.
func TestPostureString(t *testing.T) {
	cases := []struct {
		p    Posture
		want string
	}{
		{PostureMTLS, "MTLS"},
		{PosturePlaintext, "PLAINTEXT"},
		{PostureUnset, "UNSET"},
	}
	for _, tc := range cases {
		if got := tc.p.String(); got != tc.want {
			t.Errorf("String(%d) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

// TestBuildFromEnv_Plaintext exercises the env-driven entry point with no
// env vars set — should return PosturePlaintext, NOT an error.
func TestBuildFromEnv_Plaintext(t *testing.T) {
	prefix := "TEST_PLAINTEXT_"
	clearEnv(t, prefix)
	client, posture, err := BuildFromEnv(prefix, quietLogger())
	if err != nil {
		t.Fatalf("BuildFromEnv: %v", err)
	}
	if posture != PosturePlaintext {
		t.Errorf("posture = %v, want PosturePlaintext", posture)
	}
	if client == nil {
		t.Error("nil client")
	}
}

// TestBuildFromEnv_MTLS exercises the env-driven entry point with valid cert
// + key set under the prefix — should return PostureMTLS.
func TestBuildFromEnv_MTLS(t *testing.T) {
	prefix := "TEST_MTLS_"
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)
	t.Setenv(prefix+"CLIENT_CERT_FILE", certPath)
	t.Setenv(prefix+"CLIENT_KEY_FILE", keyPath)
	_, posture, err := BuildFromEnv(prefix, quietLogger())
	if err != nil {
		t.Fatalf("BuildFromEnv: %v", err)
	}
	if posture != PostureMTLS {
		t.Errorf("posture = %v, want PostureMTLS", posture)
	}
}

// TestBuildFromEnv_HalfConfigured exercises the half-config rejection on the
// env path.
func TestBuildFromEnv_HalfConfigured(t *testing.T) {
	prefix := "TEST_HALFCONFIG_"
	clearEnv(t, prefix)
	t.Setenv(prefix+"CLIENT_CERT_FILE", "/nonexistent.pem")
	// key deliberately omitted
	_, posture, err := BuildFromEnv(prefix, quietLogger())
	if !errors.Is(err, ErrHalfConfigured) {
		t.Errorf("want ErrHalfConfigured wrapped, got %v", err)
	}
	if posture != PostureUnset {
		t.Errorf("posture = %v, want PostureUnset on error", posture)
	}
}

// TestBuildFromEnv_BadTimeout pins that an unparseable HTTP_TIMEOUT is
// startup-fatal — the binary refuses to start with a meaningless timeout.
func TestBuildFromEnv_BadTimeout(t *testing.T) {
	prefix := "TEST_BADTIMEOUT_"
	clearEnv(t, prefix)
	t.Setenv(prefix+"HTTP_TIMEOUT", "not-a-duration")
	_, _, err := BuildFromEnv(prefix, quietLogger())
	if err == nil {
		t.Fatal("want error on unparseable HTTP_TIMEOUT, got nil")
	}
}

// clearEnv unsets every clienttls env var under the prefix so a test can
// start from a known-empty state regardless of host env.
func clearEnv(t *testing.T, prefix string) {
	t.Helper()
	for _, suffix := range []string{"CLIENT_CERT_FILE", "CLIENT_KEY_FILE", "CA_FILE", "HTTP_TIMEOUT"} {
		t.Setenv(prefix+suffix, "")
	}
}
