package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Open HTTPS: with no ClientCAFile the ledger serves a TLS listener that does
// NOT require a client cert — reads are open, writes are gated by crypto
// (admission + the in-body G5 signature), per the zero-trust transparency model.
func TestBuildServerTLSConfig_OpenHTTPSWhenNoClientCA(t *testing.T) {
	s := &Server{
		cfg:    ServerConfig{TLSCertFile: "x.crt", TLSKeyFile: "x.key"}, // no ClientCAFile
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	cfg, err := s.buildServerTLSConfig()
	if err != nil {
		t.Fatalf("open HTTPS (no ClientCAFile) must not error: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert (open HTTPS — writes gated by crypto, not transport)", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("ClientCAs must be nil when serving open HTTPS")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3 (%x)", cfg.MinVersion, tls.VersionTLS13)
	}
}

func TestBuildServerTLSConfig_RejectsBadCAFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		cfg:    ServerConfig{TLSCertFile: "x.crt", TLSKeyFile: "x.key", ClientCAFile: bad},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if _, err := s.buildServerTLSConfig(); err == nil {
		t.Fatal("expected error for unparseable CA, got nil")
	}
}

func TestBuildServerTLSConfig_EnforcesMTLS(t *testing.T) {
	dir := t.TempDir()
	caPath := writeSelfSignedTestCert(t, dir, "ca")

	s := &Server{
		cfg: ServerConfig{
			TLSCertFile:  "x.crt",
			TLSKeyFile:   "x.key",
			ClientCAFile: caPath,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	cfg, err := s.buildServerTLSConfig()
	if err != nil {
		t.Fatalf("buildServerTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3 (%x)", cfg.MinVersion, tls.VersionTLS13)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil, want pool from CA file")
	}
	if want := []string{"h2", "http/1.1"}; len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != want[0] || cfg.NextProtos[1] != want[1] {
		t.Errorf("NextProtos = %v, want %v", cfg.NextProtos, want)
	}
}

func writeSelfSignedTestCert(t *testing.T, dir, name string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name+".pem")
	if err := os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}
