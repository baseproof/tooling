package stack

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/baseproof/baseproof/network"
)

func dsn(host, db string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", pgUser, pgPass, host, db)
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return "…" + s[len(s)-400:]
	}
	return s
}

// caClient builds an HTTPS client pinning caFile (server-verify, no client cert).
func caClient(caFile string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certs in %s", caFile)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}, nil
}

// httpsHealthy reports whether url (server-verified against caFile) returns 200 "ok".
func httpsHealthy(caFile, url string) bool {
	c, err := caClient(caFile)
	if err != nil {
		return false
	}
	resp, err := c.Get(url)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	return resp.StatusCode == 200 && strings.TrimSpace(string(b)) == "ok"
}

// httpStatus GETs a plain-http url, returning its status (0 on transport error).
func httpStatus(url string) int {
	resp, err := http.Get(url)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// resolveRoot finds the tooling repo root (the dir holding go.work, or
// services/ledger/cmd/genesis-ceremony), walking up from the cwd. hint overrides.
func resolveRoot(hint string) (string, error) {
	if hint != "" {
		return filepath.Abs(hint)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := wd; ; {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, "services", "ledger", "cmd", "genesis-ceremony")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find the tooling repo root (need go.work or services/ledger/cmd/genesis-ceremony above %s); set Config.RepoRoot", wd)
		}
		dir = parent
	}
}

// networkIDFromBootstrap derives the network id (the cosign-domain SHA-256 of the
// JCS-canonical bootstrap) from the minted bootstrap doc.
func networkIDFromBootstrap(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("decode bootstrap %s: %w", path, err)
	}
	ids, err := doc.IDs()
	if err != nil {
		return "", fmt.Errorf("bootstrap ids: %w", err)
	}
	return hex.EncodeToString(ids.NetworkID[:]), nil
}
