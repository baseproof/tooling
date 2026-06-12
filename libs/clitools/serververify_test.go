package clitools

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// writeLeafAsCA writes the httptest server's self-signed leaf as a CA-pin file.
func writeLeafAsCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// treeHeadServer is an open-HTTPS (no client cert) ledger stub answering
// /v1/tree/head — enough to prove the CA-pinned handshake completes.
func treeHeadServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tree/head", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tree_size": 1})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// FUNCTIONAL: the server-verify ledger client pins the CA, presents NO client
// cert, and completes a real GET against an open-HTTPS ledger. This is the
// aggregator's open scan path against the now-open ledger.
func TestNewServerVerifyLedgerClient_ReachesOpenLedger(t *testing.T) {
	srv := treeHeadServer(t)
	c, err := NewServerVerifyLedgerClient(srv.URL, writeLeafAsCA(t, srv), "")
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	head, err := c.TreeHead()
	if err != nil {
		t.Fatalf("TreeHead over CA-pinned server-verify failed: %v", err)
	}
	if head["tree_size"] == nil {
		t.Fatalf("unexpected head payload: %v", head)
	}
}

// FUNCTIONAL negative: the plaintext client (system roots) REJECTS the same
// privately-signed ledger — proving the pin is what makes server-verify work.
func TestNewLedgerClient_SystemRoots_RejectsPrivate(t *testing.T) {
	srv := treeHeadServer(t)
	c, err := NewLedgerClient(srv.URL)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if _, err := c.TreeHead(); err == nil {
		t.Fatal("system-roots client accepted a privately-signed cert — verification was NOT enforced")
	}
}

func TestNewServerVerifyLedgerClient_RequiresCA(t *testing.T) {
	if _, err := NewServerVerifyLedgerClient("https://ledger:8080", "", ""); err == nil {
		t.Fatal("empty CA must error (cannot verify a self-signed cert against nothing)")
	}
}

func TestNewServerVerifyLedgerClient_BadCAFailsClosed(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServerVerifyLedgerClient("https://ledger:8080", bad, ""); err == nil {
		t.Fatal("unparseable CA must error")
	}
}

// NOTE: the Config-driven posture tests (LoadConfig fail-closed on
// ALLOW_SELF_SIGNED without a CA; the LedgerServerVerifyConfigured truth
// table) moved WITH the Config to judicial-network tools/common — the
// court-typed tools config is the tenant's, not the agnostic layer's.
