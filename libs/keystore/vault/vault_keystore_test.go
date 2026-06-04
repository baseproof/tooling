/*
FILE PATH: libs/keystore/vault/vault_keystore_test.go

DESCRIPTION:

	Constructor + lifecycle + helper tests for the Vault Transit
	keystore. Curve-specific round-trips live in
	vault_secp256k1_test.go and vault_ed25519_test.go; the
	cross-backend conformance run lives in vault_conformance_test.go;
	the in-process Vault mock lives in vault_fakeserver_test.go.
*/
package vault

import (
	"net/http"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// New — config validation
// ─────────────────────────────────────────────────────────────────────

func TestNew_RequiresAddress(t *testing.T) {
	if _, err := New(Config{Token: "x", HTTPClient: &http.Client{}}); err == nil {
		t.Error("expected error for missing address")
	}
}

func TestNew_RequiresToken(t *testing.T) {
	if _, err := New(Config{Address: "https://vault", HTTPClient: &http.Client{}}); err == nil {
		t.Error("expected error for missing token")
	}
}

// TestNew_RequiresHTTPClient pins the v1.27.x contract: a nil HTTPClient
// is a startup-fatal error. The legacy 10s-timeout plaintext-fallback
// path was deleted with the rest of the silent-fallback shapes.
func TestNew_RequiresHTTPClient(t *testing.T) {
	_, err := New(Config{Address: "https://vault", Token: "t"})
	if err == nil {
		t.Fatal("expected error for missing HTTPClient")
	}
}

func TestNew_DefaultsMount(t *testing.T) {
	ks, err := New(Config{Address: "https://vault", Token: "t", HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if ks.cfg.Mount != "transit" {
		t.Errorf("Mount = %q, want transit", ks.cfg.Mount)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Lifecycle (Destroy / ExportForEscrow / List)
//
// Staged rotation tests live in vault_rotation_test.go.
// ─────────────────────────────────────────────────────────────────────

func TestVault_DestroyRemoves(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.Generate("did:web:test:judge", "signing"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ks.Destroy("did:web:test:judge"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if list := ks.List(); len(list) != 0 {
		t.Errorf("list len after destroy = %d, want 0", len(list))
	}
}

func TestVault_ExportForEscrow_Refuses(t *testing.T) {
	ks, srv := newKS(t)
	defer srv.Close()
	if _, err := ks.ExportForEscrow("did:web:test:judge"); err == nil {
		t.Error("expected ExportForEscrow to refuse")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Errors + helpers
// ─────────────────────────────────────────────────────────────────────

func TestVault_BadToken_Surfaces(t *testing.T) {
	srv := newFakeVault(t)
	defer srv.Close()
	ks, err := New(Config{Address: srv.URL, Token: "wrong-token", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := ks.Generate("did:web:x", "signing"); err == nil {
		t.Error("expected forbidden error")
	}
}

func TestVault_StripPrefix(t *testing.T) {
	if got := stripVaultPrefix("vault:v1:abc"); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := stripVaultPrefix("plain"); got != "plain" {
		t.Errorf("no-colon path: got %q", got)
	}
}

func TestVault_LeftPad32(t *testing.T) {
	if got := leftPad32([]byte{1, 2, 3}); len(got) != 32 || got[29] != 1 {
		t.Errorf("leftPad32 wrong: %x", got)
	}
}

func TestVault_LoadTokenFile_Missing(t *testing.T) {
	if _, err := LoadTokenFile("/no/such/file/__"); err == nil {
		t.Error("expected error for missing token file")
	}
}
