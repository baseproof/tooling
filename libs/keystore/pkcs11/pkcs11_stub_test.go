//go:build !pkcs11

/*
FILE PATH: libs/keystore/pkcs11/pkcs11_stub_test.go

DESCRIPTION:

	Default-build tests. Pin the no-cgo stub contract: every entry
	point returns ErrNotBuilt, LoadPINFile still validates filesystem
	existence so config validation paths stay testable without the
	cgo build.
*/
package pkcs11

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStub_NewReturnsNotBuilt(t *testing.T) {
	_, err := New(Config{LibraryPath: "x", PIN: "y"})
	if !errors.Is(err, ErrNotBuilt) {
		t.Errorf("New: err = %v, want ErrNotBuilt", err)
	}
}

func TestStub_AllMethodsReturnNotBuilt(t *testing.T) {
	ks := &KeyStore{}
	ks.Close() // no-op

	if _, err := ks.Generate("did", "signing"); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("Generate err = %v", err)
	}
	if _, err := ks.PublicKey("did"); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("PublicKey err = %v", err)
	}
	if _, err := ks.Sign("did", [32]byte{}); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("Sign err = %v", err)
	}
	if _, err := ks.SignEntry("did", [32]byte{}); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("SignEntry err = %v", err)
	}
	if _, err := ks.StageNextKey("did", 1); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("StageNextKey err = %v", err)
	}
	if _, err := ks.CommitRotation("did"); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("CommitRotation err = %v", err)
	}
	if got := ks.List(); got != nil {
		t.Errorf("List = %v, want nil", got)
	}
	if err := ks.Destroy("did"); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("Destroy err = %v", err)
	}
	if _, err := ks.ExportForEscrow("did"); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("ExportForEscrow err = %v", err)
	}
}

func TestStub_LoadPINFile_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pin")
	if err := os.WriteFile(p, []byte("  1234  \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadPINFile(p)
	if err != nil {
		t.Fatalf("LoadPINFile: %v", err)
	}
	if got != "1234" {
		t.Errorf("got %q, want 1234 (whitespace must be trimmed)", got)
	}
}

func TestStub_LoadPINFile_MissingErrors(t *testing.T) {
	if _, err := LoadPINFile("/no/such/file/__"); err == nil {
		t.Error("expected error for missing PIN file")
	}
}
