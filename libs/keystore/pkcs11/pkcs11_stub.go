//go:build !pkcs11

/*
FILE PATH: libs/keystore/pkcs11/pkcs11_stub.go

DESCRIPTION:

	No-cgo build target. Compiles when the `pkcs11` build tag is
	absent. Returns a clear "not built" error from New so the
	composer can surface a useful message to ledgers who configure
	`keystore.backend = softhsm` without rebuilding with `-tags pkcs11`.

	The exported surface (Config, LoadPINFile, KeyStore type, New,
	Close) mirrors the real implementation exactly so callers compile
	against either build target without changes.
*/
package pkcs11

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/baseproof/tooling/libs/keystore"
)

// ErrNotBuilt is returned by every entry point when the binary was
// compiled without `-tags pkcs11`.
var ErrNotBuilt = errors.New("pkcs11: backend not compiled in (rebuild with `-tags pkcs11` and CGO_ENABLED=1)")

// Re-exported so the composer keeps a single error sentinel surface.
var ErrEd25519Unsupported = ErrNotBuilt

// Config mirrors the real Config so callers can compose it without
// caring whether the cgo backend is available at build time.
type Config struct {
	LibraryPath string
	SlotID      uint
	PIN         string
	TokenLabel  string
}

// LoadPINFile reads the token PIN from disk so the composer can
// always sanity-check the PIN file even when the cgo backend isn't
// built. The PIN itself is unused by the stub but having the helper
// available means config-validation tests don't need build-tag forks.
func LoadPINFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("pkcs11: read PIN file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// KeyStore is the no-cgo stub. Every method returns ErrNotBuilt.
type KeyStore struct{}

// New always fails in the no-cgo build.
func New(_ Config) (*KeyStore, error) { return nil, ErrNotBuilt }

func (k *KeyStore) Close() {}

func (k *KeyStore) Generate(_ string, _ string) (*keystore.KeyInfo, error) { return nil, ErrNotBuilt }
func (k *KeyStore) PublicKey(_ string) ([]byte, error)                     { return nil, ErrNotBuilt }
func (k *KeyStore) Sign(_ string, _ [32]byte) ([]byte, error)              { return nil, ErrNotBuilt }
func (k *KeyStore) SignEntry(_ string, _ [32]byte) ([]byte, error)         { return nil, ErrNotBuilt }
func (k *KeyStore) StageNextKey(_ string, _ int) (*keystore.KeyInfo, error) {
	return nil, ErrNotBuilt
}
func (k *KeyStore) CommitRotation(_ string) (*keystore.KeyInfo, error) { return nil, ErrNotBuilt }
func (k *KeyStore) List() []*keystore.KeyInfo                          { return nil }
func (k *KeyStore) Destroy(_ string) error                             { return ErrNotBuilt }
func (k *KeyStore) ExportForEscrow(_ string) ([]byte, error)           { return nil, ErrNotBuilt }
