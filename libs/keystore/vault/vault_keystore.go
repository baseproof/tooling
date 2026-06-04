/*
FILE PATH: libs/keystore/vault/vault_keystore.go

DESCRIPTION:

	HashiCorp Vault Transit native backend for keystore.KeyStore
	(secp256k1-only). Owns the Config + KeyStore types, constructor, and
	the management surface; curve glue lives in vault_secp256k1.go, HTTP
	plumbing in vault_http.go.

	Vault Transit OSS supports `ecdsa-p256k1` since v1.18 (Sept 2024);
	production deploys run latest Vault. Private keys never leave Vault;
	ExportForEscrow returns an explicit "not exportable" error (Vault
	keys are non-extractable by design — escrow ceremonies run against
	the in-memory keystore at bootstrap).

	# STAGED ROTATION

	StageNextKey / CommitRotation layer the SDK's old-key-signs chain
	of custody on top of Vault Transit's native key versioning:

	  - StageNextKey: POST /v1/<mount>/keys/<name>/rotate creates a
	    new Vault version (e.g., v1 → v2). The new version becomes
	    Vault's "latest" pointer, but we record the OLD version in
	    activeVersion[did] so Sign continues to thread ?key_version=
	    pointed at the OLD key. The pending rotation is stashed in
	    pendingSec until commit.
	  - CommitRotation: POST /v1/<mount>/keys/<name>/config raises
	    min_encryption_version to the new version (retiring the
	    OLD), then promotes pendingSec → keysSec and updates
	    activeVersion. New signs now use the NEW key; previously-
	    issued signatures remain verifiable via the cached pubkey
	    bytes (no Vault round-trip required at verify time).
*/
package vault

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/baseproof/tooling/libs/keystore"
)

// Config configures a Vault Transit keystore. Mirrors
// api/config.VaultConfig. HTTPClient is REQUIRED: every binary that
// uses Vault must thread its hoisted outbound *http.Client through
// here so the Vault traffic shares the operator-chosen mTLS posture
// (Vault sits behind the network's HSM perimeter; a silent plaintext
// fallback is exactly the v1.27.x anti-pattern we removed).
type Config struct {
	Address    string
	Token      string
	Mount      string // default "transit"
	HTTPClient *http.Client
}

// KeyStore is a keystore.KeyStore backed by Vault Transit secp256k1 keys.
// Per-DID Vault key names are derived as "<sanitized-did>__secp256k1".
type KeyStore struct {
	cfg Config
	hc  *http.Client

	mu      sync.RWMutex
	keysSec map[string]*keystore.KeyInfo // did → secp256k1 KeyInfo (cached)

	// Staged rotation.
	//
	// Vault's Transit API supports key versioning natively:
	// POST /v1/<mount>/keys/<name>/rotate creates a new version
	// (v2 if v1 exists). Vault's sign endpoint defaults to the
	// LATEST version, so a naked rotate would immediately swap
	// signing keys — losing the old-key-signs chain of custody
	// the SDK's RotationHistorySource requires.
	//
	// We layer staged semantics on top, NOT touching Vault's
	// min_encryption_version until commit:
	//   - StageNextKey rotates the Vault key, stashes the new
	//     version + its pubkey in pendingSec. activeVersion[did]
	//     remains pointed at the OLD version.
	//   - Sign / SignEntry pass activeVersion[did] through
	//     signDERAt → the Vault sign request body's "key_version"
	//     field, so the rotation entry — which NAMES the new key
	//     — is signed by the OLD key. The OLD pubkey cached in
	//     keysSec[did] is what packCompact's recovery-byte
	//     search matches against, keeping the wire shape
	//     internally consistent.
	//   - CommitRotation calls updateKeyConfig to raise
	//     min_encryption_version to NEW (retiring OLD), then
	//     moves pendingSec → keysSec and updates activeVersion.
	pendingSec map[string]*pendingRotation

	// activeVersion[did] records which Vault key version is the
	// keystore's "active" signer. The Vault server's latest
	// version may differ during a staged rotation; we always
	// sign with the recorded active version explicitly via the
	// sign endpoint body's "key_version" field.
	activeVersion map[string]int
}

// pendingRotation captures the next-version state staged via
// StageNextKey. Held until CommitRotation promotes it (or
// implicitly discarded on process restart — staged rotation is
// in-process per the MemoryKeyStore contract).
type pendingRotation struct {
	info    *keystore.KeyInfo
	version int // Vault Transit key version (>= 2 for v1.x networks)
}

// New constructs a Vault keystore. Address + Token + HTTPClient are
// required; Mount defaults to "transit". A nil HTTPClient is a
// startup-fatal error — the legacy plaintext-fallback path is gone
// (v1.27.x: thread the binary's hoisted outbound client; see
// libs/clienttls.BuildFromEnv or libs/outbound.HoistFromEnv). No
// network round-trip until the first Generate/Sign.
func New(cfg Config) (*KeyStore, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: address required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault: token required")
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("vault: HTTPClient required (thread the binary's hoisted outbound client; see libs/clienttls.BuildFromEnv or libs/outbound.HoistFromEnv)")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	return &KeyStore{
		cfg:           cfg,
		hc:            cfg.HTTPClient,
		keysSec:       map[string]*keystore.KeyInfo{},
		pendingSec:    map[string]*pendingRotation{},
		activeVersion: map[string]int{},
	}, nil
}

// LoadTokenFile reads a Vault token from disk.
func LoadTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vault: read token file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// keyName scrubs the DID for use as a Vault key name (": / #" → "_").
func keyName(did, curve string) string {
	scrub := strings.NewReplacer(":", "_", "/", "_", "#", "_").Replace(did)
	return fmt.Sprintf("%s__%s", scrub, curve)
}

// ─────────────────────────────────────────────────────────────────────
// keystore.KeyStore — management surface
// ─────────────────────────────────────────────────────────────────────

func (k *KeyStore) List() []*keystore.KeyInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]*keystore.KeyInfo, 0, len(k.keysSec))
	for _, info := range k.keysSec {
		out = append(out, info)
	}
	return out
}

func (k *KeyStore) Destroy(did string) error {
	name := keyName(did, keystore.CurveSecp256k1)
	err := k.do(http.MethodDelete,
		fmt.Sprintf("/v1/%s/keys/%s", k.cfg.Mount, url.PathEscape(name)),
		nil, nil)
	k.mu.Lock()
	delete(k.keysSec, did)
	delete(k.pendingSec, did)
	delete(k.activeVersion, did)
	k.mu.Unlock()
	if err != nil {
		return fmt.Errorf("vault: destroy: %w", err)
	}
	return nil
}

// ExportForEscrow is unsupported: Vault Transit keys are non-exportable
// by design. Escrow ceremonies run against the in-memory keystore at
// bootstrap.
func (k *KeyStore) ExportForEscrow(_ string) ([]byte, error) {
	return nil, fmt.Errorf("vault: ExportForEscrow not supported (Vault Transit keys are non-exportable; run escrow at bootstrap)")
}
