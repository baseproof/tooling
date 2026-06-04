//go:build pkcs11

/*
FILE PATH: libs/keystore/pkcs11/pkcs11_keystore.go

DESCRIPTION:

	PKCS#11 backend for keystore.KeyStore. This file owns the Config +
	KeyStore types, constructor / Close, and the management surface
	(List / Destroy / ExportForEscrow). secp256k1 sign/gen + the
	staged-rotation surface live in pkcs11_secp256k1.go; PKCS#11
	object-find + EC_POINT plumbing in pkcs11_objects.go.

	Default deployment target is SoftHSMv2; the same code path drives
	any PKCS#11 v2.40 token that supports CKM_EC_KEY_PAIR_GEN +
	CKM_ECDSA with the secp256k1 OID curve parameter (1.3.132.0.10).

	# STAGED ROTATION

	PKCS#11 has no native concept of key "versions" — every key is a
	separate token object identified by CKA_LABEL. We layer staged
	rotation on top by encoding the rotation TIER in the label:

	  baseproof:<did>#tier-1   (initial Generate)
	  baseproof:<did>#tier-2   (after first rotation)
	  baseproof:<did>#tier-3   (after second rotation)
	  ...

	currentTier[did] records the active tier; signs / pubkey lookups
	derive the label from (did, currentTier[did]). StageNextKey
	generates a NEW key pair at the staged tier WITHOUT touching
	currentTier — so Sign / SignEntry continue to find the OLD key
	(chain-of-custody invariant the SDK's RotationHistorySource
	requires). CommitRotation DestroyObject's the old key handles,
	advances currentTier, and clears pendingSec.

	Build tag: this file compiles ONLY with `-tags pkcs11`. The
	miekg/pkcs11 binding requires cgo + libpkcs11.so; default builds
	must remain cgo-free, so the unbuilt path is taken by
	pkcs11_stub.go.
*/
package pkcs11

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	mpkcs11 "github.com/miekg/pkcs11"

	"github.com/baseproof/tooling/libs/keystore"
)

// ErrEd25519Unsupported is returned by every Ed25519 entry point. The
// PKCS#11 mechanism for Ed25519 (CKM_EDDSA) is optional in v2.40 and
// missing from common SoftHSMv2 builds; deployments that need
// Ed25519 either keep that DID in MemoryKeyStore or in Vault.
var ErrEd25519Unsupported = errors.New("pkcs11: Ed25519 not supported (use Vault or MemoryKeyStore)")

var errNoKey = errors.New("pkcs11: no key for DID")

// Config configures a PKCS#11 keystore. PIN is the token user PIN —
// supply it at compose time from a sealed file.
type Config struct {
	LibraryPath string
	SlotID      uint
	PIN         string
	TokenLabel  string
}

// LoadPINFile reads the token PIN from disk; trims trailing
// whitespace. Production deploys always source the PIN from a sealed
// file rather than inline JSON.
func LoadPINFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("pkcs11: read PIN file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// KeyStore is a keystore.KeyStore backed by a PKCS#11 token.
type KeyStore struct {
	cfg     Config
	ctx     *mpkcs11.Ctx
	session mpkcs11.SessionHandle

	mu      sync.RWMutex
	keysSec map[string]*keystore.KeyInfo

	// Staged rotation. PKCS#11 has no native versioning, so we
	// encode rotation tier in the CKA_LABEL and track the active
	// tier here.
	currentTier map[string]int // did → active tier (>= 1)
	pendingSec  map[string]*pendingRotation
}

// pendingRotation captures the next-tier state staged via
// StageNextKey. Held until CommitRotation promotes it; the
// rotation is in-process per the MemoryKeyStore contract.
type pendingRotation struct {
	info *keystore.KeyInfo
	tier int // the rotation tier of the staged key
}

// New initializes the PKCS#11 module, opens a session, and logs in
// with the supplied PIN. Caller MUST invoke Close at shutdown to
// release the session.
func New(cfg Config) (*KeyStore, error) {
	if cfg.LibraryPath == "" {
		return nil, fmt.Errorf("pkcs11: library_path required")
	}
	if cfg.PIN == "" {
		return nil, fmt.Errorf("pkcs11: PIN required")
	}
	ctx := mpkcs11.New(cfg.LibraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: failed to load %q", cfg.LibraryPath)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: Initialize: %w", err)
	}
	session, err := ctx.OpenSession(cfg.SlotID,
		mpkcs11.CKF_SERIAL_SESSION|mpkcs11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: OpenSession slot %d: %w", cfg.SlotID, err)
	}
	if err := ctx.Login(session, mpkcs11.CKU_USER, cfg.PIN); err != nil {
		_ = ctx.CloseSession(session)
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: Login: %w", err)
	}
	return &KeyStore{
		cfg:         cfg,
		ctx:         ctx,
		session:     session,
		keysSec:     map[string]*keystore.KeyInfo{},
		currentTier: map[string]int{},
		pendingSec:  map[string]*pendingRotation{},
	}, nil
}

// Close releases the PKCS#11 session and finalizes the module. Idempotent.
func (k *KeyStore) Close() {
	if k.ctx == nil {
		return
	}
	_ = k.ctx.Logout(k.session)
	_ = k.ctx.CloseSession(k.session)
	_ = k.ctx.Finalize()
	k.ctx.Destroy()
	k.ctx = nil
}

// labelForTier returns the CKA_LABEL bytes for a (did, tier) pair.
// Both halves of the key pair carry the same label, so a single
// FindObjects pass on (CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL) recovers
// either handle.
//
// Format: "baseproof:<did>#tier-<N>" where N is the rotation tier
// (1 for the initial Generate, 2 for the first rotation, ...).
func labelForTier(did string, tier int) []byte {
	return []byte(fmt.Sprintf("baseproof:%s#tier-%d", did, tier))
}

// labelFor returns the active CKA_LABEL for a DID — the tier
// recorded in currentTier[did]. Falls back to tier 1 if no entry
// exists, which happens only before the first Generate (and every
// caller would have errored out on findOne by then anyway).
func (k *KeyStore) labelFor(did string) []byte {
	k.mu.RLock()
	t := k.currentTier[did]
	k.mu.RUnlock()
	if t < 1 {
		t = 1
	}
	return labelForTier(did, t)
}

// ─────────────────────────────────────────────────────────────────────
// keystore.KeyStore — management
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
	// Snapshot rotation state so we know all the labels with
	// outstanding objects on the token (current + any staged).
	k.mu.RLock()
	curTier := k.currentTier[did]
	pending, hasPending := k.pendingSec[did]
	k.mu.RUnlock()

	var foundAny bool
	if curTier > 0 {
		if k.destroyByLabel(labelForTier(did, curTier)) {
			foundAny = true
		}
	} else {
		// Legacy / cache-miss path: try the labelFor fallback
		// (tier 1) so a fresh KeyStore over a token with prior
		// keys can still expunge them.
		if k.destroyByLabel(labelForTier(did, 1)) {
			foundAny = true
		}
	}
	if hasPending {
		if k.destroyByLabel(labelForTier(did, pending.tier)) {
			foundAny = true
		}
	}
	if !foundAny {
		return errNoKey
	}

	k.mu.Lock()
	delete(k.keysSec, did)
	delete(k.pendingSec, did)
	delete(k.currentTier, did)
	k.mu.Unlock()
	return nil
}

// destroyByLabel deletes the (public-key, private-key) pair whose
// CKA_LABEL matches lbl. Returns true iff at least one handle was
// destroyed.
func (k *KeyStore) destroyByLabel(lbl []byte) bool {
	var hit bool
	if pubH, err := k.findOneByLabel(lbl, mpkcs11.CKO_PUBLIC_KEY); err == nil {
		_ = k.ctx.DestroyObject(k.session, pubH)
		hit = true
	}
	if privH, err := k.findOneByLabel(lbl, mpkcs11.CKO_PRIVATE_KEY); err == nil {
		_ = k.ctx.DestroyObject(k.session, privH)
		hit = true
	}
	return hit
}

// ExportForEscrow is unsupported: PKCS#11 keys with CKA_EXTRACTABLE=false
// (which is what we always generate) cannot be exported. Same rationale
// as Vault: route escrow through bootstrap.
func (k *KeyStore) ExportForEscrow(_ string) ([]byte, error) {
	return nil, fmt.Errorf("pkcs11: ExportForEscrow not supported (token keys are non-extractable)")
}
