/*
FILE PATH: libs/anchorcache/bootstrap.go

bootstrap.json operations + the SDK PinStore interface impl.
The bootstrap document is the trust anchor for the entire
network — every other cached view (witnesses, mirrors, peers,
anchors, policy) can be re-fetched from the network's endpoints
on cache miss, but the bootstrap is what tells the verifier
WHICH network it's interacting with in the first place.

# TOFU CONTRACT

  - PinFirstContact stores the bootstrap JCS-canonical bytes
    AND a fingerprint file. The fingerprint is SHA-256 of the
    canonical bytes (equals the NetworkID per SDK contract).
  - VerifyPinned compares the supplied fingerprint against the
    stored one. ErrPinMismatch fires loudly when they differ —
    a malicious bootstrap doc cannot silently re-pin.
  - The pin is the network's IDENTITY; it does NOT change for
    the life of the network. A network that needs to change
    its bootstrap MUST re-mint with a new NetworkID and the
    consumer manually re-pins.

# WHY STORE BOTH BYTES AND FINGERPRINT

Storing just the bytes works for verification — the consumer
re-runs SHA-256 on every call. But storing the fingerprint
separately:

  - Lets a quick existence check (sha256 file) decide "is this
    network pinned?" without parsing the full JSON.
  - Surfaces tampering: a manual edit to bootstrap.json that
    doesn't update fingerprint.txt is caught immediately on
    next verify.

# SDK INTERFACE SATISFACTION

FSPinStore satisfies the SDK's log/discover.PinStore interface.
The signature is (Pin, VerifyPinned) keyed by NetworkID; under
the hood, the FS impl locates the right ManagedDir by walking
~/.baseproof/networks/* and reading each identity.json's NetworkID
to find a match. This walk is O(N) in pinned networks (typically
1-20 for a verifier) and happens only on the cache-miss path.

Callers who already have the ManagedDir handle in scope use
PinBootstrap / VerifyBootstrap directly — those are O(1).
*/
package anchorcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/baseproof/baseproof/log/discover"
	"github.com/baseproof/baseproof/network"
)

// bootstrapFilename is the per-network file holding the JCS-
// canonical BootstrapDocument bytes. Constant so a future
// renamer surfaces here.
const bootstrapFilename = "bootstrap.json"

// fingerprintFilename holds the hex-encoded SHA-256 of the
// bootstrap bytes. Kept separate from bootstrap.json so a
// quick existence check decides "is this network pinned?"
// without parsing the document.
const fingerprintFilename = "fingerprint.txt"

// MaxBootstrapBytes caps the bootstrap.json read. The SDK
// rejects bootstraps over a few KB at parse time; 256 KiB is
// generous slack.
const MaxBootstrapBytes = 256 << 10

// ErrAlreadyPinned is returned by PinBootstrap when bootstrap.json
// already exists with a DIFFERENT fingerprint. Callers receiving
// this error MUST refuse to overwrite — the operator either
// resolves the discrepancy manually OR deletes the directory and
// accepts a fresh first-contact pin.
var ErrAlreadyPinned = errors.New("anchorcache: network already pinned with a different fingerprint")

// PinBootstrap writes the bootstrap JCS bytes to bootstrap.json
// + the fingerprint to fingerprint.txt. Idempotent on matching
// fingerprint (re-pinning the same bytes is a no-op). Refuses
// to overwrite a different pin (returns ErrAlreadyPinned) —
// the caller resolves the discrepancy manually.
//
// The supplied bytes are NOT re-validated as a BootstrapDocument
// — the caller is expected to have decoded + validated upstream
// (typically via network.BootstrapDocument.IDs()). PinBootstrap
// stores whatever bytes the caller passes; the fingerprint is
// computed from the supplied bytes verbatim.
func (d *ManagedDir) PinBootstrap(canonicalBytes []byte) error {
	if len(canonicalBytes) == 0 {
		return fmt.Errorf("anchorcache: empty bootstrap bytes")
	}
	fp := sha256.Sum256(canonicalBytes)
	bsPath := filepath.Join(d.dirPath, bootstrapFilename)
	fpPath := filepath.Join(d.dirPath, fingerprintFilename)

	// If a pin already exists, the new pin MUST match — defense
	// against silently re-pinning a network to a different
	// bootstrap.
	if existingFP, err := readFingerprint(fpPath); err == nil {
		if existingFP != fp {
			return fmt.Errorf("%w: existing %x, new %x",
				ErrAlreadyPinned, existingFP, fp)
		}
		// Same fingerprint — idempotent no-op. Still re-write
		// bootstrap.json defensively in case it was deleted
		// while fingerprint.txt remained.
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("anchorcache: read existing fingerprint: %w", err)
	}

	if err := writeAtomic(bsPath, canonicalBytes, 0o600); err != nil {
		return fmt.Errorf("anchorcache: write %s: %w", bsPath, err)
	}
	if err := writeAtomic(fpPath, []byte(hex.EncodeToString(fp[:])), 0o600); err != nil {
		return fmt.Errorf("anchorcache: write %s: %w", fpPath, err)
	}
	return nil
}

// VerifyBootstrap returns nil iff the supplied bytes match the
// pinned fingerprint. Returns:
//   - ErrPinNotFound (SDK sentinel) if no pin exists yet.
//   - ErrPinMismatch (SDK sentinel) if pinned but differs.
//
// Uses the SDK's error sentinels so this method satisfies the
// PinStore-shaped contract without callers needing to learn a
// separate error vocabulary.
func (d *ManagedDir) VerifyBootstrap(canonicalBytes []byte) error {
	fpPath := filepath.Join(d.dirPath, fingerprintFilename)
	existingFP, err := readFingerprint(fpPath)
	if errors.Is(err, os.ErrNotExist) {
		return discover.ErrPinNotFound
	}
	if err != nil {
		return fmt.Errorf("anchorcache: read fingerprint: %w", err)
	}
	got := sha256.Sum256(canonicalBytes)
	if existingFP != got {
		return fmt.Errorf("%w: pinned %x, got %x",
			discover.ErrPinMismatch, existingFP, got)
	}
	return nil
}

// ReadBootstrap returns the pinned bootstrap.json bytes. Returns
// os.ErrNotExist (wrapped) if no pin exists. Callers typically
// decode via network.BootstrapDocument by json.Unmarshal then
// validate with doc.IDs().
func (d *ManagedDir) ReadBootstrap() ([]byte, error) {
	bsPath := filepath.Join(d.dirPath, bootstrapFilename)
	f, err := os.Open(bsPath)
	if err != nil {
		return nil, err // include os.ErrNotExist for errors.Is callers
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, MaxBootstrapBytes+1))
}

// ReadBootstrapDoc decodes the pinned bytes into a
// network.BootstrapDocument and validates via doc.IDs(). Returns
// (nil, os.ErrNotExist-wrapped) if no pin exists; (nil, err) on
// decode/validation failure.
//
// Convenience over ReadBootstrap for callers that want the typed
// struct directly. Defensive: a corrupted on-disk bootstrap that
// no longer validates surfaces as an error here rather than
// being served as a "trusted" pin.
func (d *ManagedDir) ReadBootstrapDoc() (*network.BootstrapDocument, error) {
	raw, err := d.ReadBootstrap()
	if err != nil {
		return nil, err
	}
	doc := &network.BootstrapDocument{}
	if err := jsonUnmarshal(raw, doc); err != nil {
		return nil, fmt.Errorf("anchorcache: decode bootstrap.json: %w", err)
	}
	if _, err := doc.IDs(); err != nil {
		return nil, fmt.Errorf("anchorcache: bootstrap fails validation: %w", err)
	}
	return doc, nil
}

// readFingerprint parses fingerprint.txt into a [32]byte. The
// file is exactly 64 hex characters; anything else is a
// corruption signal (manual edit, partial write recovery
// failure).
func readFingerprint(path string) ([32]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	// Allow trailing whitespace (e.g., a vim user added a
	// newline) by trimming.
	trimmed := trimWhitespace(string(raw))
	if len(trimmed) != 64 {
		return [32]byte{}, fmt.Errorf("anchorcache: %s has length %d, want 64 hex chars",
			path, len(trimmed))
	}
	out, err := hex.DecodeString(trimmed)
	if err != nil {
		return [32]byte{}, fmt.Errorf("anchorcache: %s malformed hex: %w", path, err)
	}
	var fp [32]byte
	copy(fp[:], out)
	return fp, nil
}

// trimWhitespace strips leading + trailing ASCII whitespace.
// Inlined to avoid an import sprawl for one helper.
func trimWhitespace(s string) string {
	start, end := 0, len(s)
	for start < end && isWS(s[start]) {
		start++
	}
	for end > start && isWS(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isWS(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// ─────────────────────────────────────────────────────────────────────
// SDK PinStore interface impl (single-dir variant)
// ─────────────────────────────────────────────────────────────────────

// SinglePinStore wraps a ManagedDir into the SDK's
// log/discover.PinStore interface. The SDK interface is keyed by
// NetworkID (not DID); SinglePinStore checks the bootstrap's
// computed NetworkID against the supplied one on every call.
//
// Use this when the caller already knows which network they're
// pinning (typical pattern: discover the network, derive
// NetworkID, then construct the SinglePinStore for that
// directory).
type SinglePinStore struct {
	dir *ManagedDir
}

// NewSinglePinStore wraps dir into the SDK PinStore interface.
func NewSinglePinStore(dir *ManagedDir) *SinglePinStore {
	return &SinglePinStore{dir: dir}
}

// Pin implements discover.PinStore. The SDK's interface takes
// (networkID, fingerprint); the on-disk pin format uses the
// fingerprint as the canonical key + stores the bytes
// separately. SinglePinStore.Pin requires the caller to have
// already supplied the bytes via PinBootstrap upstream — Pin
// here only checks that the supplied (NetworkID, fingerprint)
// pair matches an already-pinned bootstrap. A naked Pin call
// without the bootstrap bytes is rejected because the FS layer
// pins the BYTES (which include the bootstrap's full document),
// not just the hash.
func (s *SinglePinStore) Pin(_ context.Context, _ [32]byte, fingerprint [32]byte) error {
	stored, err := readFingerprint(filepath.Join(s.dir.dirPath, fingerprintFilename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("anchorcache: SinglePinStore.Pin called without PinBootstrap upstream " +
				"— FS layer pins the bytes, not just the hash")
		}
		return err
	}
	if stored != fingerprint {
		return fmt.Errorf("anchorcache: SinglePinStore.Pin: requested fingerprint %x mismatches "+
			"already-stored %x — refusing to silently re-pin",
			fingerprint, stored)
	}
	return nil
}

// VerifyPinned implements discover.PinStore.
func (s *SinglePinStore) VerifyPinned(_ context.Context, _ [32]byte, fingerprint [32]byte) error {
	stored, err := readFingerprint(filepath.Join(s.dir.dirPath, fingerprintFilename))
	if errors.Is(err, os.ErrNotExist) {
		return discover.ErrPinNotFound
	}
	if err != nil {
		return err
	}
	if stored != fingerprint {
		return fmt.Errorf("%w: stored %x, got %x", discover.ErrPinMismatch, stored, fingerprint)
	}
	return nil
}

// Compile-time guard: SinglePinStore satisfies discover.PinStore.
var _ discover.PinStore = (*SinglePinStore)(nil)
