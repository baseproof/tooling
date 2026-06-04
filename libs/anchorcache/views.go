/*
FILE PATH: libs/anchorcache/views.go

Per-view persistence — mirrors.json, peers.json, anchors.json,
policy/<view>.json, witnesses/<set_hash>.json. The bootstrap.json
+ fingerprint.txt pair lives in bootstrap.go because it has the
TOFU pin semantics; the other views are simple cache writes (no
pin, no fingerprint, always re-fetchable from the network on
miss).

# WIRE SHAPE STABILITY

The cache files mirror the ledger's wire shape verbatim — no
re-projection. A consumer reading mirrors.json gets the same
JSON the ledger's /v1/network/mirrors served (snake_case keys,
hex-encoded byte fields). This means:

  - A future SDK shape extension surfaces at the network's
    endpoint AND in the cached bytes (drift-proof by
    construction).
  - The renderer + parser are the SAME on disk and on the wire
    (the SDK's WireMirrorManifest decoder reads either source).

# UNKNOWN-FIELD POLICY

The cache files MAY contain fields the current binary doesn't
recognize (an older binary reading a newer cache, written by a
newer binary). DisallowUnknownFields would be too strict; we
accept unknown fields on read and preserve them on rewrite.

# CACHE MISS SEMANTICS

A read for a non-existent view returns (nil, os.ErrNotExist).
The caller falls through to a network fetch + writes the result
back via WriteXxx. No automatic refresh — the consumer decides
when to invalidate (typically: re-fetch on every binary boot, or
honor the endpoint's Cache-Control header).
*/
package anchorcache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MaxViewBytes caps each per-view file read. Generous — the
// largest realistic view (witnesses/<hash>.json carrying 16
// keys × ~150 bytes each) is well under 8 KiB; 256 KiB is
// hostile.
const MaxViewBytes = 256 << 10

// jsonUnmarshal is a small wrapper around json.Unmarshal so a
// future cache-side migration (e.g., a custom decoder that
// preserves unknown fields verbatim) can be introduced in one
// place. Today it's the stdlib's permissive decoder.
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// readViewFile reads a per-view file under d.dirPath/relPath.
// Returns (bytes, nil) on success or (nil, err) where err
// wraps os.ErrNotExist on miss.
func (d *ManagedDir) readViewFile(relPath string) ([]byte, error) {
	full := filepath.Join(d.dirPath, relPath)
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	body, err := io.ReadAll(io.LimitReader(f, MaxViewBytes+1))
	if err != nil {
		return nil, fmt.Errorf("anchorcache: read %s: %w", full, err)
	}
	if len(body) > MaxViewBytes {
		return nil, fmt.Errorf("anchorcache: %s exceeds %d bytes (cap)", full, MaxViewBytes)
	}
	return body, nil
}

// writeViewFile is the atomic-write helper for per-view JSON.
// Validates the payload is well-formed JSON before writing —
// a corrupted byte stream cached on disk would surface later
// as a confusing decode error far from the source.
func (d *ManagedDir) writeViewFile(relPath string, data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("anchorcache: refused to write %s: payload is not valid JSON", relPath)
	}
	full := filepath.Join(d.dirPath, relPath)
	return writeAtomic(full, data, 0o600)
}

// ─────────────────────────────────────────────────────────────────────
// identity.json — the network's four IDs derived from bootstrap
// ─────────────────────────────────────────────────────────────────────

// Identity is the wire shape mirroring api.NetworkIdentity from
// the ledger. Stored under identity.json.
type Identity struct {
	NetworkID     string `json:"network_id"`
	NetworkUUID   string `json:"network_uuid"`
	NetworkDID    string `json:"network_did"`
	BootstrapHash string `json:"bootstrap_hash"`
}

// WriteIdentity persists identity.json. Idempotent.
func (d *ManagedDir) WriteIdentity(id Identity) error {
	body, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("anchorcache: marshal identity: %w", err)
	}
	return d.writeViewFile("identity.json", body)
}

// ReadIdentity reads identity.json. Returns os.ErrNotExist
// wrapped on miss.
func (d *ManagedDir) ReadIdentity() (Identity, error) {
	body, err := d.readViewFile("identity.json")
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	if err := jsonUnmarshal(body, &id); err != nil {
		return Identity{}, fmt.Errorf("anchorcache: decode identity.json: %w", err)
	}
	return id, nil
}

// ─────────────────────────────────────────────────────────────────────
// mirrors.json — MirrorManifest cache
// ─────────────────────────────────────────────────────────────────────

// WriteMirrorsBytes persists raw mirrors.json bytes (the exact
// bytes the ledger's /v1/network/mirrors endpoint served).
// Validating the wire shape is the caller's responsibility —
// this method only enforces JSON well-formedness.
func (d *ManagedDir) WriteMirrorsBytes(raw []byte) error {
	return d.writeViewFile("mirrors.json", raw)
}

// ReadMirrorsBytes reads the raw bytes back. Caller decodes via
// the SDK's discover.MirrorManifest shape (or the ledger's
// api.WireMirrorManifest — both are wire-byte-identical).
func (d *ManagedDir) ReadMirrorsBytes() ([]byte, error) {
	return d.readViewFile("mirrors.json")
}

// ─────────────────────────────────────────────────────────────────────
// peers.json — FederationGraph cache
// ─────────────────────────────────────────────────────────────────────

// WritePeersBytes persists raw peers.json bytes (mirroring the
// ledger's /v1/network/peers shape). The decoded form is
// discover.FederationGraph in the SDK; this layer doesn't
// re-project.
func (d *ManagedDir) WritePeersBytes(raw []byte) error {
	return d.writeViewFile("peers.json", raw)
}

// ReadPeersBytes reads peers.json. Same caveats as mirrors.
func (d *ManagedDir) ReadPeersBytes() ([]byte, error) {
	return d.readViewFile("peers.json")
}

// ─────────────────────────────────────────────────────────────────────
// anchors.json — AnchorChain cache
// ─────────────────────────────────────────────────────────────────────

// WriteAnchorsBytes persists raw anchors.json bytes.
func (d *ManagedDir) WriteAnchorsBytes(raw []byte) error {
	return d.writeViewFile("anchors.json", raw)
}

// ReadAnchorsBytes reads anchors.json.
func (d *ManagedDir) ReadAnchorsBytes() ([]byte, error) {
	return d.readViewFile("anchors.json")
}

// ─────────────────────────────────────────────────────────────────────
// witnesses/<set_hash>.json — content-addressable historical sets
// ─────────────────────────────────────────────────────────────────────

// WriteWitnessSetBytes persists the JSON-shape witness set under
// witnesses/<setHashHex>.json. The cache is content-addressable
// + immutable — a re-write of the same hash with the same bytes
// is idempotent; a re-write with different bytes (would be a
// SHA-256 collision) overwrites without complaint, since the
// caller has bypassed content-addressing if it gets there.
//
// setHashHex MUST be 64 lowercase hex characters (the standard
// SetHash render). Validation is enforced — a malformed hash
// would produce a malformed filename + break any subsequent
// content-addressable lookup.
func (d *ManagedDir) WriteWitnessSetBytes(setHashHex string, raw []byte) error {
	if !validSetHashHex(setHashHex) {
		return fmt.Errorf("anchorcache: invalid set_hash hex %q (want 64 lowercase hex chars)", setHashHex)
	}
	return d.writeViewFile(filepath.Join("witnesses", setHashHex+".json"), raw)
}

// ReadWitnessSetBytes reads a content-addressable witness set
// view. Returns os.ErrNotExist wrapped on miss; the caller falls
// through to a fetch via the network's
// /v1/network/witnesses/{set_hash} endpoint.
func (d *ManagedDir) ReadWitnessSetBytes(setHashHex string) ([]byte, error) {
	if !validSetHashHex(setHashHex) {
		return nil, fmt.Errorf("anchorcache: invalid set_hash hex %q", setHashHex)
	}
	return d.readViewFile(filepath.Join("witnesses", setHashHex+".json"))
}

// HasWitnessSet returns true iff witnesses/<setHashHex>.json
// exists. Cheaper than ReadWitnessSetBytes when the caller only
// needs the "is this set cached?" predicate.
func (d *ManagedDir) HasWitnessSet(setHashHex string) bool {
	if !validSetHashHex(setHashHex) {
		return false
	}
	_, err := os.Stat(filepath.Join(d.dirPath, "witnesses", setHashHex+".json"))
	return err == nil
}

// validSetHashHex enforces the 64-lowercase-hex contract.
// SetHash render uses lowercase per the SDK's
// hex.EncodeToString default; rejecting uppercase prevents
// case-sensitivity bugs across platforms (some macOS filesystems
// fold case).
func validSetHashHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────
// policy/<view>.json — cached policy views
// ─────────────────────────────────────────────────────────────────────

// Policy view names — kept as named constants so a future view
// rename surfaces at every call site.
const (
	PolicyViewSignature = "signature.json"
	PolicyViewAlgorithm = "algorithm.json"
	PolicyViewVersion   = "version.json"

	// v1.32.0 materialized walker projections. These three views
	// cache the OUTPUT of crosslog.MaterializeFromEntries (the
	// per-PubKeyID endpoint declarations, identity labels, and
	// auditor registrations) so a consumer (auditor, witness, CLI)
	// can skip the full log scan on every restart. Wire shape is
	// JCS-canonical JSON of the *ByPosition slices; readers
	// reconstruct the SDK's record types via DecodeNetworkEntry
	// (libs/crosslog/decode_network.go) or by direct unmarshal
	// against the SDK's per-payload structs.
	//
	// The paths include the "materialized/" subdirectory so the
	// projections sit alongside the existing policy/* views without
	// colliding with the WitnessSet content-addressable cache or
	// the bootstrap pins.
	PolicyViewMaterializedLabels    = "materialized/labels.json"
	PolicyViewMaterializedEndpoints = "materialized/endpoints.json"
	PolicyViewMaterializedAuditors  = "materialized/auditors.json"
)

// WritePolicyBytes persists a per-view policy cache file under
// policy/<view>.json. view MUST be one of the named constants.
// Caller-supplied views are NOT a stable extension point — the
// SDK is the canonical source for which views exist; new views
// ship by adding a new constant here.
func (d *ManagedDir) WritePolicyBytes(view string, raw []byte) error {
	if !validPolicyView(view) {
		return fmt.Errorf("anchorcache: unknown policy view %q", view)
	}
	return d.writeViewFile(filepath.Join("policy", view), raw)
}

// ReadPolicyBytes reads a per-view policy cache file.
func (d *ManagedDir) ReadPolicyBytes(view string) ([]byte, error) {
	if !validPolicyView(view) {
		return nil, fmt.Errorf("anchorcache: unknown policy view %q", view)
	}
	return d.readViewFile(filepath.Join("policy", view))
}

func validPolicyView(view string) bool {
	switch view {
	case PolicyViewSignature, PolicyViewAlgorithm, PolicyViewVersion,
		PolicyViewMaterializedLabels, PolicyViewMaterializedEndpoints, PolicyViewMaterializedAuditors:
		return true
	default:
		return false
	}
}

// ─────────────────────────────────────────────────────────────────────
// cursor — follow/watch resume position
// ─────────────────────────────────────────────────────────────────────

// WriteCursor stores a process resume position (e.g., the last
// log sequence the auditor processed). Plain text; not JSON —
// the cursor is a single uint64 that downstream tooling treats
// as opaque.
func (d *ManagedDir) WriteCursor(cursor string) error {
	full := filepath.Join(d.dirPath, "cursor")
	return writeAtomic(full, []byte(cursor), 0o600)
}

// ReadCursor returns the stored cursor or os.ErrNotExist wrapped
// when no cursor has been written yet.
func (d *ManagedDir) ReadCursor() (string, error) {
	full := filepath.Join(d.dirPath, "cursor")
	body, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	return trimWhitespace(string(body)), nil
}

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// IsNotExist returns true iff err is an os.ErrNotExist-wrapped
// error from a cache read. Convenience for callers branching on
// cache miss without needing to import os directly.
func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
