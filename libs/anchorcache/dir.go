/*
FILE PATH: libs/anchorcache/dir.go

ManagedDir + Open primitive. ManagedDir is the typed handle to a
~/.baseproof/networks/<did>/ directory; Open ensures the directory
exists and returns a handle ready for per-file operations.

# WHY A HANDLE AND NOT FREE FUNCTIONS

A ManagedDir captures the (root, networkDID) pair once. Every
subsequent per-file call reuses that path computation, AND every
write enforces the same atomic-rename discipline. Free functions
would force every caller to re-thread the root + DID and
re-implement the atomic-write boilerplate; a handle is cheaper +
less error-prone.

# ROOT RESOLUTION

The default root is $HOME/.baseproof. Callers may override via
OpenAt for tests / multi-user systems where $HOME is not the
right anchor. The default supports the "20-year contract" — a
user's verification artifacts survive across binary upgrades
because $HOME/.baseproof is OUTSIDE the binary's package directory.

# DID → DIRECTORY NAME

The network's full DID (e.g.,
"did:baseproof:network:megvbng4xc6t7r8s9t0u1v2w3y4z5a6b") is the
directory name. The DID is content-addressed (derived from
NetworkID via the SDK's crockford encoding); two networks with
different bootstraps have different DIDs and land in different
directories. URL-unsafe characters (`:`) are allowed in
filesystem paths on every supported platform (Linux, macOS,
Windows via long-path support).

# PERMISSIONS

Directories are created with 0o700 — only the owning user can
read pinned bootstraps. The bootstrap document is PUBLIC
information (every consumer of the network has a copy), so the
permissioning is not a confidentiality measure; it's a defence
against accidental cross-user pollution on shared systems.

Files are created with 0o600. Same reasoning.

# STANDARD SUBDIRS

OpenAt eagerly creates the standard subdirectory layout so
writers don't have to remember:

  - witnesses/      content-addressable witness sets
  - policy/         signature/algorithm/version policy views
  - materialized/   v1.32.0 walker projections (labels.json,
    endpoints.json, auditors.json)
*/
package anchorcache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidDID is returned by Open / OpenAt when networkDID is
// not a valid did:baseproof:network:<crockford> identifier. We
// reject empty + obviously-malformed values at construction so
// the resulting directory cannot end up in the wrong place
// (e.g., ".." or absolute-path injection).
var ErrInvalidDID = errors.New("anchorcache: invalid network DID")

// ErrNoHome is returned by Open when the operator's $HOME env
// var is unset or empty. Tests should use OpenAt with an
// explicit root; binaries running without $HOME (containers,
// init scripts) should set BASEPROOF_CACHE_DIR or pass --cache-dir.
var ErrNoHome = errors.New("anchorcache: $HOME is empty; set BASEPROOF_CACHE_DIR or pass --cache-dir")

// CacheDirEnv names the environment override for the default
// cache root. If set, takes precedence over $HOME/.baseproof.
// Useful in containers + CI systems where $HOME isn't the right
// anchor.
const CacheDirEnv = "BASEPROOF_CACHE_DIR"

// DefaultRelativeDir is appended to $HOME (or used after
// CacheDirEnv) to form the default root.
const DefaultRelativeDir = ".baseproof"

// ManagedDir is a typed handle to ~/.baseproof/networks/<did>/.
// Construct via Open or OpenAt; all per-file operations are
// methods on ManagedDir.
//
// Thread-safety: a ManagedDir is safe for concurrent reads but
// callers MUST serialize writes (the package contract — one
// process is the sole writer; see doc.go).
type ManagedDir struct {
	root       string // absolute path to ~/.baseproof
	networkDID string // the network's full did:baseproof:network:... DID
	dirPath    string // root/networks/<did>
}

// Open returns a ManagedDir rooted at the default cache root
// (BASEPROOF_CACHE_DIR env var, else $HOME/.baseproof) for the given
// networkDID. Creates the network's directory tree if missing.
//
// Returns ErrNoHome when neither BASEPROOF_CACHE_DIR nor $HOME is
// set; returns ErrInvalidDID for an unparseable network DID.
func Open(networkDID string) (*ManagedDir, error) {
	root := os.Getenv(CacheDirEnv)
	if root == "" {
		home := os.Getenv("HOME")
		if home == "" {
			return nil, ErrNoHome
		}
		root = filepath.Join(home, DefaultRelativeDir)
	}
	return OpenAt(root, networkDID)
}

// OpenAt is the test-friendly entry point. root is the absolute
// path to use as the cache root (replaces $HOME/.baseproof).
// Same semantics as Open otherwise.
func OpenAt(root, networkDID string) (*ManagedDir, error) {
	if err := validateNetworkDID(networkDID); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("anchorcache: root %q must be absolute", root)
	}

	dirPath := filepath.Join(root, "networks", networkDID)
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		return nil, fmt.Errorf("anchorcache: mkdir %s: %w", dirPath, err)
	}
	// witnesses + policy + materialized subdirs are part of the
	// standard layout; create them eagerly so writers don't have
	// to remember.
	//
	// materialized/ is the v1.32.0 SDK adoption addition —
	// PolicyViewMaterializedLabels / Endpoints / Auditors
	// write under it.
	for _, sub := range []string{"witnesses", "policy", "materialized"} {
		if err := os.MkdirAll(filepath.Join(dirPath, sub), 0o700); err != nil {
			return nil, fmt.Errorf("anchorcache: mkdir %s: %w", sub, err)
		}
	}

	return &ManagedDir{
		root:       root,
		networkDID: networkDID,
		dirPath:    dirPath,
	}, nil
}

// Root returns the cache root (~/.baseproof or override).
func (d *ManagedDir) Root() string { return d.root }

// NetworkDID returns the DID this handle is bound to.
func (d *ManagedDir) NetworkDID() string { return d.networkDID }

// DirPath returns the absolute path of the per-network directory.
func (d *ManagedDir) DirPath() string { return d.dirPath }

// validateNetworkDID rejects empty / obviously-malicious DIDs.
// We DO allow the full did:baseproof:network:<crockford> form;
// we REJECT path-traversal attempts and absolute paths.
func validateNetworkDID(did string) error {
	if did == "" {
		return fmt.Errorf("%w: empty", ErrInvalidDID)
	}
	if strings.ContainsAny(did, "/\\") {
		return fmt.Errorf("%w: %q contains path separator", ErrInvalidDID, did)
	}
	if did == "." || did == ".." || strings.Contains(did, "..") {
		return fmt.Errorf("%w: %q is path-traversal", ErrInvalidDID, did)
	}
	if filepath.IsAbs(did) {
		return fmt.Errorf("%w: %q is absolute path", ErrInvalidDID, did)
	}
	// The actual DID prefix check is deferred — a test fixture
	// can pass "test-network" and we accept it. Production
	// callers pass the real did:baseproof:network:... form
	// because that's what network.BootstrapDocument.IDs()
	// returns; we don't gate on the prefix to keep the package
	// usable for non-baseproof test scenarios.
	return nil
}

// writeAtomic writes data to dst via an os.Rename(tmp, dst) so a
// process crash mid-write cannot leave a partial file. The temp
// file lives in the same directory as dst so the rename is a
// metadata-only operation (no cross-filesystem copy fallback).
//
// dst's parent directory is assumed to exist (OpenAt creates the
// standard layout); writeAtomic does NOT mkdir.
func writeAtomic(dst string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// If anything fails before the rename succeeds, remove
		// the temp file.
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmpName, dst, err)
	}
	return nil
}
