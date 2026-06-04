/*
FILE PATH: libs/anchorcache/anchorcache_test.go

Tests for the filesystem-backed trust-anchor cache. Uses
t.TempDir() so every test gets a fresh ~/.baseproof-equivalent
root with automatic cleanup.
*/
package anchorcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/log/discover"
	"github.com/baseproof/baseproof/network"
)

const fixtureNetworkDID = "did:baseproof:network:fixture123"

// validBootstrapBytes returns the JCS-canonical bytes of a
// minimal valid BootstrapDocument (passes doc.IDs()).
func validBootstrapBytes(t *testing.T) ([]byte, [32]byte) {
	t.Helper()
	doc := network.BootstrapDocument{
		ProtocolVersion:             "1",
		ExchangeDID:                 "did:web:fixture.example",
		NetworkName:                 "anchorcache-fixture",
		GenesisWitnessSet:           []string{"did:key:zfixture1"},
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("01", 32)},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
	raw, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	return raw, sha256.Sum256(raw)
}

// ─────────────────────────────────────────────────────────────────────
// OpenAt + validateNetworkDID
// ─────────────────────────────────────────────────────────────────────

func TestOpenAt_CreatesLayout(t *testing.T) {
	root := t.TempDir()
	d, err := OpenAt(root, fixtureNetworkDID)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	wantDir := filepath.Join(root, "networks", fixtureNetworkDID)
	if d.DirPath() != wantDir {
		t.Errorf("DirPath = %q, want %q", d.DirPath(), wantDir)
	}
	// Standard subdirs.
	for _, sub := range []string{"witnesses", "policy"} {
		if _, err := os.Stat(filepath.Join(wantDir, sub)); err != nil {
			t.Errorf("subdir %s not created: %v", sub, err)
		}
	}
}

func TestOpenAt_RejectsRelativeRoot(t *testing.T) {
	_, err := OpenAt("relative/path", fixtureNetworkDID)
	if err == nil {
		t.Fatal("relative root must error")
	}
}

func TestOpenAt_RejectsEmptyDID(t *testing.T) {
	_, err := OpenAt(t.TempDir(), "")
	if !errors.Is(err, ErrInvalidDID) {
		t.Fatalf("got %v; want ErrInvalidDID", err)
	}
}

func TestOpenAt_RejectsPathTraversalDID(t *testing.T) {
	for _, did := range []string{
		"..",
		"a/../b",
		"../escape",
		"foo/bar",
		`win\\style`,
	} {
		t.Run(did, func(t *testing.T) {
			_, err := OpenAt(t.TempDir(), did)
			if !errors.Is(err, ErrInvalidDID) {
				t.Errorf("did=%q: got %v; want ErrInvalidDID", did, err)
			}
		})
	}
}

func TestOpen_NoHomeErrors(t *testing.T) {
	t.Setenv(CacheDirEnv, "") // unset override
	t.Setenv("HOME", "")
	_, err := Open(fixtureNetworkDID)
	if !errors.Is(err, ErrNoHome) {
		t.Fatalf("got %v; want ErrNoHome", err)
	}
}

func TestOpen_HonorsCacheDirEnv(t *testing.T) {
	root := t.TempDir()
	t.Setenv(CacheDirEnv, root)
	d, err := Open(fixtureNetworkDID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if d.Root() != root {
		t.Errorf("Root = %q, want %q (from CacheDirEnv)", d.Root(), root)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Bootstrap pin TOFU semantics
// ─────────────────────────────────────────────────────────────────────

func TestPinBootstrap_HappyPath(t *testing.T) {
	root := t.TempDir()
	d, _ := OpenAt(root, fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)

	if err := d.PinBootstrap(raw); err != nil {
		t.Fatalf("PinBootstrap: %v", err)
	}

	// bootstrap.json + fingerprint.txt exist.
	for _, f := range []string{"bootstrap.json", "fingerprint.txt"} {
		if _, err := os.Stat(filepath.Join(d.DirPath(), f)); err != nil {
			t.Errorf("%s not created: %v", f, err)
		}
	}

	// Re-read returns identical bytes.
	got, err := d.ReadBootstrap()
	if err != nil {
		t.Fatalf("ReadBootstrap: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("ReadBootstrap drift: got %q, want %q", got, raw)
	}
}

func TestPinBootstrap_IdempotentOnMatchingFingerprint(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)

	if err := d.PinBootstrap(raw); err != nil {
		t.Fatalf("first PinBootstrap: %v", err)
	}
	// Second call with same bytes — no error.
	if err := d.PinBootstrap(raw); err != nil {
		t.Errorf("idempotent PinBootstrap failed: %v", err)
	}
}

func TestPinBootstrap_RefusesDifferentFingerprint(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)

	if err := d.PinBootstrap(raw); err != nil {
		t.Fatalf("first PinBootstrap: %v", err)
	}
	different := append([]byte(nil), raw...)
	different[0] ^= 0xFF // flip a byte → different fingerprint

	err := d.PinBootstrap(different)
	if !errors.Is(err, ErrAlreadyPinned) {
		t.Fatalf("got %v; want ErrAlreadyPinned", err)
	}
}

func TestPinBootstrap_RejectsEmptyBytes(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	if err := d.PinBootstrap(nil); err == nil {
		t.Fatal("nil bytes must error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// VerifyBootstrap
// ─────────────────────────────────────────────────────────────────────

func TestVerifyBootstrap_MatchesReturnsNil(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)
	_ = d.PinBootstrap(raw)

	if err := d.VerifyBootstrap(raw); err != nil {
		t.Errorf("VerifyBootstrap on matching bytes: %v", err)
	}
}

func TestVerifyBootstrap_MismatchReturnsSDKSentinel(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)
	_ = d.PinBootstrap(raw)

	bad := append([]byte(nil), raw...)
	bad[0] ^= 0xFF
	err := d.VerifyBootstrap(bad)
	if !errors.Is(err, discover.ErrPinMismatch) {
		t.Fatalf("got %v; want wraps discover.ErrPinMismatch", err)
	}
}

func TestVerifyBootstrap_NotPinnedReturnsSDKSentinel(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)
	// No PinBootstrap call.
	err := d.VerifyBootstrap(raw)
	if !errors.Is(err, discover.ErrPinNotFound) {
		t.Fatalf("got %v; want wraps discover.ErrPinNotFound", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ReadBootstrapDoc — decodes + validates the pinned bytes
// ─────────────────────────────────────────────────────────────────────

func TestReadBootstrapDoc_HappyPath(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)
	_ = d.PinBootstrap(raw)

	doc, err := d.ReadBootstrapDoc()
	if err != nil {
		t.Fatalf("ReadBootstrapDoc: %v", err)
	}
	if doc.NetworkName != "anchorcache-fixture" {
		t.Errorf("NetworkName = %q, want anchorcache-fixture", doc.NetworkName)
	}
	// IDs() validates on read; if it returned an error,
	// ReadBootstrapDoc would have failed.
	if _, err := doc.IDs(); err != nil {
		t.Errorf("IDs() on re-read: %v", err)
	}
}

func TestReadBootstrapDoc_NotPinnedErrors(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	_, err := d.ReadBootstrapDoc()
	if !IsNotExist(err) {
		t.Fatalf("got %v; want IsNotExist == true", err)
	}
}

func TestReadBootstrapDoc_CorruptedFileErrors(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	// Write garbage directly (bypass PinBootstrap's validation).
	bsPath := filepath.Join(d.DirPath(), "bootstrap.json")
	if err := os.WriteFile(bsPath, []byte("{corrupted}"), 0o600); err != nil {
		t.Fatalf("seed corrupted file: %v", err)
	}
	_, err := d.ReadBootstrapDoc()
	if err == nil {
		t.Fatal("corrupted bootstrap.json must error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// SinglePinStore — SDK PinStore interface satisfaction
// ─────────────────────────────────────────────────────────────────────

func TestSinglePinStore_VerifyPinnedHappyPath(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, fp := validBootstrapBytes(t)
	_ = d.PinBootstrap(raw)

	ps := NewSinglePinStore(d)
	if err := ps.VerifyPinned(context.Background(), [32]byte{}, fp); err != nil {
		t.Errorf("VerifyPinned: %v", err)
	}
}

func TestSinglePinStore_VerifyPinnedMismatch(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, _ := validBootstrapBytes(t)
	_ = d.PinBootstrap(raw)

	ps := NewSinglePinStore(d)
	err := ps.VerifyPinned(context.Background(), [32]byte{}, [32]byte{0xFF})
	if !errors.Is(err, discover.ErrPinMismatch) {
		t.Fatalf("got %v; want discover.ErrPinMismatch", err)
	}
}

func TestSinglePinStore_VerifyPinnedNotPinned(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	ps := NewSinglePinStore(d)
	err := ps.VerifyPinned(context.Background(), [32]byte{}, [32]byte{0xAA})
	if !errors.Is(err, discover.ErrPinNotFound) {
		t.Fatalf("got %v; want discover.ErrPinNotFound", err)
	}
}

func TestSinglePinStore_PinWithoutBytesRejected(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	ps := NewSinglePinStore(d)
	err := ps.Pin(context.Background(), [32]byte{}, [32]byte{0xAA})
	if err == nil {
		t.Fatal("Pin without PinBootstrap upstream must error")
	}
}

func TestSinglePinStore_PinMatchingFingerprintOK(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	raw, fp := validBootstrapBytes(t)
	_ = d.PinBootstrap(raw)

	ps := NewSinglePinStore(d)
	if err := ps.Pin(context.Background(), [32]byte{}, fp); err != nil {
		t.Errorf("Pin matching: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Per-view persistence
// ─────────────────────────────────────────────────────────────────────

func TestWriteAndReadIdentity_RoundTrip(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	want := Identity{
		NetworkID:     "aabbcc",
		NetworkUUID:   "11111111-2222-3333-4444-555555555555",
		NetworkDID:    fixtureNetworkDID,
		BootstrapHash: "aabbcc",
	}
	if err := d.WriteIdentity(want); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	got, err := d.ReadIdentity()
	if err != nil {
		t.Fatalf("ReadIdentity: %v", err)
	}
	if got != want {
		t.Errorf("Identity drift: got %+v, want %+v", got, want)
	}
}

func TestReadIdentity_NotExistReturnsErrNotExist(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	_, err := d.ReadIdentity()
	if !IsNotExist(err) {
		t.Errorf("got %v; want IsNotExist == true", err)
	}
}

// Mirrors / Peers / Anchors share the same shape; sample one as
// a sweep check.
func TestRawBytesViewsRoundTrip(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	body := []byte(`{"log_did":"did:web:test","mirrors":[]}`)

	cases := []struct {
		name  string
		write func() error
		read  func() ([]byte, error)
	}{
		{"mirrors", func() error { return d.WriteMirrorsBytes(body) }, d.ReadMirrorsBytes},
		{"peers", func() error { return d.WritePeersBytes(body) }, d.ReadPeersBytes},
		{"anchors", func() error { return d.WriteAnchorsBytes(body) }, d.ReadAnchorsBytes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.write(); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := c.read()
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != string(body) {
				t.Errorf("drift: %q vs %q", got, body)
			}
		})
	}
}

func TestWriteBytesRejectsInvalidJSON(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	err := d.WriteMirrorsBytes([]byte(`{not-json`))
	if err == nil {
		t.Fatal("invalid JSON must error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// witnesses/<set_hash>.json — content-addressable
// ─────────────────────────────────────────────────────────────────────

func TestWitnessSetBytes_RoundTrip(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	hashHex := hex.EncodeToString(hash[:])
	body := []byte(`{"set_hash":"` + hashHex + `","keys":[]}`)

	if !d.HasWitnessSet(hashHex) == false {
		t.Errorf("HasWitnessSet must be false before write")
	}
	if err := d.WriteWitnessSetBytes(hashHex, body); err != nil {
		t.Fatalf("WriteWitnessSetBytes: %v", err)
	}
	if !d.HasWitnessSet(hashHex) {
		t.Error("HasWitnessSet must be true after write")
	}
	got, err := d.ReadWitnessSetBytes(hashHex)
	if err != nil {
		t.Fatalf("ReadWitnessSetBytes: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("drift")
	}
}

func TestWitnessSetBytes_RejectsMalformedHash(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	for _, bad := range []string{
		"",
		"too_short",
		strings.Repeat("g", 64),  // non-hex char
		strings.Repeat("AB", 32), // uppercase
		strings.Repeat("00", 31), // 62 chars
		strings.Repeat("00", 33), // 66 chars
	} {
		t.Run(bad, func(t *testing.T) {
			err := d.WriteWitnessSetBytes(bad, []byte(`{}`))
			if err == nil {
				t.Errorf("hash %q must error on write", bad)
			}
			if d.HasWitnessSet(bad) {
				t.Errorf("hash %q must report false for HasWitnessSet", bad)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Policy views
// ─────────────────────────────────────────────────────────────────────

func TestPolicyViews_RoundTrip(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	body := []byte(`{"min_signatures_per_entry":2}`)
	for _, view := range []string{
		PolicyViewSignature, PolicyViewAlgorithm, PolicyViewVersion,
	} {
		t.Run(view, func(t *testing.T) {
			if err := d.WritePolicyBytes(view, body); err != nil {
				t.Fatalf("Write %s: %v", view, err)
			}
			got, err := d.ReadPolicyBytes(view)
			if err != nil {
				t.Fatalf("Read %s: %v", view, err)
			}
			if string(got) != string(body) {
				t.Errorf("drift for %s", view)
			}
		})
	}
}

func TestPolicyViews_RejectsUnknownView(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	if err := d.WritePolicyBytes("unknown.json", []byte(`{}`)); err == nil {
		t.Error("unknown view must be rejected on write")
	}
	if _, err := d.ReadPolicyBytes("unknown.json"); err == nil {
		t.Error("unknown view must be rejected on read")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Cursor
// ─────────────────────────────────────────────────────────────────────

func TestCursor_RoundTrip(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	if err := d.WriteCursor("12345"); err != nil {
		t.Fatalf("WriteCursor: %v", err)
	}
	got, err := d.ReadCursor()
	if err != nil {
		t.Fatalf("ReadCursor: %v", err)
	}
	if got != "12345" {
		t.Errorf("Cursor = %q, want 12345", got)
	}
}

func TestCursor_NotExistError(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	_, err := d.ReadCursor()
	if !IsNotExist(err) {
		t.Errorf("got %v; want IsNotExist == true", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Atomic write — crash safety
// ─────────────────────────────────────────────────────────────────────

// TestWriteAtomic_NoPartialOnExistingFile pins that a successful
// write replaces the previous file content atomically — a reader
// that reads concurrently with the write either sees the OLD
// bytes or the NEW bytes, never a mixed state.
func TestWriteAtomic_NoPartialOnExistingFile(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	if err := d.WriteIdentity(Identity{NetworkID: "old"}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := d.WriteIdentity(Identity{NetworkID: "new"}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ := d.ReadIdentity()
	if got.NetworkID != "new" {
		t.Errorf("NetworkID = %q, want new", got.NetworkID)
	}
}

// TestWriteAtomic_LeavesNoTempFile pins that successful writes
// clean up the .tmp-* sidecar — a leftover would surface in
// directory scans + confuse operators.
func TestWriteAtomic_LeavesNoTempFile(t *testing.T) {
	d, _ := OpenAt(t.TempDir(), fixtureNetworkDID)
	if err := d.WriteIdentity(Identity{NetworkID: "x"}); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	entries, _ := os.ReadDir(d.DirPath())
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}
