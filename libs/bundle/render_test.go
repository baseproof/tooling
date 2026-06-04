/*
FILE PATH: libs/bundle/render_test.go

Pins the Render function's stable output shape — the lines a
future `baseproof inspect` CLI promises consumers (operators
parsing logs, dashboards capturing terminal output).
*/
package bundle

import (
	"strings"
	"testing"
	"time"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	sdktypes "github.com/baseproof/baseproof/types"
)

func renderableBundle() *sdkbundle.Bundle {
	return &sdkbundle.Bundle{
		Format:        sdkbundle.FormatV1,
		NetworkID:     [32]byte{0xAA, 0xBB, 0xCC, 0xDD},
		NetworkDID:    "did:baseproof:network:test123",
		BootstrapHash: [32]byte{0x11, 0x22, 0x33, 0x44},
		Entry: sdkbundle.BundleEntry{
			WireBytes: []byte("entry-bytes"),
			Sequence:  42,
			LogTime:   time.Unix(1700000000, 0).UTC(),
		},
		CosignedHead: sdktypes.CosignedTreeHead{
			TreeHead: sdktypes.TreeHead{
				TreeSize: 100,
				RootHash: [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
				SMTRoot:  [32]byte{0xFE, 0xED, 0xBE, 0xEF},
			},
			Signatures: []sdktypes.WitnessSignature{
				{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: []byte{0xAA}},
				{PubKeyID: [32]byte{0x02}, SchemeTag: 0x01, SigBytes: []byte{0xBB}},
			},
		},
		InclusionProof: sdktypes.MerkleProof{
			LeafPosition: 42,
			Siblings:     [][32]byte{{0x01}, {0x02}, {0x03}},
		},
		SMTProof: sdktypes.SMTProof{
			TerminalKind: sdktypes.SMTTerminalLeaf,
			TerminalLeaf: &sdktypes.SMTLeaf{Key: [32]byte{0x77}},
		},
		WitnessSetHint: sdkbundle.WitnessSetHint{SetHash: [32]byte{0xC0, 0xFE, 0xE0}},
		Algorithms:     sdkbundle.DefaultAlgorithmsHint(),
	}
}

// TestRender_NilReturnsEmpty pins the nil-safe contract.
func TestRender_NilReturnsEmpty(t *testing.T) {
	if got := Render(nil); got != "" {
		t.Errorf("Render(nil) = %q, want empty", got)
	}
}

// TestRender_StableLines pins every line the renderer emits.
// A regression in any line surfaces here — operators / dashboards
// pin their parsers on these field names + the colon-space layout.
func TestRender_StableLines(t *testing.T) {
	b := renderableBundle()
	out := Render(b)

	// Per-line presence. Each line is a stable contract.
	requiredSubstrings := []string{
		"Bundle baseproof-bundle/v1",
		"Network:        did:baseproof:network:test123",
		"NetworkID:      aabbccdd", // hex of [32]byte{0xAA, 0xBB, ...}
		"Bootstrap hash: 11223344", // hex of [32]byte{0x11, 0x22, ...}
		"Entry:          seq=42",
		"Tree:           size=100 root=deadbeef...",
		"SMT root:       feedbeef...",
		"Inclusion:      leaf=42 path-depth=3",
		"SMT terminal:   leaf",
		"Witness set:    c0fee0",
		"Algorithms:     entry=\"ecdsa-secp256k1\"",
		"Hash families:  merkle=",
		"Signatures:     2 at this head",
	}
	for _, want := range requiredSubstrings {
		if !strings.Contains(out, want) {
			t.Errorf("Render output missing %q in:\n%s", want, out)
		}
	}
}

func TestRender_NonMembershipTerminal(t *testing.T) {
	b := renderableBundle()
	b.SMTProof.TerminalKind = sdktypes.SMTTerminalEmpty
	b.SMTProof.TerminalLeaf = nil
	out := Render(b)
	if !strings.Contains(out, "empty (non-membership)") {
		t.Errorf("non-membership terminal not rendered:\n%s", out)
	}
}

func TestRender_BranchMismatchTerminal(t *testing.T) {
	b := renderableBundle()
	b.SMTProof.TerminalKind = sdktypes.SMTTerminalMismatch
	out := Render(b)
	if !strings.Contains(out, "branch_mismatch") {
		t.Errorf("branch-mismatch terminal not rendered:\n%s", out)
	}
}

func TestRender_UnknownTerminalKind(t *testing.T) {
	b := renderableBundle()
	b.SMTProof.TerminalKind = 99 // not a defined SDK constant
	out := Render(b)
	if !strings.Contains(out, "unknown(99)") {
		t.Errorf("unknown terminal kind not surfaced:\n%s", out)
	}
}

func TestRender_ZeroTimeOmitsTimestamp(t *testing.T) {
	b := renderableBundle()
	b.Entry.LogTime = time.Time{}
	out := Render(b)
	// "at <time>" should be absent when LogTime is zero.
	if strings.Contains(out, " at ") && strings.Contains(out, "seq=42 at ") {
		t.Errorf("zero LogTime should not render an 'at' timestamp:\n%s", out)
	}
}
