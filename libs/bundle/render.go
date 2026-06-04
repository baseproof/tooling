/*
FILE PATH: libs/bundle/render.go

Pretty-print a Bundle for human consumption. Used by:

  - A future `baseproof inspect <bundle>` CLI.
  - Operator-facing dashboards rendering a Verdict outcome.
  - Test diagnostics — a failed assertion's bundle can be
    surfaced verbatim so the failure shape is legible.

The renderer produces a stable, line-oriented text format
suitable for terminal output and structured-log capture. Bytes
are hex-encoded; positions are decimal. No colour codes — leaves
that to the caller's terminal layer.

# WHY NOT JSON

JSON is what the wire format ALREADY is (the bundle's JCS bytes).
A consumer that wants JSON has it for free. The renderer's job
is the OPPOSITE — a quick-glance human view.
*/
package bundle

import (
	"fmt"
	"sort"
	"strings"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	sdktypes "github.com/baseproof/baseproof/types"
)

// Render returns a multi-line, human-readable summary of bundle.
// Empty string when bundle is nil (callers should check that
// before calling).
//
// Output shape (stable; tests pin individual lines):
//
//	Bundle baseproof-bundle/v1
//	  Network:        did:baseproof:network:<crockford>
//	  NetworkID:      <64-char hex>
//	  Bootstrap hash: <64-char hex>
//	  Entry:          seq=<N> at <RFC3339Nano>
//	  Tree:           size=<S> root=<8-char hex prefix>...
//	  SMT root:       <8-char hex prefix>...
//	  Inclusion:      leaf=<N> path-depth=<D>
//	  SMT terminal:   <leaf|leaf_blocking|branch_mismatch|empty>
//	  Witness set:    <64-char hex>
//	  Algorithms:     entry=[<algoIDs>] witness=[<schemeTags>]
//	  Signatures:     N at this head (cosigned by witness set)
func Render(b *sdkbundle.Bundle) string {
	if b == nil {
		return ""
	}

	var w strings.Builder
	fmt.Fprintf(&w, "Bundle %s\n", b.Format)
	fmt.Fprintf(&w, "  Network:        %s\n", b.NetworkDID)
	fmt.Fprintf(&w, "  NetworkID:      %x\n", b.NetworkID)
	fmt.Fprintf(&w, "  Bootstrap hash: %x\n", b.BootstrapHash)
	if !b.Entry.LogTime.IsZero() {
		fmt.Fprintf(&w, "  Entry:          seq=%d at %s\n",
			b.Entry.Sequence, b.Entry.LogTime.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"))
	} else {
		fmt.Fprintf(&w, "  Entry:          seq=%d\n", b.Entry.Sequence)
	}
	fmt.Fprintf(&w, "  Tree:           size=%d root=%s...\n",
		b.CosignedHead.TreeSize, shortHex(b.CosignedHead.RootHash[:]))
	fmt.Fprintf(&w, "  SMT root:       %s...\n", shortHex(b.CosignedHead.SMTRoot[:]))
	fmt.Fprintf(&w, "  Inclusion:      leaf=%d path-depth=%d\n",
		b.InclusionProof.LeafPosition, len(b.InclusionProof.Siblings))
	fmt.Fprintf(&w, "  SMT terminal:   %s\n", smtTerminalKind(b.SMTProof.TerminalKind))
	fmt.Fprintf(&w, "  Witness set:    %x\n", b.WitnessSetHint.SetHash)

	// AlgorithmsHint carries name strings (not numeric IDs) —
	// render the envelope signing algorithm + the witness
	// cosignature algorithm list. Same fields the SDK's
	// DefaultAlgorithmsHint populates.
	fmt.Fprintf(&w, "  Algorithms:     entry=%q witness=[%s]\n",
		b.Algorithms.EnvelopeSig, strings.Join(b.Algorithms.CosignSigs, ","))
	fmt.Fprintf(&w, "  Hash families:  merkle=%q smt=%q\n",
		b.Algorithms.MerkleHash, b.Algorithms.SMTHash)
	fmt.Fprintf(&w, "  Signatures:     %d at this head\n",
		len(b.CosignedHead.Signatures))
	return w.String()
}

// shortHex returns the first 8 hex chars of b — a 4-byte preview
// suitable for at-a-glance comparison. Returns "(empty)" for an
// empty byte slice.
func shortHex(b []byte) string {
	if len(b) == 0 {
		return "(empty)"
	}
	if len(b) >= 4 {
		return fmt.Sprintf("%x", b[:4])
	}
	return fmt.Sprintf("%x", b)
}

// smtTerminalKind translates the SDK's uint8 TerminalKind into a
// human name. The SDK ships exactly three terminal kinds (Empty,
// Leaf, Mismatch — types/proofs.go:123-126); the leaf-key-equals-
// query-key vs. leaf-key-differs-from-query-key distinction is
// observed by comparing TerminalLeaf.Key with the query key, NOT
// by a separate "leaf_blocking" constant.
func smtTerminalKind(k uint8) string {
	switch k {
	case sdktypes.SMTTerminalLeaf:
		return "leaf"
	case sdktypes.SMTTerminalMismatch:
		return "branch_mismatch (non-membership)"
	case sdktypes.SMTTerminalEmpty:
		return "empty (non-membership)"
	default:
		return fmt.Sprintf("unknown(%d)", k)
	}
}

// _ keeps the sort import stable in case future render fields
// need ordered slices.
var _ = sort.Sort
