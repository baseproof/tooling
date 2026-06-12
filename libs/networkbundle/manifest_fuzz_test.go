/*
FILE PATH: libs/networkbundle/manifest_fuzz_test.go

DESCRIPTION:

	The wire mandate's fuzz target for the discovery container. Invariants
	under arbitrary bytes:

	  - DecodeManifest never panics;
	  - IF it accepts, the document re-validates, canonicalizes, and the
	    canonical bytes are a FIXED POINT: re-decoding them re-canonicalizes
	    to identical bytes, and ContentHash == sha256(canonical) — so an
	    accepted document can always be served, anchored, and re-verified
	    byte-stably.

	Seeds: the golden pre-move document, the full reference manifest, and a
	handful of near-miss shapes (unknown field, wrong format tag, truncated)
	to push the decoder's refusal paths into coverage.
*/
package networkbundle

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func FuzzDecodeManifest(f *testing.F) {
	f.Add([]byte(goldenPreMoveManifest))
	if b, err := refManifest().CanonicalBytes(); err == nil {
		f.Add(b)
	}
	f.Add([]byte(strings.Replace(goldenPreMoveManifest, `"exchange"`, `"surprise": 1, "exchange"`, 1)))
	f.Add([]byte(strings.Replace(goldenPreMoveManifest, "manifest/v1", "manifest/v9", 1)))
	f.Add([]byte(goldenPreMoveManifest)[:200])
	f.Add([]byte(`{"format":"baseproof-network-manifest/v1","exchange":"x","operations":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DecodeManifest(data)
		if err != nil {
			return // refusal is always a legal outcome
		}
		// Accepted ⇒ the document must be fully well-behaved.
		if vErr := m.Validate(); vErr != nil {
			t.Fatalf("accepted document failed re-validation: %v", vErr)
		}
		canon, cErr := m.CanonicalBytes()
		if cErr != nil {
			t.Fatalf("accepted document failed to canonicalize: %v", cErr)
		}
		h, hErr := m.ContentHash()
		if hErr != nil || h != sha256.Sum256(canon) {
			t.Fatalf("ContentHash invariant broken: %v", hErr)
		}
		back, dErr := DecodeManifest(canon)
		if dErr != nil {
			t.Fatalf("canonical bytes failed to re-decode: %v", dErr)
		}
		canon2, c2Err := back.CanonicalBytes()
		if c2Err != nil || !bytes.Equal(canon, canon2) {
			t.Fatal("canonical form is not a fixed point")
		}
		// The graph mechanics must also be total on accepted documents.
		_ = m.TopoOrder()
		if len(m.Operations) > 0 {
			_ = m.DependentsOf(m.Operations[0].EventType)
		}
	})
}
