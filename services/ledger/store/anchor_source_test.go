package store

// anchor_source_test.go — the projection probe's contract: a real cosigned
// anchor projects its SourceLogDID; EVERYTHING else (other kinds, malformed
// payloads, oversized DIDs, nil) projects "" — the discovery column fails
// toward omission (alarm direction), never toward a wrong attribution.

import (
	"strings"
	"testing"

	sdkanchor "github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
)

func entryWithPayload(t *testing.T, payload []byte) *envelope.Entry {
	t.Helper()
	e, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:key:zPublisher",
		Destination: "did:web:parent.example",
		EventTime:   1_700_000_000_000_000,
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return e
}

func TestAnchorSourceLogDID(t *testing.T) {
	anchorPayload := func(src string) []byte {
		a := sdkanchor.CosignedAnchorV1{
			AnchorType:   sdkanchor.CosignedAnchorType,
			SourceLogDID: src,
			TreeHeadRef:  strings.Repeat("ab", 32),
		}
		raw, err := a.Marshal()
		if err != nil {
			t.Fatalf("marshal anchor: %v", err)
		}
		return raw
	}

	cases := []struct {
		name  string
		entry *envelope.Entry
		want  string
	}{
		{"real cosigned anchor projects", entryWithPayload(t, anchorPayload("did:baseproof:network:child")), "did:baseproof:network:child"},
		{"empty source projects nothing", entryWithPayload(t, anchorPayload("")), ""},
		{"oversized source projects nothing", entryWithPayload(t, anchorPayload(strings.Repeat("x", MaxSourceLogDIDLen+1))), ""},
		{"non-anchor payload projects nothing", entryWithPayload(t, []byte(`{"kind":"BP-ENTRY-WITNESS-ENDPOINT-V1"}`)), ""},
		{"garbage payload projects nothing", entryWithPayload(t, []byte("not json")), ""},
		{"nil entry projects nothing", nil, ""},
	}
	for _, c := range cases {
		if got := AnchorSourceLogDID(c.entry); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
