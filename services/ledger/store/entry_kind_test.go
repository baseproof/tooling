package store

import (
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/kinds"
)

func TestEntryKindProjection(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"recognized schema-shard-genesis", `{"kind":"` + kinds.EntrySchemaShardGenesisV1 + `","x":1}`, kinds.EntrySchemaShardGenesisV1},
		{"recognized network-burn", `{"kind":"` + kinds.EntryNetworkBurnV1 + `"}`, kinds.EntryNetworkBurnV1},
		{"recognized destination-provision", `{"kind":"` + kinds.EntryDestinationProvisionV1 + `"}`, kinds.EntryDestinationProvisionV1},
		{"unrecognized kind projects nothing", `{"kind":"BP-ENTRY-NOT-REAL-V1"}`, ""},
		{"attacker free-string projects nothing", `{"kind":"'; DROP TABLE entry_index;--"}`, ""},
		{"no kind field", `{"event_type":"case_initiation"}`, ""},
		{"empty kind", `{"kind":""}`, ""},
		{"non-JSON payload", `not json at all`, ""},
		{"empty payload", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EntryKindProjection(&envelope.Entry{DomainPayload: []byte(tc.payload)})
			if got != tc.want {
				t.Fatalf("EntryKindProjection = %q, want %q", got, tc.want)
			}
		})
	}
	// nil entry is the defensive no-op.
	if got := EntryKindProjection(nil); got != "" {
		t.Fatalf("nil entry must project nothing, got %q", got)
	}
}

// TestEntryKindProjection_WholeCatalogRoundTrips proves the projection
// recognizes EVERY kind the SDK enumerates — so a future SDK kind that the
// admission firewall gains an arm for is automatically indexable, with no
// drift between the closed set and what gets projected.
func TestEntryKindProjection_WholeCatalogRoundTrips(t *testing.T) {
	for _, k := range kinds.AllEntryKinds() {
		payload := `{"kind":"` + k + `"}`
		if got := EntryKindProjection(&envelope.Entry{DomainPayload: []byte(payload)}); got != k {
			t.Fatalf("catalog kind %q did not round-trip: got %q", k, got)
		}
	}
}
