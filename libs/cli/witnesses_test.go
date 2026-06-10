package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWitnesses_CurrentAndAt drives `baseproof witnesses` against a fake ledger
// serving the current set, a historical set (/at/{seq}), and labels — asserting
// the command fetches + renders both the current and the time-travel views.
func TestWitnesses_CurrentAndAt(t *testing.T) {
	ctx := context.Background()
	writeJSONResp := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	id1 := strings.Repeat("11", 32)
	id2 := strings.Repeat("22", 32)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/witnesses/current", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, wireWitnessSetFull{
			SetHash: strings.Repeat("ab", 32), SchemeTag: 1, EffectiveSeq: 100,
			Keys: []wireWitnessKeyFull{{ID: id1, PublicKey: "04aa", SchemeTag: 1}, {ID: id2, PublicKey: "04bb", SchemeTag: 1}},
		})
	})
	mux.HandleFunc("/v1/network/witnesses/at/{seq}", func(w http.ResponseWriter, _ *http.Request) {
		retired := uint64(99)
		writeJSONResp(w, wireWitnessSetFull{
			SetHash: strings.Repeat("cd", 32), SchemeTag: 1, EffectiveSeq: 0, RetiredSeq: &retired,
			Keys: []wireWitnessKeyFull{{ID: id1, PublicKey: "04aa", SchemeTag: 1}},
		})
	})
	mux.HandleFunc("/v1/network/labels", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, wireLabels{Labels: []wireLabelEntry{{PubKeyID: id1, Label: "anchor-witness"}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	bundlePath := writeBundle(t, ClientBundle{
		NetworkID: strings.Repeat("ef", 32), Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 2,
	})

	// current set
	if err := RunWitnesses(ctx, []string{"--bundle", bundlePath}); err != nil {
		t.Fatalf("witnesses (current): %v", err)
	}
	// time-travel to a historical (retired) set
	if err := RunWitnesses(ctx, []string{"--bundle", bundlePath, "--at", "50"}); err != nil {
		t.Fatalf("witnesses (--at 50): %v", err)
	}
}
