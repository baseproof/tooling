package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
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

// genesisFixture serves a REAL bootstrap (canonical bytes, real did:keys) and
// NO witness-history endpoints — the never-rotated / pre-genesis-baseline
// ledger shape that 404s /v1/network/witnesses/*.
func genesisFixture(t *testing.T, nWitnesses int) (srv *httptest.Server, bundlePath string) {
	t.Helper()
	dids := make([]string, nWitnesses)
	for i := range dids {
		kp, err := sdkdid.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
		}
		dids[i] = kp.DID
	}
	// GenesisQuorumK is REQUIRED + NetworkID-bound since rc4; a simple majority
	// satisfies 2K>N for any N. The same k feeds the bundle below so the served
	// constitution and the client handle agree (the CLI derives K from the
	// verified doc, #74).
	k := len(dids)/2 + 1
	doc := network.BootstrapDocument{
		ProtocolVersion:        "1.0",
		ExchangeDID:            "did:web:genesis.test",
		NetworkName:            "genesis-fallback-test",
		GenesisWitnessSet:      dids,
		GenesisQuorumK:         k,
		GenesisTreeHead:        network.GenesisTreeHead{RootHash: strings.Repeat("00", 32)},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{CostMode: "uncharged"},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	sum := sha256.Sum256(canonical)
	idHex := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(canonical)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	bundlePath = writeBundle(t, ClientBundle{
		NetworkID: idHex, BootstrapHash: idHex, Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: k,
	})
	return srv, bundlePath
}

// TestWitnesses_GenesisFallback pins the fallback: when the ledger serves no
// witness history at all (404 on /current — never rotated, or an image
// predating the genesis-baseline row), the command derives the genesis set
// from the hash-verified bootstrap instead of failing.
func TestWitnesses_GenesisFallback(t *testing.T) {
	ctx := context.Background()
	_, bundlePath := genesisFixture(t, 3)

	if err := RunWitnesses(ctx, []string{"--bundle", bundlePath}); err != nil {
		t.Fatalf("witnesses (genesis fallback): %v", err)
	}
	// --at with no history at all: genesis covers every committed seq.
	if err := RunWitnesses(ctx, []string{"--bundle", bundlePath, "--at", "7"}); err != nil {
		t.Fatalf("witnesses --at (genesis fallback): %v", err)
	}
}

// TestWitnesses_AtRefusesRealHistoryHole pins the guard: when /current SERVES
// a set but /at/{seq} 404s, that is a hole in recorded history (a ledger that
// rotated before the genesis baseline existed) — the command surfaces it
// rather than guessing the genesis set covered that era.
func TestWitnesses_AtRefusesRealHistoryHole(t *testing.T) {
	ctx := context.Background()
	writeJSONResp := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/witnesses/current", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, wireWitnessSetFull{
			SetHash: strings.Repeat("ab", 32), SchemeTag: 1, EffectiveSeq: 100,
			Keys: []wireWitnessKeyFull{{ID: strings.Repeat("11", 32), PublicKey: "04aa", SchemeTag: 1}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	bundlePath := writeBundle(t, ClientBundle{
		NetworkID: strings.Repeat("ef", 32), Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 2,
	})

	err := RunWitnesses(ctx, []string{"--bundle", bundlePath, "--at", "5"})
	if err == nil {
		t.Fatal("expected an error for a real history hole (current serves, at 404s)")
	}
	if !strings.Contains(err.Error(), "history exists") {
		t.Fatalf("error should name the history hole, got: %v", err)
	}
}
