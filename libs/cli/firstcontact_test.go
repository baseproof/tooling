/*
FILE PATH: libs/cli/firstcontact_test.go

#75 — the client half of the endorsed-transport contract, pinned at the ONE
first-contact chokepoint every CLI flow funnels through (fetchBootstrap →
network.LoadVerifiedBootstrap):

  - FORM-AGNOSTIC acceptance: the same pin admits the canonical serve and the
    endorsed serve (the NetworkID is recomputed over the canonical subset).
  - THE STRIP ATTACK refused: a require-policy constitution served WITHOUT its
    endorsements (the policy survives inside the canonical bytes; the ceremony
    does not) is rejected client-side, whatever the server chose to do.
  - THE PINLESS PATH is dead: a bundle with no bootstrap pin refuses first
    contact instead of trusting whatever the endpoint serves.
*/
package cli

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
)

// mintRequireNetwork builds a require-policy constitution whose single witness
// key the test holds, returning the endorsed serve bytes, the stripped
// (canonical-only) bytes, and the NetworkID pin.
func mintRequireNetwork(t *testing.T) (endorsed, stripped []byte, pinHex string) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	doc := network.BootstrapDocument{
		ProtocolVersion:   "1",
		ExchangeDID:       "did:web:strip.example",
		NetworkName:       "strip-attack-net",
		GenesisWitnessSet: []string{sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)},
		GenesisQuorumK:    1,
		GenesisTreeHead:   network.GenesisTreeHead{RootHash: strings.Repeat("0", 64)},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: false, CostMode: "uncharged",
		},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes: []uint16{1}, AllowedCosignSchemeTags: []uint8{1}, MinSignaturesPerEntry: 1,
		},
		GenesisEndorsementPolicy: network.GenesisEndorsementRequire,
	}
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}
	end, err := network.EndorseGenesis(doc, priv)
	if err != nil {
		t.Fatalf("EndorseGenesis: %v", err)
	}
	doc.GenesisEndorsements = []network.GenesisEndorsement{end}
	endorsed, err = network.EndorsedBootstrapBytes(doc)
	if err != nil {
		t.Fatalf("EndorsedBootstrapBytes: %v", err)
	}
	stripped, err = doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	return endorsed, stripped, hex.EncodeToString(ids.NetworkID[:])
}

func serveBootstrap(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchBootstrap_EndorsedServeAccepted(t *testing.T) {
	endorsed, _, pin := mintRequireNetwork(t)
	srv := serveBootstrap(t, endorsed)
	hc := &http.Client{Timeout: 5 * time.Second}

	doc, err := fetchBootstrap(context.Background(), hc, srv.URL, pin)
	if err != nil {
		t.Fatalf("endorsed serve must pass first contact: %v", err)
	}
	if len(doc.GenesisEndorsements) != 1 {
		t.Fatalf("verified doc carries %d endorsements, want 1", len(doc.GenesisEndorsements))
	}
}

func TestFetchBootstrap_StripAttackRefused(t *testing.T) {
	_, stripped, pin := mintRequireNetwork(t)
	srv := serveBootstrap(t, stripped)
	hc := &http.Client{Timeout: 5 * time.Second}

	_, err := fetchBootstrap(context.Background(), hc, srv.URL, pin)
	if err == nil {
		t.Fatal("a require constitution served WITHOUT its endorsements passed first contact — the strip attack succeeds")
	}
}

func TestFetchBootstrap_PinlessRefused(t *testing.T) {
	endorsed, _, _ := mintRequireNetwork(t)
	srv := serveBootstrap(t, endorsed)
	hc := &http.Client{Timeout: 5 * time.Second}

	if _, err := fetchBootstrap(context.Background(), hc, srv.URL, ""); err == nil {
		t.Fatal("a pinless bundle made unverified first contact — the lenient path is alive")
	}
}
