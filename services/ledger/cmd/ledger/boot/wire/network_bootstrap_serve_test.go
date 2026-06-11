/*
#75 Phase C — the writer's serve-form decision, pinned where it is made:
buildNetworkBootstrapHandler emits network.EndorsedBootstrapBytes, and a
require-policy constitution whose ceremony cannot be verified is a BOOT
FAILURE — never a quiet 404, never a stripped serve.
*/
package wire

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
)

func mintRequireDoc(t *testing.T) network.BootstrapDocument {
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
		ExchangeDID:       "did:web:serveform.example",
		NetworkName:       "serveform-net",
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
	end, err := network.EndorseGenesis(doc, priv)
	if err != nil {
		t.Fatalf("EndorseGenesis: %v", err)
	}
	doc.GenesisEndorsements = []network.GenesisEndorsement{end}
	return doc
}

// TestBuildNetworkBootstrapHandler_ServesVerifiableForm: the boot-built handler
// serves bytes a client admits through LoadVerifiedBootstrap — the round-trip
// that makes the writer and every first-contact client agree by construction.
func TestBuildNetworkBootstrapHandler_ServesVerifiableForm(t *testing.T) {
	doc := mintRequireDoc(t)
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}
	h, err := buildNetworkBootstrapHandler(doc)
	if err != nil {
		t.Fatalf("an endorsed require constitution must build its serve form: %v", err)
	}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/bootstrap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got, err := network.LoadVerifiedBootstrap(rec.Body.Bytes(), [32]byte(ids.NetworkID))
	if err != nil {
		t.Fatalf("served bytes must round-trip the client first-contact door: %v", err)
	}
	if len(got.GenesisEndorsements) == 0 {
		t.Fatal("served form carries no endorsements — clients cannot verify the ceremony")
	}
}

// TestBuildNetworkBootstrapHandler_RefusesStrippedRequire: a require
// constitution stripped of its endorsements fails the handler BUILD (= boot),
// with the SDK's ceremony error surfacing — serving quietly would make the
// strip attack indistinguishable from an honest legacy network.
func TestBuildNetworkBootstrapHandler_RefusesStrippedRequire(t *testing.T) {
	doc := mintRequireDoc(t)
	doc.GenesisEndorsements = nil // the strip
	if _, err := buildNetworkBootstrapHandler(doc); err == nil {
		t.Fatal("a STRIPPED require constitution built a serve handler — boot must fail instead")
	}
}

// TestBuildNetworkBootstrapHandler_UnconfiguredStays404: no bootstrap document
// (test/dev paths) keeps the structural 404 — absence is not an error.
func TestBuildNetworkBootstrapHandler_UnconfiguredStays404(t *testing.T) {
	h, err := buildNetworkBootstrapHandler(network.BootstrapDocument{})
	if err != nil {
		t.Fatalf("zero doc must not error: %v", err)
	}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/v1/network/bootstrap", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
