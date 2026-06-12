/*
FILE PATH: api/network_bundle_test.go

DESCRIPTION:

	Pins the platform's GET /v1/network/bundle composition:

	  - a pre-bootstrap node mounts NOTHING (nil handler, matching the
	    404 posture of the other identity-derived surfaces);
	  - the served manifest is DERIVED from the same boot sources the
	    sibling /v1/network/* handlers serve: identity (network id + DID),
	    quorum + name from the bootstrap document, the destination log DID,
	    the federation graph's siblings, and the admission posture — with
	    an EMPTY operation DAG (the platform owns no domain vocabulary);
	  - the destination key is the network DID (what /v1/network/identity
	    publishes); anything else is 404, and the bare GET envelope lists
	    exactly that DID;
	  - no PublicURL ⇒ no Endpoints section (the document never asserts an
	    address the operator didn't configure), and the transport posture
	    is derived from the scheme (https ⇒ server-verify, http ⇒
	    plaintext);
	  - the shared serve handler's contract holds here too: sha256 ETag +
	    If-None-Match → 304, X-Manifest-Published: false in unpublished
	    mode.
*/
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/tooling/libs/networkbundle"
)

func bundleSources(t *testing.T, publicURL string) NetworkBundleSources {
	t.Helper()
	return NetworkBundleSources{
		Doc:            validBootstrap(t),
		LogDID:         "did:web:log.example",
		PublicURL:      publicURL,
		Payment:        []string{"credit", "pow"},
		EpochWindowSec: 300,
		Federation: WireFederationGraph{
			Siblings: []WireLogNode{
				{NetworkID: "11111111111111111111111111111111111111111111111111111111111111aa", AdmissionURL: "https://peer-a.example"},
				{NetworkID: "22222222222222222222222222222222222222222222222222222222222222bb"},
			},
		},
	}
}

func bundleGET(t *testing.T, h http.Handler, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNewNetworkBundleHandler_PreBootstrapNodeMountsNothing(t *testing.T) {
	h, err := NewNetworkBundleHandler(NetworkBundleSources{LogDID: "did:web:log.example"})
	if err != nil {
		t.Fatalf("zero doc must not error: %v", err)
	}
	if h != nil {
		t.Fatal("a pre-bootstrap node has nothing to describe — handler must be nil (route unmounted)")
	}
}

func TestNetworkBundle_ServesDerivedPlatformManifest(t *testing.T) {
	src := bundleSources(t, "https://ledger.example/")
	h, err := NewNetworkBundleHandler(src)
	if err != nil || h == nil {
		t.Fatalf("handler: %v / %v", h, err)
	}
	id, err := BuildNetworkIdentity(src.Doc)
	if err != nil {
		t.Fatal(err)
	}

	// The bare GET envelope lists exactly the network DID.
	rec := bundleGET(t, h, "/v1/network/bundle", nil)
	var env struct {
		Format    string   `json:"format"`
		Exchanges []string `json:"exchanges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Format != networkbundle.ManifestFormat || len(env.Exchanges) != 1 || env.Exchanges[0] != id.NetworkDID {
		t.Fatalf("envelope = %+v, want the network DID %s", env, id.NetworkDID)
	}

	// An unknown destination is 404.
	if rec := bundleGET(t, h, "/v1/network/bundle?destination=did:web:stranger", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown destination: %d, want 404", rec.Code)
	}

	// The manifest, by the DID identity publishes.
	rec = bundleGET(t, h, "/v1/network/bundle?destination="+id.NetworkDID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Manifest-Published") != "false" {
		t.Error("no anchor configured ⇒ unpublished mode")
	}
	m, err := networkbundle.DecodeManifest(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("served document must strict-decode: %v", err)
	}

	// Identity-derived fields match what /v1/network/identity serves.
	if m.Network.NetworkID != id.NetworkID || m.Exchange != id.NetworkDID {
		t.Errorf("identity drift: manifest (%s, %s) vs identity (%s, %s)",
			m.Network.NetworkID, m.Exchange, id.NetworkID, id.NetworkDID)
	}
	if m.Network.Name != src.Doc.NetworkName || m.Network.QuorumK != src.Doc.GenesisQuorumK {
		t.Errorf("bootstrap drift: name=%q quorum=%d", m.Network.Name, m.Network.QuorumK)
	}
	if m.Network.LogDID != "did:web:log.example" {
		t.Errorf("log DID = %q", m.Network.LogDID)
	}
	if m.Network.BootstrapEndpoint != "https://ledger.example" {
		t.Errorf("bootstrap endpoint must be the trimmed public URL: %q", m.Network.BootstrapEndpoint)
	}

	// The single ledger endpoint: https ⇒ server-verify, health probe set.
	if len(m.Endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want exactly the ledger", m.Endpoints)
	}
	ep := m.Endpoints[0]
	if ep.ID != "ledger" || ep.URL != "https://ledger.example" || ep.Transport.TLS != "server-verify" ||
		ep.Protocol != "baseproof-ledger/v1" || ep.Status != "/healthz" {
		t.Errorf("ledger endpoint = %+v", ep)
	}

	// Admission posture, submit door, status probes.
	if m.Admission.Gating != "open" || m.Admission.WriteVia != "ledger" ||
		m.Admission.PolicyProbe != "/v1/admission/policy" || m.Admission.EpochWindowSec != 300 ||
		len(m.Admission.Payment) != 2 {
		t.Errorf("admission = %+v", m.Admission)
	}
	if m.Submit.Endpoint != "ledger" || m.Submit.Path != "/v1/entries" {
		t.Errorf("submit = %+v", m.Submit)
	}
	if m.Status.Protocol != "ledger:/v1/entries-hash/{hash}" || m.Status.Finality != "ledger:/v1/tree/horizon" {
		t.Errorf("status probes = %+v", m.Status)
	}

	// The platform carries NO domain vocabulary.
	if len(m.Operations) != 0 || len(m.Roles) != 0 || len(m.Datatypes) != 0 {
		t.Errorf("the platform manifest must carry an empty domain layer: ops=%d roles=%d datatypes=%d",
			len(m.Operations), len(m.Roles), len(m.Datatypes))
	}

	// Federation is the peers snapshot, mapped.
	if len(m.Federation) != 2 ||
		m.Federation[0].NetworkID != src.Federation.Siblings[0].NetworkID ||
		m.Federation[0].Endpoint != "https://peer-a.example" ||
		m.Federation[1].Endpoint != "" {
		t.Errorf("federation = %+v", m.Federation)
	}

	// Shared serve contract: ETag round-trips to 304.
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("ETag required")
	}
	if rec := bundleGET(t, h, "/v1/network/bundle?destination="+id.NetworkDID, map[string]string{"If-None-Match": etag}); rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: %d, want 304", rec.Code)
	}
}

func TestNetworkBundle_NoPublicURL_AssertsNoAddress(t *testing.T) {
	h, err := NewNetworkBundleHandler(bundleSources(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := BuildNetworkIdentity(validBootstrap(t))
	rec := bundleGET(t, h, "/v1/network/bundle?destination="+id.NetworkDID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	m, err := networkbundle.DecodeManifest(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Endpoints) != 0 || m.Submit.Endpoint != "" || m.Admission.WriteVia != "" || m.Network.BootstrapEndpoint != "" {
		t.Errorf("with no PublicURL the document must assert no address: eps=%+v submit=%+v write_via=%q",
			m.Endpoints, m.Submit, m.Admission.WriteVia)
	}
	if m.Submit.Path != "/v1/entries" {
		t.Errorf("the submit PATH is still declared: %q", m.Submit.Path)
	}
}

func TestNetworkBundle_PlaintextPostureDerivedFromScheme(t *testing.T) {
	h, err := NewNetworkBundleHandler(bundleSources(t, "http://ledger.local:8080"))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := BuildNetworkIdentity(validBootstrap(t))
	rec := bundleGET(t, h, "/v1/network/bundle?destination="+id.NetworkDID, nil)
	m, err := networkbundle.DecodeManifest(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if m.Endpoints[0].Transport.TLS != "plaintext" {
		t.Errorf("http:// must derive plaintext posture, got %q", m.Endpoints[0].Transport.TLS)
	}
}
