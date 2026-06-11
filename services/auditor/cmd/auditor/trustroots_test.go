package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdknetwork "github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/auditing/peers"
	"github.com/baseproof/tooling/services/auditor/internal/gossipfeed"
)

// newDIDKey mints a fresh secp256k1 did:key (the shape of both witness DIDs and
// a ledger's operational gossip-originator DID).
func newDIDKey(t *testing.T) string {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	did, err := gossipfeed.DIDKeyForSigningKey(priv)
	if err != nil {
		t.Fatalf("DIDKeyForSigningKey: %v", err)
	}
	return did
}

// writeBootstrap mints n did:key witnesses and writes a minimal valid bootstrap
// document, returning its path + the exchange (log) DID.
func writeBootstrap(t *testing.T, n int) (path, exchangeDID string) {
	t.Helper()
	dids := make([]string, n)
	for i := 0; i < n; i++ {
		dids[i] = newDIDKey(t)
	}
	exchangeDID = "did:web:test:log"
	doc := sdknetwork.BootstrapDocument{
		ProtocolVersion:   "1",
		NetworkName:       "auditor-test-net",
		ExchangeDID:       exchangeDID,
		GenesisWitnessSet: dids,
		GenesisQuorumK:    len(dids)/2 + 1, // REQUIRED since rc4; majority always satisfies 2K>N
		GenesisTreeHead: sdknetwork.GenesisTreeHead{
			RootHash: hex.EncodeToString(make([]byte, 32)),
			TreeSize: 0,
		},
		GenesisAdmissionPolicy: sdknetwork.GenesisAdmissionPolicy{
			GatingRequired: false,
			CostMode:       "uncharged",
		},
		GenesisSignaturePolicy: sdknetwork.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001}, // SigAlgoECDSA
			AllowedCosignSchemeTags: []uint8{0x01},    // SchemeECDSA
			MinSignaturesPerEntry:   1,
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal bootstrap: %v", err)
	}
	path = filepath.Join(t.TempDir(), "network-bootstrap.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}
	return path, exchangeDID
}

// logInfoServer stands in for a peer ledger's GET /v1/log-info.
func logInfoServer(t *testing.T, body map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/log-info" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLoadBootstrap proves the auditor parses NetworkID + exchange_did + the
// genesis witness DIDs and validates K-of-N — WITHOUT prematurely keying the
// witness set (the key is the per-peer gossip originator, resolved later).
func TestLoadBootstrap(t *testing.T) {
	path, exchangeDID := writeBootstrap(t, 5)

	nid, gotExchange, witnessDIDs, _, err := loadBootstrap(path, 3)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	if nid == ([32]byte{}) {
		t.Error("NetworkID must be non-zero (derived from the bootstrap)")
	}
	if gotExchange != exchangeDID {
		t.Errorf("exchange_did = %q, want %q", gotExchange, exchangeDID)
	}
	if len(witnessDIDs) != 5 {
		t.Errorf("witnessDIDs = %d, want 5", len(witnessDIDs))
	}
}

func TestLoadBootstrap_FailClosed(t *testing.T) {
	path, _ := writeBootstrap(t, 3)

	if _, _, _, _, err := loadBootstrap(path, 0); err == nil {
		t.Error("K=0 must fail")
	}
	if _, _, _, _, err := loadBootstrap(path, 4); err == nil {
		t.Error("K>N must fail")
	}
	if _, _, _, _, err := loadBootstrap(filepath.Join(t.TempDir(), "nope.json"), 2); err == nil {
		t.Error("missing bootstrap file must fail")
	}
}

// TestResolveAndBind_Discovery is the regression for the production bug: STHs
// arrive under the ledger's OPERATIONAL did:key, so the genesis witness set must
// be keyed by THAT, discovered from the peer's /v1/log-info — not by exchange_did.
func TestResolveAndBind_Discovery(t *testing.T) {
	path, exchangeDID := writeBootstrap(t, 5)
	nid, _, witnessDIDs, bootstrapDoc, err := loadBootstrap(path, 3)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	operatorDID := newDIDKey(t)
	srv := logInfoServer(t, map[string]any{
		"log_did":    exchangeDID,
		"ledger_did": operatorDID,
		"network_id": networkIDHexPrefix(nid),
	})

	feeds := []peers.PeerFeed{{LogDID: exchangeDID, BaseURL: srv.URL}}
	rps, err := resolvePeers(context.Background(), feeds, true, nid, nil, testHTTPClient(), testLogger())
	if err != nil {
		t.Fatalf("resolvePeers: %v", err)
	}
	if len(rps) != 1 || rps[0].originatorDID != operatorDID {
		t.Fatalf("originatorDID = %+v, want %q", rps, operatorDID)
	}

	sets, err := buildWitnessSets(rps, witnessDIDs, 3, nid,
		bootstrapDoc.GenesisSignaturePolicy.AllowedCosignSchemeTags)
	if err != nil {
		t.Fatalf("buildWitnessSets: %v", err)
	}
	// Keyed by the OPERATIONAL did:key — not exchange_did.
	if _, ok := sets[exchangeDID]; ok {
		t.Error("witness set must NOT be keyed by exchange_did")
	}
	set, ok := sets[operatorDID]
	if !ok || set == nil {
		t.Fatalf("no witness set for operational DID %q (got %d sets)", operatorDID, len(sets))
	}
	if set.Quorum() != 3 {
		t.Errorf("Quorum = %d, want 3", set.Quorum())
	}
}

// TestResolveAndBind_ExplicitPin proves the operator-pinned path: with discovery
// off, the DID configured in AUDITOR_PEERS is the originator verbatim.
func TestResolveAndBind_ExplicitPin(t *testing.T) {
	path, _ := writeBootstrap(t, 3)
	nid, _, witnessDIDs, bootstrapDoc, err := loadBootstrap(path, 2)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	pinned := newDIDKey(t)
	feeds := []peers.PeerFeed{{LogDID: pinned, BaseURL: "http://unused.invalid"}}

	rps, err := resolvePeers(context.Background(), feeds, false, nid, nil, testHTTPClient(), testLogger())
	if err != nil {
		t.Fatalf("resolvePeers: %v", err)
	}
	if rps[0].originatorDID != pinned {
		t.Fatalf("originatorDID = %q, want pinned %q", rps[0].originatorDID, pinned)
	}
	sets, err := buildWitnessSets(rps, witnessDIDs, 2, nid,
		bootstrapDoc.GenesisSignaturePolicy.AllowedCosignSchemeTags)
	if err != nil {
		t.Fatalf("buildWitnessSets: %v", err)
	}
	if _, ok := sets[pinned]; !ok {
		t.Errorf("no witness set for pinned DID %q", pinned)
	}
}

// TestResolvePeers_NetworkGuard refuses to bind trust when the peer advertises a
// different network — a misconfiguration guard (the real trust root is the
// witness cosignatures, but binding across networks is operator error).
func TestResolvePeers_NetworkGuard(t *testing.T) {
	path, exchangeDID := writeBootstrap(t, 3)
	nid, _, _, _, err := loadBootstrap(path, 2)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	srv := logInfoServer(t, map[string]any{
		"log_did":    exchangeDID,
		"ledger_did": newDIDKey(t),
		"network_id": "deadbeefdeadbeef", // wrong network
	})
	feeds := []peers.PeerFeed{{LogDID: exchangeDID, BaseURL: srv.URL}}
	if _, err := resolvePeers(context.Background(), feeds, true, nid, nil, testHTTPClient(), testLogger()); err == nil {
		t.Fatal("expected cross-network bind to fail")
	}
}

// TestResolvePeers_DiscoveryUnreachable fails closed (does not hang) when a peer
// never serves /v1/log-info; a short context bounds the retry loop.
func TestResolvePeers_DiscoveryUnreachable(t *testing.T) {
	path, exchangeDID := writeBootstrap(t, 3)
	nid, _, _, _, err := loadBootstrap(path, 2)
	if err != nil {
		t.Fatalf("loadBootstrap: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	feeds := []peers.PeerFeed{{LogDID: exchangeDID, BaseURL: "http://127.0.0.1:0"}}
	if _, err := resolvePeers(ctx, feeds, true, nid, nil, testHTTPClient(), testLogger()); err == nil {
		t.Fatal("expected discovery against an unreachable peer to fail")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// testHTTPClient is the *http.Client every resolvePeers caller in this file
// supplies. v1.27.1 made HTTPClient a required parameter of resolvePeers
// (mirror of the binary's hoisted peerHTTPClient); a plain 5s timeout is
// sufficient for the in-process httptest backends these tests run against.
func testHTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

// fakeEndpointResolver satisfies sdklog.EndpointResolver structurally.
type fakeEndpointResolver struct {
	url string
	err error
}

func (f fakeEndpointResolver) LedgerEndpoint(_ context.Context, _ string) (string, error) {
	return f.url, f.err
}

// TestParsePeers_BareDIDWeb: did:web-native entries (no =baseURL) parse with an
// empty BaseURL (URL resolved later); explicit pairs and a mix still work.
func TestParsePeers_BareDIDWeb(t *testing.T) {
	got := parsePeers("did:web:ledger.example.gov")
	if len(got) != 1 || got[0].LogDID != "did:web:ledger.example.gov" || got[0].BaseURL != "" {
		t.Fatalf("bare did:web parse = %+v", got)
	}
	got = parsePeers("did:web:a=https://a.example, did:web:b, not-a-did")
	if len(got) != 2 || got[0].BaseURL != "https://a.example" || got[1].LogDID != "did:web:b" || got[1].BaseURL != "" {
		t.Fatalf("mixed parse = %+v (non-DID bare token must be ignored)", got)
	}
}

// TestResolvePeers_DIDWebNative: a bare did:web peer resolves its base URL via
// the injected EndpointResolver (discover=false, so no network).
func TestResolvePeers_DIDWebNative(t *testing.T) {
	feeds := []peers.PeerFeed{{LogDID: "did:web:ledger.example.gov", BaseURL: ""}}
	res := fakeEndpointResolver{url: "https://ledger.example.gov"}
	rps, err := resolvePeers(context.Background(), feeds, false, cosign.NetworkID{}, res, testHTTPClient(), testLogger())
	if err != nil {
		t.Fatalf("resolvePeers: %v", err)
	}
	if len(rps) != 1 || rps[0].baseURL != "https://ledger.example.gov" {
		t.Fatalf("resolved base URL = %+v, want https://ledger.example.gov", rps)
	}
	if rps[0].originatorDID != "did:web:ledger.example.gov" {
		t.Fatalf("pinned originator = %q, want the did:web verbatim", rps[0].originatorDID)
	}
}

// TestResolvePeers_BareDIDNoResolver: a bare did:web with no resolver fails
// closed (verification must never silently proceed without an endpoint).
func TestResolvePeers_BareDIDNoResolver(t *testing.T) {
	feeds := []peers.PeerFeed{{LogDID: "did:web:x", BaseURL: ""}}
	if _, err := resolvePeers(context.Background(), feeds, false, cosign.NetworkID{}, nil, testHTTPClient(), testLogger()); err == nil {
		t.Fatal("expected failure when a bare did:web peer has no resolver")
	}
}
