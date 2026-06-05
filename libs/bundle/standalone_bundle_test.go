package bundle

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
)

// fullVocab builds a generation vocabulary covering every governance chain + a
// signer-rotation schema, keyed by the SDK's canonical section names.
func fullVocab() (map[string]types.LogPosition, *types.LogPosition) {
	gov := make(map[string]types.LogPosition, len(protocol.GovernanceSectionNames))
	for i, name := range protocol.GovernanceSectionNames {
		gov[name] = types.LogPosition{LogDID: "did:web:wr-test-net", Sequence: uint64(10 + i)}
	}
	sr := types.LogPosition{LogDID: "did:web:wr-test-net", Sequence: 100}
	return gov, &sr
}

// bootstrapServer serves the doc's JCS-canonical bytes at /v1/network/bootstrap
// (mirroring the ledger's NewNetworkBootstrapHandler), returning the bytes + their
// SHA-256 (the trust-root pin).
func bootstrapServer(t *testing.T, doc *network.BootstrapDocument) (*httptest.Server, [32]byte) {
	t.Helper()
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/network/bootstrap" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(canonical)
			return
		}
		http.NotFound(w, r)
	}))
	return srv, sha256.Sum256(canonical)
}

func bundleClient(t *testing.T, srv *httptest.Server) *clitools.LedgerClient {
	t.Helper()
	c, err := clitools.NewLedgerClient(srv.URL, "did:web:gather.test")
	if err != nil {
		t.Fatalf("NewLedgerClient: %v", err)
	}
	return c
}

// A full-vocabulary bundle drives the gather: the bootstrap is fetched + hash-
// verified from the endpoint, and the governance + signer chains are
// self-configured from the bundle — no hand-passed options.
func TestNewBundleGather_SelfConfiguresFromBundle(t *testing.T) {
	doc := witnessTestBootstrap([]string{"did:key:zSinglePlaceholderForCanonicalBytes"})
	srv, hash := bootstrapServer(t, doc)
	defer srv.Close()

	gov, sr := fullVocab()
	b := &protocol.NetworkBundle{
		Endpoint:             srv.URL,
		TrustRoot:            protocol.GenesisTrustRoot{QuorumK: 2, BootstrapDocumentHash: hash},
		GovernanceSchemas:    gov,
		SignerRotationSchema: sr,
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("bundle should be valid: %v", err)
	}

	g, err := NewBundleGather(context.Background(), b, bundleClient(t, srv), srv.Client(), 7, [32]byte{0x9})
	if err != nil {
		t.Fatalf("NewBundleGather: %v", err)
	}
	// Vocabulary translated into the gather.
	if len(g.governance) != len(protocol.GovernanceSectionNames) {
		t.Errorf("governance vocabulary: got %d chains, want %d", len(g.governance), len(protocol.GovernanceSectionNames))
	}
	for name, want := range gov {
		if got := g.governance[name]; got != want {
			t.Errorf("governance[%q] = %+v, want %+v", name, got, want)
		}
	}
	if g.signerRotationSchema == nil || *g.signerRotationSchema != *sr {
		t.Errorf("signerRotationSchema = %+v, want %+v", g.signerRotationSchema, sr)
	}
	// Network identity came from the bundle: quorum + the fetched bootstrap.
	if g.quorumK != 2 {
		t.Errorf("quorumK = %d, want 2 (from bundle.TrustRoot)", g.quorumK)
	}
	if g.bootstrap == nil {
		t.Fatal("bootstrap was not fetched from the endpoint")
	}
	if g.baseURL != srv.URL {
		t.Errorf("baseURL = %q, want the bundle endpoint %q", g.baseURL, srv.URL)
	}
}

// A verify-only bundle (no Endpoint) cannot drive generation — rejected.
func TestNewBundleGather_VerifyOnlyBundleRejected(t *testing.T) {
	b := &protocol.NetworkBundle{TrustRoot: protocol.GenesisTrustRoot{QuorumK: 2}}
	_, err := NewBundleGather(context.Background(), b, nil, http.DefaultClient, 1, [32]byte{})
	if err == nil {
		t.Fatal("a verify-only bundle (no endpoint) must be rejected for generation")
	}
}

// The fetched bootstrap MUST hash to the bundle's pin; a mismatch means the
// endpoint serves a different network — fail closed before building anything.
func TestNewBundleGather_BootstrapHashMismatch(t *testing.T) {
	doc := witnessTestBootstrap([]string{"did:key:zSinglePlaceholderForCanonicalBytes"})
	srv, _ := bootstrapServer(t, doc)
	defer srv.Close()

	gov, sr := fullVocab()
	b := &protocol.NetworkBundle{
		Endpoint:             srv.URL,
		TrustRoot:            protocol.GenesisTrustRoot{QuorumK: 2, BootstrapDocumentHash: [32]byte{0xDE, 0xAD}}, // wrong pin
		GovernanceSchemas:    gov,
		SignerRotationSchema: sr,
	}
	_, err := NewBundleGather(context.Background(), b, bundleClient(t, srv), srv.Client(), 7, [32]byte{0x9})
	if err == nil {
		t.Fatal("a bootstrap whose hash != the bundle pin must be rejected")
	}
}

// An invalid bundle (unknown governance section) is rejected up front.
func TestNewBundleGather_InvalidBundleRejected(t *testing.T) {
	b := &protocol.NetworkBundle{
		Endpoint:          "http://x",
		GovernanceSchemas: map[string]types.LogPosition{"not_a_section": {LogDID: "did:x", Sequence: 1}},
	}
	_, err := NewBundleGather(context.Background(), b, nil, http.DefaultClient, 1, [32]byte{})
	if err == nil {
		t.Fatal("an invalid bundle (unknown governance section) must be rejected")
	}
}

// gatherOptionsFromBundle yields one option per configured surface; a genesis-only
// bundle yields none (a Part-I + receipt proof).
func TestGatherOptionsFromBundle_Count(t *testing.T) {
	gov, sr := fullVocab()
	if n := len(gatherOptionsFromBundle(&protocol.NetworkBundle{GovernanceSchemas: gov, SignerRotationSchema: sr})); n != 2 {
		t.Errorf("full vocab → %d options, want 2", n)
	}
	if n := len(gatherOptionsFromBundle(&protocol.NetworkBundle{})); n != 0 {
		t.Errorf("empty vocab → %d options, want 0", n)
	}
	if n := len(gatherOptionsFromBundle(&protocol.NetworkBundle{GovernanceSchemas: gov})); n != 1 {
		t.Errorf("governance-only → %d options, want 1", n)
	}
}
