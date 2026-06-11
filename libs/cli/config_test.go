package cli

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestConfigStore covers the gcloud-style store + the resolveBundle precedence:
// an explicit --bundle wins, then --network, then the active network, then a
// clear error.
func TestConfigStore(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	nidA := strings.Repeat("ab", 32)

	if err := saveNetwork("alpha", &ClientBundle{NetworkID: nidA, Endpoint: "https://a", LogDID: "did:web:a", QuorumK: 1}); err != nil {
		t.Fatalf("saveNetwork alpha: %v", err)
	}
	if err := saveNetwork("beta", &ClientBundle{NetworkID: strings.Repeat("cd", 32), Endpoint: "https://b", QuorumK: 1}); err != nil {
		t.Fatalf("saveNetwork beta: %v", err)
	}

	if names, _ := listNetworks(); len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("listNetworks = %v, want [alpha beta]", names)
	}

	// No active network ⇒ resolveBundle with no flags errors clearly.
	if _, err := resolveBundle("", ""); err == nil {
		t.Error("resolveBundle with no active network should error")
	}

	if err := setActiveNetwork("alpha"); err != nil {
		t.Fatalf("setActiveNetwork: %v", err)
	}
	if cfg, _ := loadConfig(); cfg.ActiveNetwork != "alpha" {
		t.Fatalf("active = %q, want alpha", cfg.ActiveNetwork)
	}

	// precedence: active …
	if b, err := resolveBundle("", ""); err != nil || b.NetworkID != nidA {
		t.Fatalf("active resolve: %v / %s", err, mustID(b))
	}
	// … --network overrides active …
	if b, err := resolveBundle("", "beta"); err != nil || b.Endpoint != "https://b" {
		t.Fatalf("--network resolve: %v / %s", err, mustEndpoint(b))
	}
	// … explicit --bundle file wins over everything.
	path := writeBundle(t, ClientBundle{NetworkID: nidA, Endpoint: "https://file"})
	if b, err := resolveBundle(path, "beta"); err != nil || b.Endpoint != "https://file" {
		t.Fatalf("--bundle should win: %v / %s", err, mustEndpoint(b))
	}

	if err := setActiveNetwork("missing"); err == nil {
		t.Error("setActiveNetwork on a missing network should error")
	}
}

func mustID(b *ClientBundle) string {
	if b == nil {
		return "<nil>"
	}
	return b.NetworkID
}
func mustEndpoint(b *ClientBundle) string {
	if b == nil {
		return "<nil>"
	}
	return b.Endpoint
}

// TestNetworkAuthoring proves bundle authoring from a live ledger: it builds a
// valid bundle from the introspection surface, CONFIRMS the served bootstrap
// hashes to the network id (Zero-Trust), captures the federation, and fails
// closed when a ledger lies about its identity.
func TestNetworkAuthoring(t *testing.T) {
	ctx := context.Background()
	peer := newFakeNet(t, nil, false)
	root := newFakeNet(t, []wireLogNode{{NetworkID: peer.nid, AdmissionURL: peer.url}}, false)

	b, err := authorBundleFromLedger(ctx, root.url, "", "did:web:test-log", 5*time.Second)
	if err != nil {
		t.Fatalf("authorBundleFromLedger: %v", err)
	}
	if b.NetworkID != root.nid || b.Endpoint != root.url || b.BootstrapHash != root.nid {
		t.Errorf("authored bundle: id=%s ep=%s hash=%s (want id==hash==%s)", b.NetworkID, b.Endpoint, b.BootstrapHash, root.nid)
	}
	// QuorumK comes from the hash-verified constitution (GenesisQuorumK=1 in
	// mustBootstrapDoc), never from an operator flag.
	if b.LogDID != "did:web:test-log" || b.QuorumK != 1 {
		t.Errorf("log_did=%q quorum=%d, want did:web:test-log / 1 (constitutional)", b.LogDID, b.QuorumK)
	}
	if len(b.Federation) != 1 || b.Federation[0].NetworkID != peer.nid {
		t.Errorf("federation not captured: %+v", b.Federation)
	}
	if err := b.validate(); err != nil {
		t.Errorf("authored bundle invalid: %v", err)
	}

	// ZT: a ledger whose served bootstrap does NOT hash to its claimed id ⇒ fail closed.
	bad := newFakeNet(t, nil, true) // identity serves ff…ff; bootstrap is the real doc
	if _, err := authorBundleFromLedger(ctx, bad.url, "", "did:web:x", 5*time.Second); err == nil {
		t.Error("authoring from a ledger whose bootstrap does not hash to its id must fail closed")
	}
}
