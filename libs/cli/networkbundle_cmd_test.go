/*
FILE PATH: libs/cli/networkbundle_cmd_test.go

DESCRIPTION:

	Pins `network bundle get|verify|publish` end to end against a stub
	network built from the SAME hash-verified constitution fixture the
	other command tests use:

	  get      — fetches, runs the VERIFY DOOR, emits the envelope with the
	             serve headers; a server returning NON-CANONICAL bytes is
	             refused (discovery is never authority); the sole-destination
	             default resolves from the discovery envelope.
	  verify   — a canonical file bound to the network verifies; a file
	             naming another network refuses.
	  publish  — the two-step producer: step 1 publishes the anchor schema
	             entry and waits for its sequence (printing the exact
	             --anchor value); step 2 refuses an unverifiable manifest
	             (fail-closed: never signed), and publishes a verified one,
	             waiting for the ledger to sequence it.
*/
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkdid "github.com/baseproof/baseproof/did"

	"github.com/baseproof/tooling/libs/networkbundle"
)

// bundleNet is a stub ledger serving the constitution, the bundle route, and
// the submit/wait pair the publisher drives.
type bundleNet struct {
	url      string
	nidHex   string
	manifest []byte // body served at /v1/network/bundle?destination=...
	dest     string
	// captured publishes: canonical_hash → wire; sequence assigned in order.
	submitted int
}

func newBundleNet(t *testing.T) *bundleNet {
	t.Helper()
	doc := mustBootstrapDoc(t)
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	n := &bundleNet{nidHex: hex.EncodeToString(sum[:]), dest: "did:web:exchange.example"}

	// The served manifest: canonical bytes bound to this network's identity.
	m := &networkbundle.Manifest{
		Format:     networkbundle.ManifestFormat,
		Network:    networkbundle.NetworkRef{NetworkID: n.nidHex, Name: "stubnet"},
		Exchange:   n.dest,
		Operations: []networkbundle.Operation{},
	}
	n.manifest, err = m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(canonical)
	})
	mux.HandleFunc("/v1/network/bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("destination") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"exchanges": []string{n.dest}})
			return
		}
		w.Header().Set("X-Manifest-Published", "false")
		_, _ = w.Write(n.manifest)
	})
	mux.HandleFunc("POST /v1/entries", func(w http.ResponseWriter, r *http.Request) {
		wire, _ := readBody(r)
		h := sha256.Sum256(wire)
		n.submitted++
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"canonical_hash": hex.EncodeToString(h[:])})
	})
	mux.HandleFunc("GET /v1/entries-hash/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]uint64{"sequence_number": uint64(6 + n.submitted)})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	n.url = srv.URL
	return n
}

func readBody(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		k, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:k]...)
		if err != nil {
			return buf, nil
		}
	}
}

func bundleNetClientBundle(t *testing.T, n *bundleNet) string {
	t.Helper()
	return writeBundle(t, ClientBundle{
		NetworkID: n.nidHex, Endpoint: n.url, LogDID: "did:web:stub-log",
		QuorumK: 1, BootstrapHash: n.nidHex,
	})
}

func signerKeyFile(t *testing.T) string {
	t.Helper()
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signer.hex")
	if err := writeHexKey(path, scalarBytes(kp.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	return path
}

// ─── get ─────────────────────────────────────────────────────────────

func TestNetworkBundleGet_VerifiedEnvelopeWithSoleDestinationDefault(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	n := newBundleNet(t)
	cb := bundleNetClientBundle(t, n)

	out, err := captureStdout(t, func() error {
		return RunNetwork(context.Background(), []string{"bundle", "get", "--bundle", cb, "--output=json"})
	})
	if err != nil {
		t.Fatalf("get must verify and emit: %v", err)
	}
	var data NetworkBundleGetData
	if err := json.Unmarshal(decodeEnvelope(t, out, "network-bundle"), &data); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(n.manifest)
	if !data.Verified || data.Destination != n.dest ||
		data.ContentHash != hex.EncodeToString(wantHash[:]) || data.Published != "false" ||
		data.Manifest == nil || data.Manifest.Network.NetworkID != n.nidHex {
		t.Fatalf("data = %+v", data)
	}
}

func TestNetworkBundleGet_NonCanonicalServeRefused(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	n := newBundleNet(t)
	n.manifest = append(n.manifest, ' ') // reformatters need not apply
	cb := bundleNetClientBundle(t, n)

	err := RunNetwork(context.Background(), []string{"bundle", "get", "--bundle", cb})
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("a non-canonical serve must be refused, not displayed: %v", err)
	}
}

// ─── verify ──────────────────────────────────────────────────────────

func TestNetworkBundleVerify_File(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	n := newBundleNet(t)
	cb := bundleNetClientBundle(t, n)

	path := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(path, n.manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return RunNetwork(context.Background(), []string{"bundle", "verify", "--bundle", cb, "--output=json", path})
	})
	if err != nil {
		t.Fatalf("a canonical bound manifest must verify: %v", err)
	}
	var data NetworkBundleVerifyData
	if err := json.Unmarshal(decodeEnvelope(t, out, "network-bundle-verify"), &data); err != nil {
		t.Fatal(err)
	}
	if !data.Verified || data.NetworkID != n.nidHex || data.Exchange != n.dest {
		t.Fatalf("data = %+v", data)
	}

	// A manifest naming ANOTHER network refuses against this constitution.
	other := &networkbundle.Manifest{
		Format:     networkbundle.ManifestFormat,
		Network:    networkbundle.NetworkRef{NetworkID: strings.Repeat("ee", 32)},
		Exchange:   n.dest,
		Operations: []networkbundle.Operation{},
	}
	ob, _ := other.CanonicalBytes()
	opath := filepath.Join(t.TempDir(), "other.json")
	_ = os.WriteFile(opath, ob, 0o600)
	if err := RunNetwork(context.Background(), []string{"bundle", "verify", "--bundle", cb, opath}); err == nil {
		t.Fatal("a manifest for another network must refuse")
	}
}

// ─── publish: the two-step producer ──────────────────────────────────

func TestNetworkBundlePublish_TwoStep(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	n := newBundleNet(t)
	cb := bundleNetClientBundle(t, n)
	key := signerKeyFile(t)

	// Step 1: the anchor entry — submitted, sequenced, and the exact
	// --anchor value emitted.
	out, err := captureStdout(t, func() error {
		return RunNetwork(context.Background(), []string{
			"bundle", "publish", "--bundle", cb, "--publish-anchor",
			"--signer-key", key, "--output=json",
		})
	})
	if err != nil {
		t.Fatalf("step 1: %v", err)
	}
	var step1 NetworkBundlePublishData
	if err := json.Unmarshal(decodeEnvelope(t, out, "network-bundle-publish"), &step1); err != nil {
		t.Fatal(err)
	}
	if step1.Step != "anchor" || step1.Sequence == 0 || step1.Anchor != fmt.Sprintf("did:web:stub-log@%d", step1.Sequence) {
		t.Fatalf("step1 = %+v", step1)
	}

	// Step 2 FAIL-CLOSED: an unverifiable manifest is never signed.
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, append(append([]byte{}, n.manifest...), ' '), 0o600)
	err = RunNetwork(context.Background(), []string{
		"bundle", "publish", "--bundle", cb,
		"--manifest", bad, "--anchor", step1.Anchor, "--signer-key", key,
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to publish") {
		t.Fatalf("an unverifiable manifest must never be signed: %v", err)
	}

	// Step 2: the verified manifest publishes and sequences.
	good := filepath.Join(t.TempDir(), "m.json")
	_ = os.WriteFile(good, n.manifest, 0o600)
	out, err = captureStdout(t, func() error {
		return RunNetwork(context.Background(), []string{
			"bundle", "publish", "--bundle", cb,
			"--manifest", good, "--anchor", step1.Anchor, "--signer-key", key, "--output=json",
		})
	})
	if err != nil {
		t.Fatalf("step 2: %v", err)
	}
	var step2 NetworkBundlePublishData
	if err := json.Unmarshal(decodeEnvelope(t, out, "network-bundle-publish"), &step2); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(n.manifest)
	if step2.Step != "manifest" || step2.Sequence <= step1.Sequence ||
		step2.ContentHash != hex.EncodeToString(wantHash[:]) || step2.Exchange != n.dest {
		t.Fatalf("step2 = %+v", step2)
	}
}
