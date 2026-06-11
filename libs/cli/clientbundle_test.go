package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/baseproof/tooling/libs/loadgen"
)

func writeBundle(t *testing.T, b ClientBundle) string {
	t.Helper()
	b.Format = ClientBundleFormat
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func TestClientBundle_LoadValidate(t *testing.T) {
	nid := strings.Repeat("ab", 32) // 64 hex
	path := writeBundle(t, ClientBundle{
		NetworkID: nid, Endpoint: "https://ledger:8443", LogDID: "did:web:x", QuorumK: 2,
	})
	b, err := LoadClientBundle(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if b.Endpoint != "https://ledger:8443" || b.QuorumK != 2 {
		t.Fatalf("parsed bundle wrong: %+v", b)
	}
	if id, err := b.NetworkID32(); err != nil || hex.EncodeToString(id[:]) != nid {
		t.Fatalf("NetworkID32 = %x err %v, want %s", id, err, nid)
	}
	if got, err := b.RequireLogDID(); err != nil || got != "did:web:x" {
		t.Fatalf("RequireLogDID = %q err %v", got, err)
	}

	// Bad format and missing endpoint are rejected at load.
	bad := writeBundle(t, ClientBundle{Endpoint: "https://x"})
	if err := overwriteFormat(t, bad, "wrong/v9"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientBundle(bad); err == nil {
		t.Error("expected format-mismatch rejection")
	}
	noEndpoint := writeBundle(t, ClientBundle{NetworkID: nid})
	if _, err := LoadClientBundle(noEndpoint); err == nil {
		t.Error("expected missing-endpoint rejection")
	}

	// A short network_id fails the proof accessor (not load).
	shortID := writeBundle(t, ClientBundle{NetworkID: "abcd", Endpoint: "https://x"})
	lb, err := LoadClientBundle(shortID)
	if err != nil {
		t.Fatalf("load short-id bundle: %v", err)
	}
	if _, err := lb.NetworkID32(); err == nil {
		t.Error("expected NetworkID32 to reject a short id")
	}
}

func overwriteFormat(t *testing.T, path, format string) error {
	t.Helper()
	var b ClientBundle
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &b)
	b.Format = format
	out, _ := json.Marshal(b)
	return os.WriteFile(path, out, 0o644)
}

// TestClientBundle_MessagesAndFederation covers the self-describing sections: the
// accepted-message set is validated against the foundational catalog, schemas +
// federation parse, an unconstrained bundle accepts anything, and bad inputs are
// rejected at load.
func TestClientBundle_MessagesAndFederation(t *testing.T) {
	nid := strings.Repeat("ab", 32)
	fed := strings.Repeat("cd", 32)

	path := writeBundle(t, ClientBundle{
		NetworkID: nid, Endpoint: "https://l:8443", LogDID: "did:web:x", QuorumK: 2,
		Messages:   []string{"entity", "amendment", "delegation", "schema"},
		Schemas:    map[string]uint64{"signature_policy": 42},
		Federation: []FederatedNet{{Name: "peer", NetworkID: fed, Endpoint: "https://p:8443"}},
	})
	b, err := LoadClientBundle(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !b.AcceptsMessage("entity") || b.AcceptsMessage("mirror") {
		t.Errorf("AcceptsMessage wrong: entity=%v mirror=%v", b.AcceptsMessage("entity"), b.AcceptsMessage("mirror"))
	}
	if b.Schemas["signature_policy"] != 42 || len(b.Federation) != 1 || b.Federation[0].Name != "peer" {
		t.Errorf("messages/schemas/federation not parsed: %+v", b)
	}

	// No messages list ⇒ unconstrained (accepts anything).
	open := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: "https://x"})
	ob, _ := LoadClientBundle(open)
	if !ob.AcceptsMessage("anything") {
		t.Error("a bundle with no messages list must not constrain")
	}

	// An unknown message name is rejected at load (catalog-validated).
	badMsg := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: "https://x", Messages: []string{"entity", "not-a-real-structure"}})
	if _, err := LoadClientBundle(badMsg); err == nil {
		t.Error("expected unknown-message rejection")
	}

	// A malformed federation network_id is rejected at load.
	badFed := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: "https://x", Federation: []FederatedNet{{Name: "p", NetworkID: "xyz"}}})
	if _, err := LoadClientBundle(badFed); err == nil {
		t.Error("expected bad-federation-id rejection")
	}
}

// TestClientBundle_RejectsUnknownField pins the strict-decode clean break: a
// bundle carrying a field this binary does not recognize is REJECTED, not
// silently dropped (the write_endpoint-class hazard — a pre-field binary would
// drop write_endpoint and treat a gated network as ungated). The bundle's open
// vocabulary (the Schemas map's section names, Messages, Federation) is
// value-space and stays accepted — strict decode only rejects unknown STRUCT
// keys, so the network bundle's expressiveness is maintained.
func TestClientBundle_RejectsUnknownField(t *testing.T) {
	nid := strings.Repeat("ab", 32)

	// A valid bundle with an injected unknown top-level key is rejected.
	valid := ClientBundle{Format: ClientBundleFormat, NetworkID: nid, Endpoint: "https://x", LogDID: "did:web:x", QuorumK: 2}
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["surprise_field"] = json.RawMessage(`"unexpected"`)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientBundle(path); err == nil {
		t.Fatal("LoadClientBundle accepted a bundle carrying an unknown field")
	}

	// The open vocabulary is maintained: an arbitrary Schemas section name is
	// value-space (a map key), not an unknown struct key, and still loads.
	okPath := writeBundle(t, ClientBundle{
		NetworkID: nid, Endpoint: "https://x", QuorumK: 2,
		Schemas: map[string]uint64{"any_section_name": 7},
	})
	if _, err := LoadClientBundle(okPath); err != nil {
		t.Fatalf("a bundle using the open Schemas vocabulary must still load: %v", err)
	}
}

// fakeLedger is a minimal in-memory ledger: accept entry → assign monotonic
// sequence → answer hash→sequence lookups.
func fakeLedger() *httptest.Server {
	var (
		mu     sync.Mutex
		seq    uint64
		byHash = map[string]uint64{}
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/admission/difficulty", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]uint32{"difficulty": 0})
	})
	mux.HandleFunc("/v1/entries", func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		buf := make([]byte, 1<<16)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		sum := sha256.Sum256(body)
		h := hex.EncodeToString(sum[:])
		mu.Lock()
		seq++
		byHash[h] = seq
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"canonical_hash": h})
	})
	mux.HandleFunc("/v1/entries-hash/", func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimPrefix(r.URL.Path, "/v1/entries-hash/")
		mu.Lock()
		s, ok := byHash[h]
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]string{"state": "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]uint64{"sequence_number": s})
	})
	return httptest.NewServer(mux)
}

// TestRunLoad_EndToEnd drives the whole `load` command — client bundle → loadgen
// engine → streamed JSONL oracle — against a fake ledger, asserting the run
// completes and the oracle is a header line plus one leaf per root.
func TestRunLoad_EndToEnd(t *testing.T) {
	srv := fakeLedger()
	defer srv.Close()

	manifest := filepath.Join(t.TempDir(), "oracle.jsonl")
	bundlePath := writeBundle(t, ClientBundle{
		NetworkID: strings.Repeat("cd", 32), Endpoint: srv.URL, LogDID: "did:web:baseproof:test", QuorumK: 2,
	})

	err := RunLoad(context.Background(), []string{
		"--bundle", bundlePath,
		"-n", "120",
		"--amend-ratio", "0.5",
		"--workers", "1",
		"--amend-window", "8",
		"--seed", "1",
		"--token", "test-credit", // Mode A: no PoW
		"--manifest", manifest,
		"--timeout", "5s",
	})
	if err != nil {
		t.Fatalf("RunLoad: %v", err)
	}

	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("manifest has %d lines, want header + leaves", len(lines))
	}
	var hdr loadgen.OracleHeader
	if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil || hdr.Format != loadgen.OracleFormat {
		t.Fatalf("header %q: %v (format=%q)", lines[0], err, hdr.Format)
	}
	if hdr.N != 120 {
		t.Errorf("header N=%d, want 120", hdr.N)
	}
	// Every leaf line parses and carries a 64-hex key.
	for i, ln := range lines[1:] {
		var leaf map[string]any
		if err := json.Unmarshal([]byte(ln), &leaf); err != nil {
			t.Fatalf("leaf %d %q: %v", i, ln, err)
		}
		if k, _ := leaf["key"].(string); len(k) != 64 {
			t.Errorf("leaf %d key %q not 64 hex", i, k)
		}
	}
}
