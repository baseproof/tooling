package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
)

// govGather builds a gather pointed at srv, configured with one governance schema
// (signature_policy_chain) so the governance dispatch is exercised.
func govGather(t *testing.T, srv *httptest.Server, schema types.LogPosition) *StandaloneLedgerGather {
	t.Helper()
	client, err := clitools.NewLedgerClient(srv.URL, "did:web:gather.test")
	if err != nil {
		t.Fatalf("NewLedgerClient: %v", err)
	}
	var key [32]byte
	key[0] = 0x9
	g, err := NewStandaloneLedgerGather(client, srv.URL, srv.Client(),
		&network.BootstrapDocument{NetworkName: "gov-test"}, 2, 7, key,
		WithGovernanceSchemas(map[string]types.LogPosition{"signature_policy_chain": schema}))
	if err != nil {
		t.Fatalf("NewStandaloneLedgerGather: %v", err)
	}
	return g
}

// An unconfigured governance chain returns null without any HTTP call.
func TestGather_Governance_Unconfigured(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, _ := clitools.NewLedgerClient(srv.URL, "did:web:gather.test")
	g, err := NewStandaloneLedgerGather(client, srv.URL, srv.Client(),
		&network.BootstrapDocument{NetworkName: "x"}, 2, 7, [32]byte{}) // no WithGovernanceSchemas
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	got, err := g.FetchSection(context.Background(), "algorithm_policy_chain", 100)
	if err != nil || got != nil {
		t.Fatalf("unconfigured chain: got (%s, %v), want (null, nil)", got, err)
	}
	if hits != 0 {
		t.Errorf("unconfigured chain made %d HTTP calls, want 0", hits)
	}
}

// A configured chain with no on-log amendments discovers via the INDEX and returns
// a null section (no checkpoint fetched) — and never touches /scan.
func TestGather_Governance_EmptyDiscovery(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{"entries":[],"count":0}`))
	}))
	defer srv.Close()

	g := govGather(t, srv, types.LogPosition{LogDID: "did:web:net", Sequence: 2})
	got, err := g.FetchSection(context.Background(), "signature_policy_chain", 100)
	if err != nil {
		t.Fatalf("FetchSection: %v", err)
	}
	if got != nil {
		t.Errorf("empty chain must be null, got %s", got)
	}
	if len(paths) != 1 || !strings.HasPrefix(paths[0], "/v1/query/schema_ref/did:web:net:2") {
		t.Errorf("expected one index query to schema_ref, got %v", paths)
	}
	for _, p := range paths {
		if strings.Contains(p, "/scan") {
			t.Fatalf("gather fell back to a SCAN (%q) — forbidden", p)
		}
	}
}

// burn_attestation is gathered from GET /v1/burn (a fetched fact) and encoded with
// the proof's checkpoint tree size as as_of. (The horizon is pre-cached so the test
// exercises burnSection without a full cosigned-head mock.)
func TestGather_BurnSection(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"is_burned":true}`))
	}))
	defer srv.Close()

	g := newTestGather(t, srv, 7)
	g.horizon = &types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 42}} // skip the horizon fetch

	raw, err := g.FetchSection(context.Background(), "burn_attestation", 100)
	if err != nil {
		t.Fatalf("burn FetchSection: %v", err)
	}
	if gotPath != "/v1/burn" {
		t.Errorf("path = %q, want /v1/burn", gotPath)
	}
	var got struct {
		ThisNetwork struct {
			IsBurned bool   `json:"is_burned"`
			AsOf     uint64 `json:"as_of"`
		} `json:"this_network"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode burn_attestation %s: %v", raw, err)
	}
	if !got.ThisNetwork.IsBurned || got.ThisNetwork.AsOf != 42 {
		t.Errorf("burn_attestation = %+v, want is_burned=true as_of=42 (the checkpoint)", got.ThisNetwork)
	}
}

// A missing index (non-200 on the discovery query) fails the section loud
// (ErrIndexUnavailable) — never a scan.
func TestGather_Governance_FailLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no index", http.StatusNotFound)
	}))
	defer srv.Close()

	g := govGather(t, srv, types.LogPosition{LogDID: "did:web:net", Sequence: 2})
	_, err := g.FetchSection(context.Background(), "signature_policy_chain", 100)
	if !errors.Is(err, ErrIndexUnavailable) {
		t.Fatalf("want ErrIndexUnavailable on a missing index, got %v", err)
	}
}
