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
	"time"
)

// fakeNet is a realistic single-network ledger fixture: it serves the whole
// /v1/network/* introspection surface (bootstrap, identity, witnesses, auditors,
// mirrors, peers), a horizon, and admission difficulty — plus a separate auditor
// service with /healthz + /v1/log-info. Its network_id is SHA-256(canonical
// bootstrap), exactly as the real ledger derives it, so `info`'s recompute holds.
type fakeNet struct {
	url string // ledger base URL
	nid string // network_id (= sha256(canonical bootstrap)), 64-hex
}

func newFakeNet(t *testing.T, siblings []wireLogNode, tamperID bool) *fakeNet {
	t.Helper()
	doc := mustBootstrapDoc(t)
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	sum := sha256.Sum256(canonical)
	nid := hex.EncodeToString(sum[:])
	servedID := nid
	if tamperID {
		servedID = strings.Repeat("ff", 32) // lies about its own identity
	}

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	// Auditor service.
	amux := http.NewServeMux()
	amux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	amux.HandleFunc("/v1/log-info", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]uint64{"tree_size": 100}) // caught up to the ledger horizon
	})
	aud := httptest.NewServer(amux)

	// Ledger service.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(canonical)
	})
	mux.HandleFunc("/v1/network/identity", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, wireIdentity{NetworkID: servedID, NetworkDID: "did:baseproof:network:" + nid[:8]})
	})
	mux.HandleFunc("/v1/network/witnesses/current", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, wireWitnessSet{SetHash: strings.Repeat("7f", 32), Keys: []wireWitnessKey{{ID: strings.Repeat("11", 32)}}})
	})
	mux.HandleFunc("/v1/network/auditors", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, wireAuditors{Auditors: []wireAuditorEntry{{AuditorDID: "did:key:zAuditor", FindingsURL: aud.URL + "/v1/gossip"}}})
	})
	mux.HandleFunc("/v1/network/mirrors", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, wireMirrors{Mirrors: []wireMirrorEntry{{URL: "https://cdn.example"}}})
	})
	mux.HandleFunc("/v1/network/peers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, wireFederation{Siblings: siblings})
	})
	mux.HandleFunc("/v1/tree/horizon", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, wireHorizon{TreeSize: 100, SMTRoot: strings.Repeat("ab", 32)})
	})
	mux.HandleFunc("/v1/admission/difficulty", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]uint64{"difficulty": 20})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(func() { srv.Close(); aud.Close() })
	return &fakeNet{url: srv.URL, nid: nid}
}

// TestInfo_FederationRealistic drives `info` against a realistic federation: a
// root network citing two peer networks, each serving its full surface + a live
// auditor. It asserts aggregation, the identity ZT recompute, the verified peer
// walk, the auditor live+in-sync rollup, and that a peer LYING about its id is
// caught (IDMatches=false).
func TestInfo_FederationRealistic(t *testing.T) {
	ctx := context.Background()
	httpClient := &http.Client{Timeout: 5 * time.Second}

	b := newFakeNet(t, nil, false)
	c := newFakeNet(t, nil, false)
	root := newFakeNet(t, []wireLogNode{
		{NetworkID: b.nid, AdmissionURL: b.url},
		{NetworkID: c.nid, AdmissionURL: c.url},
	}, false)

	bundlePath := writeBundle(t, ClientBundle{
		NetworkID: root.nid, Endpoint: root.url, LogDID: "did:web:root", QuorumK: 1,
		BootstrapHash: root.nid, Messages: []string{"entity", "amendment"},
	})
	bb, err := LoadClientBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}

	// --federation: aggregate the surface, then reach + verify both peers.
	n, err := gatherNetwork(ctx, bb, httpClient, false, true, 2)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if !n.IdentityOK {
		t.Error("identity recompute failed on a consistent network (ZT gate)")
	}
	if n.Horizon.TreeSize != 100 || len(n.Auditors.Auditors) != 1 || len(n.Witnesses.Keys) != 1 {
		t.Errorf("aggregation incomplete: horizon=%d auditors=%d witnesses=%d", n.Horizon.TreeSize, len(n.Auditors.Auditors), len(n.Witnesses.Keys))
	}
	if len(n.Peers) != 2 {
		t.Fatalf("walked %d peers, want 2", len(n.Peers))
	}
	for _, p := range n.Peers {
		if !p.Reached || !p.IDMatches {
			t.Errorf("peer %s: reached=%v idMatches=%v (want both true)", short(p.NetworkID), p.Reached, p.IDMatches)
		}
	}

	// --verify: identity hard-passes; the auditor liveness + in-sync rollup runs.
	nv, err := gatherNetwork(ctx, bb, httpClient, true, false, 1)
	if err != nil {
		t.Fatalf("gather --verify: %v", err)
	}
	if !nv.IdentityOK {
		t.Error("identity not OK under --verify")
	}
	if len(nv.AuditorHP) != 1 || !nv.AuditorHP[0].Live || !nv.AuditorHP[0].InSync {
		t.Errorf("auditor rollup = %+v, want exactly one live + in-sync", nv.AuditorHP)
	}

	// TAMPER: a cited peer that serves the WRONG network id must be caught.
	bad := newFakeNet(t, nil, true) // serves network_id = ff…ff, not its real id
	root2 := newFakeNet(t, []wireLogNode{{NetworkID: bad.nid, AdmissionURL: bad.url}}, false)
	bundle2 := writeBundle(t, ClientBundle{NetworkID: root2.nid, Endpoint: root2.url, LogDID: "did:web:root2", QuorumK: 1, BootstrapHash: root2.nid})
	bb2, _ := LoadClientBundle(bundle2)
	n2, err := gatherNetwork(ctx, bb2, httpClient, false, true, 1)
	if err != nil {
		t.Fatalf("gather tamper: %v", err)
	}
	if len(n2.Peers) != 1 || n2.Peers[0].Reached != true || n2.Peers[0].IDMatches {
		t.Errorf("a peer lying about its id was not caught: %+v (want Reached=true, IDMatches=false)", n2.Peers)
	}
}
