package cli

// live_http_test.go — the platform e2e's RUNNABLE tier (no Postgres, no Docker).
//
// It stands up an httptest ledger that serves the v2 proof gather's read endpoints
// from a REAL-crypto fixture (the same artifacts realproof_test.go verifies offline),
// then drives the ACTUAL command surface — RunProof's live gather over real HTTP
// (fetchBootstrap → ledgerReaderFor/clitools → NewBundleGather → BuildStandalone) —
// and verifies the emitted proof FULLY OFFLINE (RunVerify, zero network). That is
// the v2 standalone-proof property end to end: a proof gathered from a live ledger
// is self-contained and verifiable with no ledger present. A tampered proof is
// rejected fail-closed.
//
// This closes the "proof live gather over real HTTP" gap with evidence that runs in
// any environment. The real WRITE pipeline (submit/load → sequencer → builder →
// checkpoint → cosign) is the Postgres-backed tier that runs in CI.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
	"github.com/baseproof/tooling/libs/networkbundle"
)

// startFixtureServer serves the gather's read endpoints from the fixture's real
// crypto, in the exact wire shapes clitools + the SDK fetchers consume. Genesis-only,
// so beyond Part-I the gather hits only /v1/receipt/proof (→ null, not-asserted) and
// /v1/burn (→ a real not-burned attestation).
func (fx *realFixture) startFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// GET /v1/network/bootstrap — the JCS-canonical bytes that hash to the network id.
	mux.HandleFunc("GET /v1/network/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(fx.canonical)
	})

	// GET /v1/tree/horizon — the witness-cosigned head (canonical wire-hex shape).
	mux.HandleFunc("GET /v1/tree/horizon", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, types.FromCosignedTreeHead(fx.head))
	})

	// GET /v1/entries/{seq}/raw — the SDK HTTPEntryFetcher contract: raw wire bytes
	// + X-Sequence (must equal the requested seq) + X-Log-Time (RFC-3339Nano).
	mux.HandleFunc("GET /v1/entries/{seq}/raw", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Sequence", r.PathValue("seq"))
		w.Header().Set("X-Log-Time", fx.logTime.Format(time.RFC3339Nano))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(fx.entryBytes)
	})

	// GET /v1/tree/inclusion/{seq}?tree_size=N — RFC-6962 co-path (clitools shape).
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", func(w http.ResponseWriter, _ *http.Request) {
		hashes := make([]string, len(fx.inc.Siblings))
		for i, s := range fx.inc.Siblings {
			hashes[i] = hex.EncodeToString(s[:])
		}
		writeJSON(w, map[string]any{
			"leaf_index": fx.inc.LeafPosition, "tree_size": fx.inc.TreeSize, "hashes": hashes,
		})
	})

	// GET /v1/smt/proof/{key}?smt_root=hex — a REAL Jellyfish proof for the requested
	// key against the cosigned SMT root (fx.smtRoot == fx.head.SMTRoot): membership
	// for a present key (the target entry), non-membership for any other key (the
	// random keys VerifyHorizon samples). Generated live from the fixture's tree.
	mux.HandleFunc("GET /v1/smt/proof/{key}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		raw, err := hex.DecodeString(r.PathValue("key"))
		if err != nil || len(raw) != 32 {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		var key [32]byte
		copy(key[:], raw)
		typ := "membership"
		p, err := fx.smtTree.GenerateMembershipProof(ctx, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if p == nil { // absent key ⇒ non-membership
			typ = "non_membership"
			if p, err = fx.smtTree.GenerateNonMembershipProof(ctx, key); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, map[string]any{"type": typ, "proof": p})
	})

	// GET /v1/receipt/proof/{seq} — genesis network asserts no receipt leg ⇒ null
	// (the gather leaves receipt_proof not-asserted; the Part-I proof still verifies).
	mux.HandleFunc("GET /v1/receipt/proof/{seq}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"receipt_proof": nil})
	})

	// GET /v1/burn — equivocation status (a fetched fact). Not burned.
	mux.HandleFunc("GET /v1/burn", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"is_burned": false})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// TestProof_LiveGatherOverHTTP drives RunProof's live gather over real HTTP, then
// verifies the emitted proof fully offline (the standalone property), pins it to the
// network id, and rejects a tampered copy.
func TestProof_LiveGatherOverHTTP(t *testing.T) {
	ctx := context.Background()
	fx := buildRealFixture(t, 3, 2) // 3 witnesses, quorum 2
	srv := fx.startFixtureServer(t)

	bundlePath := writeBundle(t, ClientBundle{
		NetworkID:     hex.EncodeToString(fx.nid[:]),
		Endpoint:      srv.URL,
		LogDID:        fx.networkDID,
		QuorumK:       fx.k,
		BootstrapHash: hex.EncodeToString(fx.bootstrapHash[:]),
	})
	proofPath := filepath.Join(t.TempDir(), "live.proof")

	// LIVE GATHER over HTTP via the real command surface (RunProof self-verifies the
	// gathered proof offline before it ever writes — fail-closed at the source).
	if err := RunProof(ctx, []string{
		"--bundle", bundlePath,
		"--seq", strconv.FormatUint(fx.seq, 10),
		"--smt-key", hex.EncodeToString(fx.smtKey[:]),
		"--out", proofPath,
	}); err != nil {
		t.Fatalf("RunProof live gather over HTTP failed: %v", err)
	}

	// OFFLINE VERIFY (zero network) — the v2 standalone-proof property.
	proof, res, err := verifyProofFile(ctx, proofPath, "")
	if err != nil {
		t.Fatalf("offline verify REJECTED a live-gathered proof: %v", err)
	}
	if !res.Valid {
		t.Fatalf("live-gathered proof not Valid; verified=%v notAsserted=%v",
			res.Coverage.Verified, res.Coverage.NotAsserted)
	}
	if proof.Format != sdkbundle.FormatV2 {
		t.Fatalf("format=%q, want v2", proof.Format)
	}
	if proof.NetworkID != fx.nid {
		t.Fatalf("proof network id %x != fixture %x", proof.NetworkID[:8], fx.nid[:8])
	}
	t.Logf("live proof verified OFFLINE: sections=%v quorum=%d-of-%d tree_size=%d",
		res.Coverage.Verified, res.WitnessQuorum.Have, res.WitnessQuorum.Need, res.TreeSize)

	// Pin to the bundle's network id (the ZT anchor) — still verifies.
	if _, _, err := verifyProofFile(ctx, proofPath, hex.EncodeToString(fx.nid[:])); err != nil {
		t.Fatalf("verify with correct --pin failed: %v", err)
	}

	// TAMPER: flip an entry byte in the emitted file ⇒ fail-closed.
	raw, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("read proof: %v", err)
	}
	bad, err := sdkbundle.DecodeStandalone(raw)
	if err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	bad.Entry.WireBytes[0] ^= 0xFF
	badRaw, err := sdkbundle.EncodeStandalone(bad)
	if err != nil {
		t.Fatalf("re-encode tampered: %v", err)
	}
	badPath := filepath.Join(t.TempDir(), "tampered.proof")
	if err := os.WriteFile(badPath, badRaw, 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, _, err := verifyProofFile(ctx, badPath, ""); err == nil {
		t.Fatal("a tampered live proof verified — fail-closed broken")
	}
}

// TestInfoVerify_HorizonOverHTTP exercises the verify-on-fetch core of `info
// --verify` against the real cosigned horizon: it builds the network's witness set
// the same way info does (networkbundle.Build) and runs clitools.VerifyHorizon over
// real HTTP — K-of-N cosignature recompute on /v1/tree/horizon plus sampled
// SMT proofs (non-membership for random keys) bound to the witnessed smt_root.
func TestInfoVerify_HorizonOverHTTP(t *testing.T) {
	ctx := context.Background()
	fx := buildRealFixture(t, 3, 2)
	srv := fx.startFixtureServer(t)

	// The witness set, built exactly as info.go does (info.go:199).
	nb, err := networkbundle.Build(fx.bdoc, srv.URL, fx.k, networkbundle.Vocabulary{})
	if err != nil {
		t.Fatalf("networkbundle.Build: %v", err)
	}

	hc := &http.Client{Timeout: 5 * time.Second}
	hr, err := clitools.VerifyHorizon(ctx, srv.URL, nb.Witnesses, 6, hc)
	if err != nil {
		t.Fatalf("VerifyHorizon over real HTTP failed: %v", err)
	}
	if hr.ValidCosigs < hr.Quorum {
		t.Fatalf("cosigs %d < quorum %d", hr.ValidCosigs, hr.Quorum)
	}
	if hr.ProofsOK != hr.ProofsTotal || hr.ProofsTotal != 6 {
		t.Fatalf("sampled proofs %d/%d, want 6/6", hr.ProofsOK, hr.ProofsTotal)
	}
	if hr.SMTRoot != fx.smtRoot || hr.TreeSize != fx.head.TreeSize {
		t.Fatalf("horizon anchor mismatch: smt_root/%x tree_size/%d", hr.SMTRoot[:8], hr.TreeSize)
	}
	t.Logf("horizon verified OVER HTTP: %d-of-%d cosigs, %d/%d sampled proofs against witnessed smt_root, tree_size=%d",
		hr.ValidCosigs, hr.Quorum, hr.ProofsOK, hr.ProofsTotal, hr.TreeSize)
}
