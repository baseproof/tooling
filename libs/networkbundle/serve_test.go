/*
FILE PATH: libs/networkbundle/serve_test.go

DESCRIPTION:

	Pins the GET /v1/network/bundle handler's contract end to end against a
	stub ledger serving REAL signed entry wire bytes:

	  - construction refuses incomplete wiring (no Compile/Destinations;
	    an anchor without a ledger URL; a malformed anchor);
	  - the bare GET returns the discovery envelope; an unknown destination
	    is 404 (ErrUnknownDestination from the injected composer);
	  - UNPUBLISHED mode serves the compiled projection byte-exactly with
	    X-Manifest-Published:false, a sha256 ETag, and If-None-Match → 304;
	  - PUBLISHED resolution walks candidates newest-first and serves the
	    first one that strict-decodes, names the destination, AND
	    re-canonicalizes to its own bytes — a non-canonical payload and a
	    wrong-exchange manifest are both skipped (each pinned here);
	  - DRIFT (published ≠ enforced) is served with
	    X-Manifest-Enforced-Match:false — declared truth wins the serve,
	    the mismatch is surfaced, never hidden;
	  - a failed resolution falls back loudly: X-Manifest-Resolve-Error +
	    the compiled projection.
*/
package networkbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
)

const (
	testDest   = "did:web:exchange.example"
	testAnchor = "did:web:ledger.example@7"
)

// entryWire wraps payload in a REAL signed, serialized entry — exactly what
// /v1/entries/{seq}/raw returns — so fetchEntryPayload exercises true
// envelope deserialization, not a shortcut.
func entryWire(t *testing.T, payload []byte) []byte {
	t.Helper()
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	e, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:ledger.example", SignerDID: kp.DID, Payload: payload,
		EventTime: time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := envelope.NewUnsignedEntry(e.Header, e.DomainPayload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(u))
	sig, err := signatures.SignEntry(digest, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	u.Signatures = []envelope.Signature{{SignerDID: kp.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	wire, err := envelope.Serialize(u)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// stubLedger serves schema_ref (candidate sequences, as configured) and the
// raw entries backing them.
func stubLedger(t *testing.T, seqs []uint64, raw map[uint64][]byte, schemaRefStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/query/schema_ref/", func(w http.ResponseWriter, _ *http.Request) {
		if schemaRefStatus != http.StatusOK {
			w.WriteHeader(schemaRefStatus)
			return
		}
		type ent struct {
			SequenceNumber uint64 `json:"sequence_number"`
		}
		out := struct {
			Entries []ent `json:"entries"`
		}{}
		for _, s := range seqs {
			out.Entries = append(out.Entries, ent{s})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/entries/", func(w http.ResponseWriter, r *http.Request) {
		var seq uint64
		if _, err := fmt.Sscanf(r.URL.Path, "/v1/entries/%d/raw", &seq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		wire, ok := raw[seq]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(wire)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// compiledManifest is the enforced projection the test composer serves.
func compiledManifest() *Manifest {
	m := refManifest()
	m.Exchange = testDest
	return m
}

func testServeConfig(t *testing.T, anchor, ledgerURL string) ServeConfig {
	t.Helper()
	return ServeConfig{
		Compile: func(dest string) (*Manifest, error) {
			if dest != testDest {
				return nil, fmt.Errorf("%w: %s", ErrUnknownDestination, dest)
			}
			return compiledManifest(), nil
		},
		Destinations:  func() []string { return []string{testDest} },
		Anchor:        anchor,
		LedgerBaseURL: ledgerURL,
	}
}

func get(t *testing.T, h http.Handler, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ─── construction ────────────────────────────────────────────────────

func TestNewServeHandler_WiringRefusals(t *testing.T) {
	if _, err := NewServeHandler(ServeConfig{}); err == nil {
		t.Error("missing Compile/Destinations must refuse")
	}
	cfg := testServeConfig(t, testAnchor, "")
	if _, err := NewServeHandler(cfg); err == nil || !strings.Contains(err.Error(), "LedgerBaseURL") {
		t.Errorf("anchor without ledger URL must refuse: %v", err)
	}
	cfg = testServeConfig(t, "no-seq-separator", "http://l")
	if _, err := NewServeHandler(cfg); err == nil || !strings.Contains(err.Error(), "<log-did>@<seq>") {
		t.Errorf("malformed anchor must refuse: %v", err)
	}
	cfg = testServeConfig(t, "did:web:l@notanumber", "http://l")
	if _, err := NewServeHandler(cfg); err == nil {
		t.Error("non-numeric anchor sequence must refuse")
	}
}

// ─── envelope + 404 ──────────────────────────────────────────────────

func TestServe_EnvelopeAndUnknownDestination(t *testing.T) {
	h, err := NewServeHandler(testServeConfig(t, "", ""))
	if err != nil {
		t.Fatal(err)
	}

	rec := get(t, h, "/v1/network/bundle", nil)
	var env struct {
		Format           string   `json:"format"`
		Exchanges        []string `json:"exchanges"`
		AnchorConfigured bool     `json:"anchor_configured"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Format != ManifestFormat || len(env.Exchanges) != 1 || env.Exchanges[0] != testDest || env.AnchorConfigured {
		t.Errorf("envelope = %+v", env)
	}

	rec = get(t, h, "/v1/network/bundle?destination=did:web:stranger", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown destination: code = %d, want 404", rec.Code)
	}
}

// ─── unpublished mode + ETag ─────────────────────────────────────────

func TestServe_UnpublishedCompiledProjection(t *testing.T) {
	h, err := NewServeHandler(testServeConfig(t, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := compiledManifest().CanonicalBytes()

	rec := get(t, h, "/v1/network/bundle?destination="+testDest, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if rec.Header().Get("X-Manifest-Published") != "false" {
		t.Error("unpublished serve must say X-Manifest-Published: false")
	}
	if rec.Body.String() != string(want) {
		t.Error("unpublished serve must be the compiled projection byte-exactly")
	}
	wantTag := `"` + hex.EncodeToString(func() []byte { s := sha256.Sum256(want); return s[:] }()) + `"`
	if got := rec.Header().Get("ETag"); got != wantTag {
		t.Errorf("ETag = %s, want sha256 of the served bytes", got)
	}

	// If-None-Match round-trips to 304 with no body.
	rec = get(t, h, "/v1/network/bundle?destination="+testDest, map[string]string{"If-None-Match": wantTag})
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("If-None-Match must 304 with empty body; got %d / %d bytes", rec.Code, rec.Body.Len())
	}
}

// ─── published resolution: newest valid wins; invalid candidates skipped ──

func TestServe_PublishedResolution_SkipsInvalidCandidates(t *testing.T) {
	published, _ := compiledManifest().CanonicalBytes()

	wrongExchange := compiledManifest()
	wrongExchange.Exchange = "did:web:other.example"
	wrongBytes, _ := wrongExchange.CanonicalBytes()

	raw := map[uint64][]byte{
		// seq 12 — NEWEST, decodes fine but is non-canonical (trailing space):
		// must be skipped by the re-canonicalization check.
		12: entryWire(t, append(append([]byte{}, published...), ' ')),
		// seq 11 — canonical but for a different exchange: skipped.
		11: entryWire(t, wrongBytes),
		// seq 10 — the valid publication, byte-equal to the enforced projection.
		10: entryWire(t, published),
	}
	srv := stubLedger(t, []uint64{10, 11, 12}, raw, http.StatusOK)

	h, err := NewServeHandler(testServeConfig(t, testAnchor, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, h, "/v1/network/bundle?destination="+testDest, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if rec.Header().Get("X-Manifest-Published") != "true" {
		t.Error("a resolved publication must serve X-Manifest-Published: true")
	}
	if pos := rec.Header().Get("X-Manifest-Position"); pos != "did:web:ledger.example@10" {
		t.Errorf("position = %q, want the seq-10 publication (12 non-canonical + 11 wrong-exchange skipped)", pos)
	}
	if rec.Header().Get("X-Manifest-Enforced-Match") != "true" {
		t.Error("published == enforced must report match: true")
	}
	if rec.Body.String() != string(published) {
		t.Error("the serve must be the on-log bytes exactly")
	}
}

func TestServe_Drift_SurfacedNeverHidden(t *testing.T) {
	drifted := compiledManifest()
	drifted.Network.Name = "declared-but-not-enforced"
	driftBytes, _ := drifted.CanonicalBytes()

	srv := stubLedger(t, []uint64{10}, map[uint64][]byte{10: entryWire(t, driftBytes)}, http.StatusOK)
	h, err := NewServeHandler(testServeConfig(t, testAnchor, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, h, "/v1/network/bundle?destination="+testDest, nil)
	if rec.Header().Get("X-Manifest-Enforced-Match") != "false" {
		t.Error("declared ≠ enforced must report match: false")
	}
	if rec.Body.String() != string(driftBytes) {
		t.Error("the DECLARED (on-log) manifest wins the serve even when drifted")
	}
}

func TestServe_ResolveFailure_FallsBackLoudly(t *testing.T) {
	srv := stubLedger(t, nil, nil, http.StatusInternalServerError)
	h, err := NewServeHandler(testServeConfig(t, testAnchor, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, h, "/v1/network/bundle?destination="+testDest, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fallback must still serve: code = %d", rec.Code)
	}
	if rec.Header().Get("X-Manifest-Resolve-Error") == "" {
		t.Error("a failed resolution must be surfaced in X-Manifest-Resolve-Error")
	}
	if rec.Header().Get("X-Manifest-Published") != "false" {
		t.Error("fallback serves the compiled projection, marked unpublished")
	}
	want, _ := compiledManifest().CanonicalBytes()
	if rec.Body.String() != string(want) {
		t.Error("fallback body must be the compiled projection")
	}
}
