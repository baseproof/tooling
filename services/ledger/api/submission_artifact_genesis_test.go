package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/reservation"
)

// fakeReserver records the ReserveRequest it was handed and returns a canned
// token / error.
type fakeReserver struct {
	got    reservation.ReserveRequest
	called bool
	tok    string
	err    error
}

func (f *fakeReserver) Reserve(_ context.Context, req reservation.ReserveRequest) (string, error) {
	f.called, f.got = true, req
	return f.tok, f.err
}

// genesisResponse is the decode target: the inlined SCT (log_did) + the token.
type genesisResponse struct {
	LogDID      string `json:"log_did"`
	UploadToken string `json:"upload_token"`
}

// TestArtifactReserve_ReservesAndReturnsToken: posting an artifact-genesis entry
// to the dedicated endpoint admits it and returns the signed upload token, with
// the decoded claim handed to the reserver.
func TestArtifactReserve_ReservesAndReturnsToken(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()

	art := storage.Compute([]byte("a 32MB docket PDF stands in for this"))
	payload, err := storage.EncodeArtifactGenesisPayload(storage.ArtifactGenesis{
		ArtifactCID: art, MIMEType: "application/pdf", MaxSize: 32 << 20, Owner: "did:court:5",
	})
	if err != nil {
		t.Fatalf("encode genesis: %v", err)
	}
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", payload, 1, 3600)
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	reserver := &fakeReserver{tok: "UPLOAD-TOKEN-xyz"}

	rr := httptest.NewRecorder()
	NewArtifactReserveHandler(deps, reserver).ServeHTTP(
		rr, httptest.NewRequest(http.MethodPost, "/v1/artifacts/reserve", bytes.NewReader(wire)))

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202\nbody: %s", rr.Code, rr.Body.String())
	}
	var resp genesisResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.UploadToken != "UPLOAD-TOKEN-xyz" {
		t.Fatalf("upload_token = %q, want the minted token", resp.UploadToken)
	}
	if !reserver.called {
		t.Fatal("reserver was not called")
	}
	if reserver.got.ArtifactCID != art.String() || reserver.got.MIMEType != "application/pdf" ||
		reserver.got.MaxSize != 32<<20 || reserver.got.Owner != "did:court:5" {
		t.Fatalf("ReserveRequest mismatch: %+v", reserver.got)
	}
}

// TestArtifactReserve_NonGenesis_400: a non-genesis entry posted to the artifact
// endpoint is a clean 400 with NOTHING admitted (the reserver is never called).
func TestArtifactReserve_NonGenesis_400(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", []byte("just an ordinary entry"), 1, 3600)
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})
	reserver := &fakeReserver{tok: "should-not-appear"}

	rr := httptest.NewRecorder()
	NewArtifactReserveHandler(deps, reserver).ServeHTTP(
		rr, httptest.NewRequest(http.MethodPost, "/v1/artifacts/reserve", bytes.NewReader(wire)))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (non-genesis to artifact endpoint)\nbody: %s", rr.Code, rr.Body.String())
	}
	if reserver.called {
		t.Fatal("reserver must not be called for a non-genesis request")
	}
}

// TestGenericSubmission_IsArtifactBlind proves the generic /v1/entries handler
// stays domain-agnostic: even a valid artifact-genesis entry mints no reservation
// and the response carries no upload_token (byte-identical to the bare SCT).
func TestGenericSubmission_IsArtifactBlind(t *testing.T) {
	opSignerPriv, _ := signatures.GenerateKey()
	payload, err := storage.EncodeArtifactGenesisPayload(storage.ArtifactGenesis{
		ArtifactCID: storage.Compute([]byte("a pdf")), MIMEType: "application/pdf", MaxSize: 1 << 20, Owner: "did:court:5",
	})
	if err != nil {
		t.Fatalf("encode genesis: %v", err)
	}
	wire, _, signerPriv := signedEntryModeB(t, "did:test:log", payload, 1, 3600)
	deps := makeSubmissionDeps(t, opSignerPriv, &signerPriv.PublicKey, &stubSubmissionWAL{})

	rr := httptest.NewRecorder()
	NewSubmissionHandler(deps).ServeHTTP(
		rr, httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(wire)))

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202\nbody: %s", rr.Code, rr.Body.String())
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("upload_token")) {
		t.Fatalf("/v1/entries must stay artifact-blind (no upload_token): %s", rr.Body.String())
	}
}
